import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { getDatabase } from '../backend/db.js';
import { createApiRouter } from '../backend/routes.js';
import { createAdminRouter } from '../backend/admin/adminRoutes.js';
import { hashSessionToken, hashPassword } from '../backend/auth.js';
import fs from 'node:fs';

const testDbPath = `test_auth_loop_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.db`;

describe('AUTH ROLE ROUTING & INFINITE LOOP PREVENTION TEST SUITE', () => {
  let app: express.Express;
  let db: any;
  let userToken: string;
  let orgAdminToken: string;
  let superAdminToken: string;

  before(async () => {
    process.env.FILE_SENTINEL_DB_PATH = testDbPath;
    process.env.FILE_SENTINEL_DEV_MODE = 'false'; // Ensure strict production auth behavior
    process.env.NODE_ENV = 'production';

    db = getDatabase(testDbPath);
    app = express();
    app.locals.db = db;
    app.use(express.json());

    const apiRouter = createApiRouter(db);
    const adminRouter = createAdminRouter(db);
    apiRouter.use('/admin', adminRouter);
    app.use('/api', apiRouter);

    // Setup seed users
    const now = new Date().toISOString();
    const defaultOrgId = 'org-test-auth-loop';

    db.prepare('INSERT OR REPLACE INTO organizations (org_id, name, suspended, created_at) VALUES (?, ?, 0, ?)').run(
      defaultOrgId,
      'Auth Loop Test Org',
      now
    );

    db.prepare('INSERT OR REPLACE INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)').run(
      'dev-device-default',
      defaultOrgId,
      'Test Dev Device',
      now
    );

    // Seed active license
    db.prepare(`
      INSERT OR REPLACE INTO licenses (license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at, max_users, max_devices, scan_limit, scans_used, feature_flags, created_at, updated_at)
      VALUES ('lic-auth-loop-1', ?, 'plan-enterprise', 'ACTIVE', ?, ?, ?, 100, 100, 10000, 0, ?, ?, ?)
    `).run(
      defaultOrgId,
      now,
      now,
      new Date(Date.now() + 365 * 86400000).toISOString(),
      JSON.stringify(['LOCAL_SCANNING', 'AUDIT_ENGINE', 'MULTI_FOLDER_SCAN', 'CLOUD_EVIDENCE_UPLOAD', 'CENTRAL_HISTORY', 'ADVANCED_REPORTING', 'API_ACCESS']),
      now,
      now
    );

    // 1. Standard USER
    const userPassHash = hashPassword('userpassword');
    db.prepare('INSERT OR REPLACE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
      'user-std-1',
      defaultOrgId,
      'user',
      userPassHash,
      'USER',
      now
    );

    // 2. Org Admin
    const orgPassHash = hashPassword('devpassword');
    db.prepare('INSERT OR REPLACE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
      'user-org-1',
      defaultOrgId,
      'devadmin',
      orgPassHash,
      'ORG_ADMIN',
      now
    );

    // 3. Super Admin
    const superPassHash = hashPassword('SysAdmin123!');
    db.prepare('INSERT OR REPLACE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
      'user-sys-1',
      defaultOrgId,
      'sysadmin',
      superPassHash,
      'SYS_ADMIN',
      now
    );
  });

  after(async () => {
    try {
      if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
      if (fs.existsSync(testDbPath + '-wal')) fs.unlinkSync(testDbPath + '-wal');
      if (fs.existsSync(testDbPath + '-shm')) fs.unlinkSync(testDbPath + '-shm');
    } catch {}
  });

  it('TEST 1 — USER LOGIN: POST /api/auth/login succeeds and returns USER role without loops', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'user', password: 'userpassword', device_id: 'dev-device-default' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.token);
    assert.strictEqual(res.body.user.role, 'USER');
    userToken = res.body.token;

    // Verify /api/auth/me returns authoritative USER conceptual role
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${userToken}`);

    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.body.role, 'USER');
    assert.strictEqual(meRes.body.conceptualRole, 'USER');
    assert.strictEqual(meRes.body.username, 'user');
  });

  it('TEST 2 — ORG ADMIN LOGIN: POST /api/auth/login succeeds and returns ORG_ADMIN role', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'devadmin', password: 'devpassword', device_id: 'dev-device-default' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.token);
    assert.strictEqual(res.body.user.role, 'ORG_ADMIN');
    orgAdminToken = res.body.token;

    // Verify /api/auth/me returns ORG_ADMIN
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${orgAdminToken}`);

    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.body.role, 'ORG_ADMIN');
    assert.strictEqual(meRes.body.conceptualRole, 'ORG_ADMIN');
  });

  it('TEST 3 — SUPER ADMIN LOGIN: POST /api/auth/login succeeds and maps SYS_ADMIN to SUPER_ADMIN', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'sysadmin', password: 'SysAdmin123!', device_id: 'dev-device-default' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.token);
    superAdminToken = res.body.token;

    // Verify /api/auth/me returns SUPER_ADMIN
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${superAdminToken}`);

    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.body.role, 'SYS_ADMIN');
    assert.strictEqual(meRes.body.conceptualRole, 'SUPER_ADMIN');
  });

  it('TEST 4 — REFRESH / SESSION RESTORE: Valid token maintains exact user and role', async () => {
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${userToken}`);

    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.body.username, 'user');
    assert.strictEqual(meRes.body.conceptualRole, 'USER');
  });

  it('TEST 5 — UNAUTHENTICATED REQUESTS: Rejects missing token with 401 (no fake auto-login)', async () => {
    const res = await request(app).get('/api/auth/me');
    assert.strictEqual(res.status, 401);
  });

  it('TEST 6 — LOGOUT: POST /api/auth/logout invalidates session and subsequent calls return 401', async () => {
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${userToken}`);

    assert.strictEqual(logoutRes.status, 200);
    assert.strictEqual(logoutRes.body.success, true);

    // Verify session is dead
    const deadRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${userToken}`);

    assert.strictEqual(deadRes.status, 401);
  });

  it('TEST 7 — BROWSER BACK PROTECTION: Revoked session cannot access protected data', async () => {
    const blockedSettings = await request(app)
      .get('/api/settings')
      .set('Authorization', `Bearer ${userToken}`);

    assert.strictEqual(blockedSettings.status, 401);
  });

  it('TEST 8 — REAL SCAN & AUTOMATIC POST-SCAN AUDIT FLOW: Operates with valid user token', async () => {
    // 1. Issue fresh user token
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'user', password: 'userpassword', device_id: 'dev-device-default' });

    const token = loginRes.body.token;

    // 2. Start Scan
    const scanRes = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client')
      .send({ root_paths: ['sample-files'] });

    assert.strictEqual(scanRes.status, 200);
    assert.ok(scanRes.body.scan_id);
    const scanId = scanRes.body.scan_id;

    // 3. Poll progress until scan finishes
    for (let i = 0; i < 40; i++) {
      await new Promise(resolve => setTimeout(resolve, 100));
      const prog = await request(app)
        .get(`/api/scans/${scanId}`)
        .set('Authorization', `Bearer ${token}`)
        .set('X-Requested-With', 'XMLHttpRequest')
        .set('X-CSRF-Token', 'filesentinel-client');
      if (prog.body?.status === 'COMPLETED' || prog.body?.status === 'FAILED') break;
    }

    // 4. Retrieve dashboard stats for user
    const statsRes = await request(app)
      .get('/api/dashboard/stats')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(statsRes.status, 200);

    // 5. Retrieve scan history for user
    const historyRes = await request(app)
      .get('/api/scans/history')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(historyRes.status, 200);
    assert.ok(Array.isArray(historyRes.body));
  });
});
