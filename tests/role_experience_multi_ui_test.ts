import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { getDatabase } from '../backend/db.js';
import { createApiRouter } from '../backend/routes.js';
import { createAdminRouter } from '../backend/admin/adminRoutes.js';
import { getConceptualRole, getUserPermissions, hashSessionToken, hashPassword } from '../backend/auth.js';
import fs from 'node:fs';

const testDbPath = `test_role_multi_ui_${Date.now()}_${Math.random().toString(36).substring(2, 6)}.db`;

describe('Role-Aware Multi-Experience UI Architecture & Authorization Gate', () => {
  let app: express.Express;
  let db: any;
  let superAdminToken: string;
  let orgAdminToken: string;
  let userToken: string;

  before(async () => {
    process.env.FILE_SENTINEL_DEV_MODE = 'true';
    process.env.NODE_ENV = 'development';
    process.env.FILE_SENTINEL_DB_PATH = testDbPath;

    db = getDatabase(testDbPath);
    app = express();
    app.locals.db = db;
    app.use(express.json());

    const apiRouter = createApiRouter(db);
    const adminRouter = createAdminRouter(db);
    apiRouter.use('/admin', adminRouter);
    app.use('/api', apiRouter);

    // Create test organization
    const orgId = 'org-test-multi-ui';
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();

    db.prepare(`
      INSERT OR REPLACE INTO organizations (org_id, name, suspended, created_at)
      VALUES (?, 'Multi-UI Test Organization', 0, ?)
    `).run(orgId, now);

    db.prepare(`
      INSERT OR REPLACE INTO devices (device_id, org_id, device_name, revoked, registered_at)
      VALUES ('dev-1', ?, 'Test Device 1', 0, ?)
    `).run(orgId, now);

    db.prepare(`
      INSERT OR REPLACE INTO licenses (license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at, max_users, max_devices, scan_limit, scans_used, feature_flags, created_at, updated_at)
      VALUES ('lic-multi-1', ?, 'plan-enterprise', 'ACTIVE', ?, ?, ?, 100, 100, 10000, 0, ?, ?, ?)
    `).run(
      orgId,
      now,
      now,
      new Date(Date.now() + 30 * 86400000).toISOString(),
      JSON.stringify(['LOCAL_SCANNING', 'AUDIT_ENGINE', 'MULTI_FOLDER_SCAN', 'CLOUD_EVIDENCE_UPLOAD', 'CENTRAL_HISTORY', 'ADVANCED_REPORTING', 'API_ACCESS']),
      now,
      now
    );

    const pwdHash = hashPassword('TestPass123!');
    
    // 1. Super Admin
    db.prepare(`
      INSERT OR REPLACE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at)
      VALUES ('u-super-1', ?, 'superadmin_user', ?, 'SUPER_ADMIN', 0, ?)
    `).run(orgId, pwdHash, now);
    superAdminToken = 'tok-super-' + Math.random().toString(36).substring(2, 10);
    db.prepare(`
      INSERT OR REPLACE INTO sessions (token_hash, user_id, org_id, device_id, expires_at, created_at)
      VALUES (?, 'u-super-1', ?, 'dev-1', ?, ?)
    `).run(hashSessionToken(superAdminToken), orgId, expiresAt, now);

    // 2. Org Admin
    db.prepare(`
      INSERT OR REPLACE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at)
      VALUES ('u-org-1', ?, 'orgadmin_user', ?, 'ORG_ADMIN', 0, ?)
    `).run(orgId, pwdHash, now);
    orgAdminToken = 'tok-org-' + Math.random().toString(36).substring(2, 10);
    db.prepare(`
      INSERT OR REPLACE INTO sessions (token_hash, user_id, org_id, device_id, expires_at, created_at)
      VALUES (?, 'u-org-1', ?, 'dev-1', ?, ?)
    `).run(hashSessionToken(orgAdminToken), orgId, expiresAt, now);

    // 3. Normal User
    db.prepare(`
      INSERT OR REPLACE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at)
      VALUES ('u-user-1', ?, 'standard_user', ?, 'USER', 0, ?)
    `).run(orgId, pwdHash, now);
    userToken = 'tok-user-' + Math.random().toString(36).substring(2, 10);
    db.prepare(`
      INSERT OR REPLACE INTO sessions (token_hash, user_id, org_id, device_id, expires_at, created_at)
      VALUES (?, 'u-user-1', ?, 'dev-1', ?, ?)
    `).run(hashSessionToken(userToken), orgId, expiresAt, now);
  });

  after(async () => {
    try {
      await new Promise(r => setTimeout(r, 800));
      db.close();
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
    } catch {}
  });

  it('1. Conceptual Role Mapping: maps SYS_ADMIN and SUPER_ADMIN to SUPER_ADMIN', () => {
    assert.strictEqual(getConceptualRole('SUPER_ADMIN'), 'SUPER_ADMIN');
    assert.strictEqual(getConceptualRole('SYS_ADMIN'), 'SUPER_ADMIN');

    const perms = getUserPermissions('SUPER_ADMIN');
    assert.ok(perms.includes('SYSTEM_ADMIN'));
    assert.ok(perms.includes('MANAGE_PILOTS'));
    assert.ok(perms.includes('GLOBAL_TELEMETRY'));
    assert.ok(perms.includes('SCAN_FILES'));
  });

  it('2. Conceptual Role Mapping: maps ORG_ADMIN to ORG_ADMIN', () => {
    assert.strictEqual(getConceptualRole('ORG_ADMIN'), 'ORG_ADMIN');

    const perms = getUserPermissions('ORG_ADMIN');
    assert.ok(perms.includes('MANAGE_ORGANIZATION'));
    assert.ok(perms.includes('MANAGE_USERS'));
    assert.ok(perms.includes('MANAGE_DEVICES'));
    assert.ok(perms.includes('SCAN_FILES'));
    assert.ok(!perms.includes('GLOBAL_TELEMETRY'));
    assert.ok(!perms.includes('MANAGE_PILOTS'));
  });

  it('3. Conceptual Role Mapping: maps USER, VIEWER, OPERATOR to USER', () => {
    assert.strictEqual(getConceptualRole('USER'), 'USER');
    assert.strictEqual(getConceptualRole('VIEWER'), 'USER');
    assert.strictEqual(getConceptualRole('OPERATOR'), 'USER');

    const perms = getUserPermissions('USER');
    assert.ok(perms.includes('SCAN_FILES'));
    assert.ok(perms.includes('VIEW_SCAN_RESULTS'));
    assert.ok(perms.includes('CHECK_ENDPOINT_COMPLIANCE'));
    assert.ok(!perms.includes('MANAGE_ORGANIZATION'));
    assert.ok(!perms.includes('MANAGE_PILOTS'));
  });

  it('4. /api/auth/me returns conceptualRole, permissions, and entitlements for USER', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.userId, 'u-user-1');
    assert.strictEqual(res.body.role, 'USER');
    assert.strictEqual(res.body.conceptualRole, 'USER');
    assert.ok(Array.isArray(res.body.permissions));
    assert.ok(res.body.entitlements);
    assert.strictEqual(res.body.entitlements.FILE_SCAN, true);
  });

  it('5. /api/auth/me returns SUPER_ADMIN conceptual role and root permissions for superadmin', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${superAdminToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.userId, 'u-super-1');
    assert.strictEqual(res.body.conceptualRole, 'SUPER_ADMIN');
    assert.ok(res.body.permissions.includes('GLOBAL_TELEMETRY'));
  });

  it('6. Authorization Security: Rejects USER from accessing /api/admin/pilots with HTTP 403', async () => {
    const res = await request(app)
      .get('/api/admin/pilots')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 403);
    assert.ok(res.body.error.includes('Forbidden'));
  });

  it('7. Authorization Security: Rejects ORG_ADMIN from accessing /api/admin/pilots with HTTP 403', async () => {
    const res = await request(app)
      .get('/api/admin/pilots')
      .set('Authorization', `Bearer ${orgAdminToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 403);
    assert.ok(res.body.error.includes('Forbidden'));
  });

  it('8. Authorization Security: Permits SUPER_ADMIN to access /api/admin/pilots with HTTP 200', async () => {
    const res = await request(app)
      .get('/api/admin/pilots')
      .set('Authorization', `Bearer ${superAdminToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body));
  });

  it('9. Authorization Security: Rejects USER from registering devices via /api/devices/register with HTTP 403', async () => {
    const res = await request(app)
      .post('/api/devices/register')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client')
      .send({ device_name: 'Unauthorized Laptop' });

    assert.strictEqual(res.status, 403);
  });

  it('10. Authorization Security: Permits ORG_ADMIN to register devices via /api/devices/register with HTTP 200', async () => {
    const res = await request(app)
      .post('/api/devices/register')
      .set('Authorization', `Bearer ${orgAdminToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client')
      .send({ device_name: 'Org Admin Laptop' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.device_id);
  });

  it('11. Safe Role Preview: Permits SUPER_ADMIN to preview USER role via /api/auth/switch-role-view', async () => {
    const res = await request(app)
      .post('/api/auth/switch-role-view')
      .set('Authorization', `Bearer ${superAdminToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client')
      .send({ role: 'USER' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.active_view_role, 'USER');
    assert.strictEqual(res.body.real_role, 'SUPER_ADMIN');
    assert.strictEqual(res.body.preview, true);

    // Verify database record for superadmin remains SUPER_ADMIN (no privilege mutation)
    const userRow = db.prepare('SELECT role FROM users WHERE user_id = ?').get('u-super-1') as any;
    assert.strictEqual(userRow.role, 'SUPER_ADMIN');
  });

  it('12. Safe Role Preview: Rejects invalid target role with HTTP 400', async () => {
    const res = await request(app)
      .post('/api/auth/switch-role-view')
      .set('Authorization', `Bearer ${superAdminToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client')
      .send({ role: 'INVALID_HACKER_ROLE' });

    assert.strictEqual(res.status, 400);
  });

  it('13. Privilege Escalation Prevention: Production USER cannot use /api/auth/switch-role-view to become SUPER_ADMIN', async () => {
    const oldDevMode = process.env.FILE_SENTINEL_DEV_MODE;
    const oldNodeEnv = process.env.NODE_ENV;
    process.env.FILE_SENTINEL_DEV_MODE = 'false';
    process.env.NODE_ENV = 'production';

    try {
      const res = await request(app)
        .post('/api/auth/switch-role-view')
        .set('Authorization', `Bearer ${userToken}`)
        .set('X-Requested-With', 'XMLHttpRequest')
        .set('X-CSRF-Token', 'filesentinel-client')
        .send({ role: 'SUPER_ADMIN' });

      assert.strictEqual(res.status, 403);
      assert.ok(res.body.error.includes('only permitted for Super Administrators'));
    } finally {
      process.env.FILE_SENTINEL_DEV_MODE = oldDevMode;
      process.env.NODE_ENV = oldNodeEnv;
    }
  });

  it('14. Shared Core API: Permits USER to access /api/dashboard/stats with HTTP 200', async () => {
    const res = await request(app)
      .get('/api/dashboard/stats')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 200);
    assert.ok(res.body.fileSummary !== undefined || res.body.file_summary !== undefined);
  });

  it('15. Shared Core API: Permits USER to access /api/scans/history with HTTP 200', async () => {
    const res = await request(app)
      .get('/api/scans/history')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body));
  });

  it('16. Shared Core API: Permits USER to start real scans via /api/scans with HTTP 200', async () => {
    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client')
      .send({ root_paths: ['sample-files'] });

    assert.strictEqual(res.status, 200);
    assert.ok(res.body.scan_id);
    assert.strictEqual(res.body.status, 'SCANNING');

    const scanId = res.body.scan_id;
    for (let i = 0; i < 40; i++) {
      await new Promise(resolve => setTimeout(resolve, 100));
      const prog = await request(app)
        .get(`/api/scans/${scanId}`)
        .set('Authorization', `Bearer ${userToken}`)
        .set('X-Requested-With', 'XMLHttpRequest')
        .set('X-CSRF-Token', 'filesentinel-client');
      if (prog.body?.status === 'COMPLETED' || prog.body?.status === 'FAILED') break;
    }
  });

  it('17. Shared Core Endpoint Assessment: Permits USER to run real endpoint assessment via /api/endpoint/assess', async () => {
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client')
      .send({});

    assert.strictEqual(res.status, 200);
    assert.ok(res.body.id || res.body.assessment_id);
    assert.ok(res.body.overall_status);
    assert.ok(res.body.usb_result);
    assert.ok(Array.isArray(res.body.web_results));
    assert.ok(res.body.category_summaries);
  });

  it('18. Shared Core Endpoint Assessment History: Permits USER to fetch assessments via /api/endpoint/assessments & /latest', async () => {
    const listRes = await request(app)
      .get('/api/endpoint/assessments?limit=5')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(listRes.status, 200);
    assert.ok(Array.isArray(listRes.body));
    assert.ok(listRes.body.length >= 1);

    const latestRes = await request(app)
      .get('/api/endpoint/latest')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(latestRes.status, 200);
    assert.ok(latestRes.body.id || latestRes.body.assessment_id);
  });

  it('19. Shared Core Audit Compliance: Permits USER to query /api/audit/sessions', async () => {
    const res = await request(app)
      .get('/api/audit/sessions')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body));
  });

  it('20. Authentic Logout: Session is terminated and subsequent requests return HTTP 401', async () => {
    // Logout the user
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(logoutRes.status, 200);

    // Subsequent request with the logged-out token must fail
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('X-CSRF-Token', 'filesentinel-client');

    assert.strictEqual(meRes.status, 401);
  });
});
