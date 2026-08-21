import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { getDatabase } from '../backend/db.js';
import { createApiRouter } from '../backend/routes.js';
import { hashSessionToken } from '../backend/auth.js';
import crypto from 'node:crypto';

describe('FRONTEND AUTHENTICATION BOOTSTRAP REGRESSION TEST SUITE', () => {
  let app: express.Express;
  let db: any;
  let validToken: string;
  let expiredToken: string;

  before(async () => {
    db = getDatabase('./test_auth_bootstrap_' + Date.now() + '.db');
    app = express();
    app.use(express.json());
    app.use('/api', createApiRouter(db));

    // Seed a valid user and session for testing
    const testOrgId = 'org-auth-test-' + crypto.randomUUID().substring(0, 6);
    const testUserId = 'user-auth-test-' + crypto.randomUUID().substring(0, 6);
    const now = new Date().toISOString();

    db.prepare('INSERT INTO organizations (org_id, name, suspended, created_at) VALUES (?, ?, 0, ?)').run(testOrgId, 'Auth Test Org', now);
    db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
      testUserId, testOrgId, 'authtestuser', 'hash', 'ORG_ADMIN', now
    );

    // Issue valid session token
    validToken = 'tok-valid-' + crypto.randomBytes(16).toString('hex');
    const validExpires = new Date(Date.now() + 3600 * 1000).toISOString();
    db.prepare('INSERT INTO sessions (token_hash, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      hashSessionToken(validToken), testUserId, testOrgId, 'dev-1', validExpires, now
    );

    // Issue expired session token
    expiredToken = 'tok-expired-' + crypto.randomBytes(16).toString('hex');
    const expiredTime = new Date(Date.now() - 3600 * 1000).toISOString();
    db.prepare('INSERT INTO sessions (token_hash, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      hashSessionToken(expiredToken), testUserId, testOrgId, 'dev-1', expiredTime, now
    );
  });

  it('1. Protected API without token is rejected when dev mode disabled', async () => {
    const oldDevMode = process.env.FILE_SENTINEL_DEV_MODE;
    const oldNodeEnv = process.env.NODE_ENV;
    process.env.FILE_SENTINEL_DEV_MODE = 'false';
    process.env.NODE_ENV = 'production';

    try {
      const res = await request(app).get('/api/settings');
      assert.strictEqual(res.status, 401);
      assert.match(res.body.error, /Missing bearer token/i);
    } finally {
      process.env.FILE_SENTINEL_DEV_MODE = oldDevMode;
      process.env.NODE_ENV = oldNodeEnv;
    }
  });

  it('2. Authenticated frontend request with valid token accesses /api/settings (200)', async () => {
    const res = await request(app)
      .get('/api/settings')
      .set('Authorization', `Bearer ${validToken}`);
    assert.strictEqual(res.status, 200);
  });

  it('3. Authenticated frontend request with valid token accesses /api/dashboard/stats (200)', async () => {
    const res = await request(app)
      .get('/api/dashboard/stats')
      .set('Authorization', `Bearer ${validToken}`);
    assert.strictEqual(res.status, 200);
  });

  it('4. Authenticated frontend request with valid token accesses /api/license (200)', async () => {
    const res = await request(app)
      .get('/api/license')
      .set('Authorization', `Bearer ${validToken}`);
    assert.strictEqual(res.status, 200);
  });

  it('5. Authenticated frontend request with valid token accesses /api/license/offline-status (200)', async () => {
    const res = await request(app)
      .get('/api/license/offline-status')
      .set('Authorization', `Bearer ${validToken}`);
    assert.strictEqual(res.status, 200);
  });

  it('6. Expired token is rejected with 401', async () => {
    const res = await request(app)
      .get('/api/settings')
      .set('Authorization', `Bearer ${expiredToken}`);
    assert.strictEqual(res.status, 401);
    assert.match(res.body.error, /Session expired/i);
  });

  it('7. Invalid / fake token is rejected with 401', async () => {
    const res = await request(app)
      .get('/api/settings')
      .set('Authorization', 'Bearer tok-fake-invalid-token');
    assert.strictEqual(res.status, 401);
    assert.match(res.body.error, /Invalid session token/i);
  });

  it('8. No static IPC secret can authenticate as SYS_ADMIN', async () => {
    const res = await request(app)
      .get('/api/admin/organizations')
      .set('x-fs-ipc-token', 'static-admin-bypass-key');
    assert.strictEqual(res.status, 401);
  });
});
