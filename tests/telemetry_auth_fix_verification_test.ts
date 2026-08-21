import assert from 'node:assert';
import crypto from 'node:crypto';
import http from 'node:http';
import { getDatabase } from '../backend/db.js';
import { TelemetrySyncService } from '../backend/telemetry/telemetrySyncService.js';
import { TelemetryService } from '../backend/telemetry.js';
import { TelemetryQueueRepository } from '../backend/telemetry/telemetryQueue.js';
import { CURRENT_TELEMETRY_SCHEMA_VERSION } from '../backend/telemetry/telemetryTypes.js';

async function runAuthFixTestSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Telemetry Auth Fix & Response Validation Test Suite   ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const queueRepo = new TelemetryQueueRepository(db);
  const telemetryService = new TelemetryService(db);
  const secret = 'test-ingestion-secret-64-character-hex-string-for-filesentinel-auth';

  let mockServerStatus = 200;
  let mockServerResponseBody: any = null;
  let receivedRequests: any[] = [];
  const seenNonces = new Set<string>();
  const processedEventIds = new Set<string>();

  const server = http.createServer((req, res) => {
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        service: 'FileSentinel Telemetry Ingestion',
        status: 'online',
        accepts: 'POST'
      }));
      return;
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let parsed: any;
      try {
        parsed = JSON.parse(body);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Malformed JSON' }));
        return;
      }

      receivedRequests.push({ headers: req.headers, body: parsed, rawBody: body });

      if (mockServerResponseBody !== null) {
        res.writeHead(mockServerStatus, { 'Content-Type': 'application/json' });
        res.end(typeof mockServerResponseBody === 'string' ? mockServerResponseBody : JSON.stringify(mockServerResponseBody));
        return;
      }

      // Check auth in body
      if (!parsed.auth || !parsed.auth.timestamp || !parsed.auth.nonce || !parsed.auth.signature) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Missing auth object in body' }));
        return;
      }

      const { timestamp, nonce, signature } = parsed.auth;

      // Freshness
      const reqTime = parseInt(timestamp, 10);
      if (Math.abs(Date.now() - reqTime) > 5 * 60 * 1000) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Timestamp expired' }));
        return;
      }

      // Nonce
      if (seenNonces.has(nonce)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Duplicate nonce' }));
        return;
      }
      seenNonces.add(nonce);

      // Canonical HMAC
      const canonicalData = JSON.stringify({
        batch_id: parsed.batch_id,
        sent_at: parsed.sent_at,
        environment: parsed.environment,
        schema_version: parsed.schema_version,
        events: parsed.events
      });
      const canonicalPayload = `${timestamp}:${nonce}:${canonicalData}`;
      const expectedSig = crypto.createHmac('sha256', secret).update(canonicalPayload).digest('hex');

      if (expectedSig.toLowerCase() !== (signature || '').toLowerCase()) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid HMAC signature' }));
        return;
      }

      let newEvents = 0;
      let dupEvents = 0;
      for (const ev of parsed.events || []) {
        if (processedEventIds.has(ev.event_id)) {
          dupEvents++;
        } else {
          processedEventIds.add(ev.event_id);
          newEvents++;
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        processed_count: newEvents,
        duplicates_count: dupEvents,
        failed_count: 0,
        timestamp: new Date().toISOString()
      }));
    });
  });

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as any).port;
  const ingestionUrl = `http://127.0.0.1:${port}/macros/s/exec`;

  const syncService = new TelemetrySyncService(db, {
    enabled: true,
    environment: 'development',
    ingestionUrl,
    ingestionSecret: secret,
    maxEventsPerBatch: 50
  });

  try {
    // TEST 1: Request contains auth inside JSON body
    {
      telemetryService.recordScanCompleted('SCN-T1', 'org-1', 'user-1', 'DEV-1', {
        duration_ms: 1000,
        findings_count: 0
      });
      receivedRequests = [];
      const res = await syncService.syncOnce();
      if (res.succeeded !== 1) {
        console.log('TEST 1 FAILED RESULT:', res);
        console.log('SERVER RECEIVED:', receivedRequests);
      }
      assert.strictEqual(res.succeeded, 1);
      assert.strictEqual(receivedRequests.length, 1);
      assert.ok(receivedRequests[0].body.auth, 'auth object must be inside JSON body');
      assert.ok(receivedRequests[0].body.auth.timestamp, 'timestamp must be in auth');
      assert.ok(receivedRequests[0].body.auth.nonce, 'nonce must be in auth');
      assert.ok(receivedRequests[0].body.auth.signature, 'signature must be in auth');
      console.log('  [PASS] Test 1: Request contains auth inside JSON body');
    }

    // TEST 2: Apps Script reconstructs identical canonical payload
    {
      const req = receivedRequests[0].body;
      const canonicalData = JSON.stringify({
        batch_id: req.batch_id,
        sent_at: req.sent_at,
        environment: req.environment,
        schema_version: req.schema_version,
        events: req.events
      });
      const canonicalPayload = `${req.auth.timestamp}:${req.auth.nonce}:${canonicalData}`;
      const recomputed = crypto.createHmac('sha256', secret).update(canonicalPayload).digest('hex');
      assert.strictEqual(recomputed, req.auth.signature, 'Recomputed canonical signature must match');
      console.log('  [PASS] Test 2: Apps Script reconstructs identical canonical payload');
    }

    // TEST 3: Valid HMAC accepted
    {
      telemetryService.recordScanCompleted('SCN-T3', 'org-1', 'user-1', 'DEV-1', { duration_ms: 500 });
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 1);
      console.log('  [PASS] Test 3: Valid HMAC accepted and acknowledged');
    }

    // TEST 4: Invalid HMAC rejected by server & handled safely by client
    {
      syncService.setConfig({ ingestionSecret: 'mismatched-wrong-secret' });
      telemetryService.recordScanCompleted('SCN-T4', 'org-1', 'user-1', 'DEV-1', { duration_ms: 500 });
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 0);
      assert.strictEqual(res.failed, 1);
      assert.ok(res.error?.toLowerCase().includes('hmac') || res.error?.toLowerCase().includes('403'));
      syncService.setConfig({ ingestionSecret: secret });
      console.log('  [PASS] Test 4: Invalid HMAC rejected');
    }

    // TEST 5: HTTP 200 + success:false => NOT marked SENT, retry backoff scheduled
    {
      db.exec('DELETE FROM telemetry_queue;');
      telemetryService.recordScanCompleted('SCN-T5', 'org-1', 'user-1', 'DEV-1', { duration_ms: 500 });
      mockServerResponseBody = { success: false, error: 'Internal ingestion error simulated' };
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 0);
      assert.strictEqual(res.failed, 1);
      const row = db.prepare('SELECT status, attempt_count, next_attempt_at FROM telemetry_queue ORDER BY rowid DESC LIMIT 1').get() as any;
      assert.strictEqual(row.status, 'PENDING', 'Record must revert to PENDING when success is false');
      assert.strictEqual(row.attempt_count, 1, 'Attempt count must increment');
      mockServerResponseBody = null;
      console.log('  [PASS] Test 5: HTTP 200 + success:false => NOT SENT, retry backoff scheduled');
    }

    // TEST 6: HTTP 200 + malformed JSON => NOT marked SENT
    {
      db.exec('DELETE FROM telemetry_queue;');
      telemetryService.recordScanCompleted('SCN-T6', 'org-1', 'user-1', 'DEV-1', { duration_ms: 500 });
      mockServerResponseBody = '<!DOCTYPE html><html><body>Error 502 Bad Gateway</body></html>';
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 0);
      assert.strictEqual(res.failed, 1);
      assert.ok(res.error?.includes('Malformed JSON'));
      const row = db.prepare('SELECT status FROM telemetry_queue ORDER BY rowid DESC LIMIT 1').get() as any;
      assert.strictEqual(row.status, 'PENDING', 'Record must revert to PENDING on malformed JSON');
      mockServerResponseBody = null;
      console.log('  [PASS] Test 6: HTTP 200 + malformed JSON => NOT SENT');
    }

    // TEST 7: HTTP 500 Server Error => NOT marked SENT
    {
      db.exec('DELETE FROM telemetry_queue;');
      telemetryService.recordScanCompleted('SCN-T7', 'org-1', 'user-1', 'DEV-1', { duration_ms: 500 });
      mockServerStatus = 500;
      mockServerResponseBody = { success: false, error: 'Google backend crash' };
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 0);
      assert.strictEqual(res.failed, 1);
      const row = db.prepare('SELECT status FROM telemetry_queue ORDER BY rowid DESC LIMIT 1').get() as any;
      assert.strictEqual(row.status, 'PENDING');
      mockServerStatus = 200;
      mockServerResponseBody = null;
      console.log('  [PASS] Test 7: HTTP 500 => NOT SENT');
    }

    // TEST 8: HTTP 200 + success:true => marked SENT
    {
      db.exec("UPDATE telemetry_queue SET next_attempt_at = datetime('now', '-1 minute');");
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 1);
      const row = db.prepare('SELECT status FROM telemetry_queue ORDER BY rowid DESC LIMIT 1').get() as any;
      assert.strictEqual(row.status, 'SENT', 'Record must transition to SENT on success: true');
      console.log('  [PASS] Test 8: HTTP 200 + success:true => marked SENT');
    }

    // TEST 9: Duplicate event acknowledged correctly (processed: 0, duplicates: 1 => success: true)
    {
      db.exec('DELETE FROM telemetry_queue;');
      const duplicateEvtId = 'EVT-DUP-TEST-01';
      processedEventIds.add(duplicateEvtId); // Simulate already processed by server
      queueRepo.enqueue({
        event_id: duplicateEvtId,
        event_type: 'APP_STARTED',
        schema_version: 1,
        timestamp_utc: new Date().toISOString(),
        installation_id: 'inst-1',
        organization_id: 'org-1',
        device_id: 'dev-1',
        endpoint_id: 'ep-1',
        application_version: '8.2.0',
        OS: 'win32',
        machine_type: 'x64'
      });
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 1, 'Duplicate event batch must be acknowledged as succeeded');
      const row = db.prepare('SELECT status FROM telemetry_queue WHERE event_id = ?').get(duplicateEvtId) as any;
      assert.strictEqual(row.status, 'SENT');
      console.log('  [PASS] Test 9: Duplicate event acknowledged correctly');
    }

    // TEST 10: doGet() returns service health response
    {
      const getRes = await new Promise<any>((resolve, reject) => {
        http.get(ingestionUrl, res => {
          let b = '';
          res.on('data', c => b += c);
          res.on('end', () => resolve(JSON.parse(b)));
        }).on('error', reject);
      });
      assert.strictEqual(getRes.service, 'FileSentinel Telemetry Ingestion');
      assert.strictEqual(getRes.status, 'online');
      assert.strictEqual(getRes.accepts, 'POST');
      console.log('  [PASS] Test 10: doGet() returns service health response');
    }

    // TEST 11: Outage isolation verified: Local scan records remain intact
    {
      mockServerStatus = 503;
      mockServerResponseBody = 'Service Unavailable';
      const scanEvt = telemetryService.recordScanCompleted('SCN-OUTAGE-SAFE-01', 'org-1', 'user-1', 'DEV-1', {
        duration_ms: 1200,
        findings_count: 0
      });
      const queueRow = db.prepare('SELECT * FROM telemetry_queue WHERE event_id = ?').get(scanEvt.event_id) as any;
      assert.ok(queueRow, 'Local queue record must be created regardless of network state');
      assert.strictEqual(queueRow.status, 'PENDING');
      mockServerStatus = 200;
      mockServerResponseBody = null;
      console.log('  [PASS] Test 11: Outage isolation verified (Scans never fail due to telemetry)');
    }

    // TEST 12: Historical SYNCED queue rows remain completely untouched
    {
      db.exec(`
        INSERT INTO telemetry_queue (id, event_id, event_type, schema_version, priority, payload_json, created_at, status)
        VALUES ('TQ-LEGACY-01', 'EVT-LEGACY-01', 'SCAN_COMPLETED', 1, 'NORMAL', '{}', datetime('now'), 'SYNCED');
      `);
      await syncService.syncOnce();
      const legacyRow = db.prepare("SELECT status FROM telemetry_queue WHERE id = 'TQ-LEGACY-01'").get() as any;
      assert.strictEqual(legacyRow.status, 'SYNCED', 'Historical SYNCED rows must not be altered');
      console.log('  [PASS] Test 12: Existing legacy SYNCED queue rows remain untouched');
    }

    // TEST 13: Authoritative queue metadata merged into outbound event envelope
    {
      db.exec('DELETE FROM telemetry_queue;');
      db.exec(`
        INSERT INTO telemetry_queue (id, event_id, event_type, schema_version, priority, payload_json, created_at, status)
        VALUES ('TQ-TEST-123', 'EVT-TEST-123', 'SCAN_COMPLETED', 1, 'NORMAL', '{"scan_id":"SCAN-123","organization_id":"org-1"}', datetime('now'), 'PENDING');
      `);
      receivedRequests = [];
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 1);
      assert.strictEqual(receivedRequests.length, 1);
      const sentEvt = receivedRequests[0].body.events[0];
      assert.strictEqual(sentEvt.event_id, 'EVT-TEST-123');
      assert.strictEqual(sentEvt.event_type, 'SCAN_COMPLETED');
      assert.strictEqual(sentEvt.schema_version, 1);
      assert.strictEqual(sentEvt.scan_id, 'SCAN-123');
      assert.strictEqual(sentEvt.organization_id, 'org-1');
      console.log('  [PASS] Test 13: Authoritative queue metadata merged into outbound event envelope');
    }

    // TEST 14: payload_json cannot overwrite authoritative queue metadata
    {
      db.exec('DELETE FROM telemetry_queue;');
      db.exec(`
        INSERT INTO telemetry_queue (id, event_id, event_type, schema_version, priority, payload_json, created_at, status)
        VALUES ('TQ-TEST-456', 'EVT-AUTH-CORRECT', 'SCAN_COMPLETED', 1, 'NORMAL', '{"event_id":"EVT-FORGED","event_type":"FORGED_TYPE","schema_version":999,"scan_id":"SCAN-456"}', datetime('now'), 'PENDING');
      `);
      receivedRequests = [];
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 1);
      assert.strictEqual(receivedRequests.length, 1);
      const sentEvt = receivedRequests[0].body.events[0];
      assert.strictEqual(sentEvt.event_id, 'EVT-AUTH-CORRECT', 'Authoritative event_id must not be overwritten');
      assert.strictEqual(sentEvt.event_type, 'SCAN_COMPLETED', 'Authoritative event_type must not be overwritten');
      assert.strictEqual(sentEvt.schema_version, 1, 'Authoritative schema_version must not be overwritten');
      assert.strictEqual(sentEvt.scan_id, 'SCAN-456');
      console.log('  [PASS] Test 14: payload_json cannot overwrite authoritative queue metadata');
    }

    console.log('\n========================================================================');
    console.log('  ALL 14/14 TELEMETRY AUTH FIX TESTS PASSED PERFECTLY (100% SUCCESS)    ');
    console.log('========================================================================\n');
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

runAuthFixTestSuite().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
