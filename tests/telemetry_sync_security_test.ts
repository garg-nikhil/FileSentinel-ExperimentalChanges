/**
 * FILE-SENTINEL — Phase T3 Unit Tests: Telemetry Sync Service & Security Authentication Suite
 */

import http from 'node:http';
import crypto from 'node:crypto';
import assert from 'node:assert';
import { DatabaseSync } from 'node:sqlite';
import { getDatabase } from '../backend/db.js';
import { TelemetryService } from '../backend/telemetry.js';
import { TelemetrySyncService } from '../backend/telemetry/telemetrySyncService.js';

async function runTelemetrySyncSecurityTests() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Phase T3 Telemetry Sync & Security Test Suite         ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const telemetryService = new TelemetryService(db);
  const queueRepo = telemetryService.getQueueRepo();

  const secret = 'test-secret-key-1234567890abcdef1234567890abcdef';
  const receivedBatches: any[] = [];
  const receivedNonces = new Set<string>();
  let mockServerStatus = 200;
  let mockServerDropConnection = false;

  // Setup Mock Google Apps Script Ingestion HTTP Server
  const server = http.createServer((req, res) => {
    if (mockServerDropConnection) {
      req.socket.destroy();
      return;
    }

    let body = '';
    req.on('data', chunk => {
      body += chunk;
    });

    req.on('end', () => {
      let parsed: any;
      try {
        parsed = JSON.parse(body);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Malformed JSON' }));
        return;
      }

      const timestamp = parsed.auth?.timestamp as string;
      const nonce = parsed.auth?.nonce as string;
      const signature = parsed.auth?.signature as string;

      // 1. Verify Timestamp Freshness (< 5 minutes)
      const now = Date.now();
      const reqTime = parseInt(timestamp || '0', 10);
      if (!timestamp || Math.abs(now - reqTime) > 5 * 60 * 1000) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Timestamp expired or missing' }));
        return;
      }

      // 2. Verify Nonce Replay
      if (!nonce || receivedNonces.has(nonce)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Replay detected' }));
        return;
      }
      receivedNonces.add(nonce);

      // 3. Verify HMAC Signature using Canonical Payload
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

      // 4. Return configured response status
      if (mockServerStatus !== 200) {
        res.writeHead(mockServerStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: `Mock error ${mockServerStatus}` }));
        return;
      }

      receivedBatches.push(parsed);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        processed_count: parsed.events?.length || 0,
        duplicates_count: 0,
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
    environment: 'test',
    ingestionUrl,
    ingestionSecret: secret,
    maxEventsPerBatch: 50
  });

  try {
    // Test 1: Successful Batch Synchronization with Valid HMAC
    {
      // Enqueue 3 events
      telemetryService.recordScanCompleted('SCN-SYNC-01', 'org-alpha', 'user-01', 'DEV-01', {
        duration_ms: 1200,
        findings_count: 0
      });
      telemetryService.recordScanCompleted('SCN-SYNC-02', 'org-alpha', 'user-01', 'DEV-01', {
        duration_ms: 1500,
        findings_count: 1
      });
      telemetryService.recordEndpointAssessmentCompleted('ASSESS-SYNC-01', 'org-alpha', 'DEV-01', {
        overall_compliance_score: 100
      });

      const res = await syncService.syncOnce();
      assert.strictEqual(res.processed, 3, 'Processed count must be 3');
      assert.strictEqual(res.succeeded, 3, 'Succeeded count must be 3');
      assert.strictEqual(res.failed, 0, 'Failed count must be 0');

      assert.strictEqual(receivedBatches.length, 1, 'Server must receive 1 batch');
      assert.strictEqual(receivedBatches[0].events.length, 3, 'Batch must contain 3 events');

      // Verify records in DB are marked SENT
      const health = syncService.getHealthStats();
      assert.strictEqual(health.events_pending, 0, 'No pending events remaining');
      assert.strictEqual(health.events_sent, 3, '3 events marked SENT');
      console.log('  [PASS] Test 1: Batch Synchronization with Valid HMAC-SHA256 Signature');
    }

    // Test 2: Maximum Batch Capping (Up to 50 events)
    {
      // Clear and enqueue 60 events
      db.exec('DELETE FROM telemetry_queue;');
      for (let i = 1; i <= 60; i++) {
        telemetryService.recordScanStarted(`SCN-BATCH-${i}`, 'org-alpha', 'user-01', 'DEV-01', {
          source_count: 1
        });
      }

      const res1 = await syncService.syncOnce();
      assert.strictEqual(res1.processed, 50, 'First batch must be capped at 50 events');
      assert.strictEqual(res1.succeeded, 50);

      const health1 = syncService.getHealthStats();
      assert.strictEqual(health1.events_pending, 10, '10 events remain pending for next cycle');

      const res2 = await syncService.syncOnce();
      assert.strictEqual(res2.processed, 10, 'Second batch processes remaining 10 events');
      assert.strictEqual(res2.succeeded, 10);
      console.log('  [PASS] Test 2: Batch Size Limit (Capped at 50 Events per Batch)');
    }

    // Test 3: Authentication Rejection (Wrong Ingestion Secret)
    {
      db.exec('DELETE FROM telemetry_queue;');
      telemetryService.recordError('ERR_01', 'CAT_01', 'Sample error message', 'org-alpha');

      // Configure wrong secret
      syncService.setConfig({ ingestionSecret: 'invalid-attacker-secret' });
      const res = await syncService.syncOnce();
      assert.strictEqual(res.failed, 1, 'Sync must report failure on invalid HMAC');
      assert.ok(res.error?.includes('403'), 'Must receive HTTP 403 Authentication failure');

      const health = syncService.getHealthStats();
      assert.strictEqual(health.events_pending, 1, 'Failed event remains pending for retry');
      assert.ok(health.last_sync_error?.includes('403'));

      // Restore valid secret and resync
      syncService.setConfig({ ingestionSecret: secret });
      // Reset next_attempt_at so it can sync immediately
      db.exec("UPDATE telemetry_queue SET next_attempt_at = datetime('now', '-1 minute');");
      const resRetry = await syncService.syncOnce();
      assert.strictEqual(resRetry.succeeded, 1, 'Resync succeeds once secret is corrected');
      console.log('  [PASS] Test 3: Authentication Rejection (Wrong HMAC Secret -> HTTP 403 & Retry)');
    }

    // Test 4: Network Outage Isolation (Endpoint Unreachable)
    {
      db.exec('DELETE FROM telemetry_queue;');
      telemetryService.recordScanCompleted('SCN-OFFLINE-01', 'org-alpha', 'user-01', 'DEV-01', {
        duration_ms: 500
      });

      // Point sync to unreachable port
      syncService.setConfig({ ingestionUrl: 'http://127.0.0.1:59999/unreachable' });

      // Outage must not throw or crash
      const res = await syncService.syncOnce();
      assert.strictEqual(res.succeeded, 0);
      assert.ok(res.error, 'Error must be captured');

      const health = syncService.getHealthStats();
      assert.strictEqual(health.events_pending, 1, 'Event remains queued locally during network outage');

      // Restore correct URL
      syncService.setConfig({ ingestionUrl });
      db.exec("UPDATE telemetry_queue SET next_attempt_at = datetime('now', '-1 minute');");
      const resRestored = await syncService.syncOnce();
      assert.strictEqual(resRestored.succeeded, 1, 'Event synchronizes after network restored');
      console.log('  [PASS] Test 4: Outage Isolation (Unreachable Endpoint -> Queued Locally -> Synchronized on Recovery)');
    }

    // Test 5: Exponential Backoff Scheduling
    {
      db.exec('DELETE FROM telemetry_queue;');
      telemetryService.recordError('ERR_NET', 'NETWORK', 'Connection reset', 'org-alpha');

      mockServerStatus = 500;
      await syncService.syncOnce();

      const row = db.prepare('SELECT attempt_count, next_attempt_at, last_error FROM telemetry_queue').get() as any;
      assert.strictEqual(row.attempt_count, 1, 'Attempt count incremented');
      assert.ok(row.next_attempt_at, 'Next attempt time calculated');
      assert.ok(new Date(row.next_attempt_at).getTime() > Date.now(), 'Next attempt scheduled in future');

      mockServerStatus = 200;
      console.log('  [PASS] Test 5: Exponential Backoff Scheduling on Transient Errors');
    }

    console.log('\n========================================================================');
    console.log('  ALL 5/5 PHASE T3 TELEMETRY SYNC & SECURITY TESTS PASSED (100% SUCCESS)');
    console.log('========================================================================\n');
  } finally {
    server.close();
    syncService.stop();
  }
}

runTelemetrySyncSecurityTests().catch(err => {
  console.error('\n❌ Test failed:', err);
  process.exit(1);
});
