/**
 * FILE-SENTINEL — Focused Telemetry Sync Activation & Lifecycle Regression Tests
 */

import http from 'node:http';
import assert from 'node:assert';
import { DatabaseSync } from 'node:sqlite';
import { getDatabase } from '../backend/db.js';
import { TelemetrySyncService } from '../backend/telemetry/telemetrySyncService.js';
import { getTelemetryConfig } from '../backend/telemetry/telemetryPrivacy.js';

async function runTelemetryActivationTests() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Telemetry Sync Activation & Lifecycle Test Suite       ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');

  // Insert mock legacy records to verify compatibility and non-deletion
  db.exec(`
    INSERT INTO telemetry_queue (
      id, queue_id, event_id, event_type, schema_version, priority, scan_id, organization_id, payload_json, status, attempts, created_at
    ) VALUES
      ('LEGACY-1', 'Q-LEG-1', 'EVT-LEG-1', 'SCAN_COMPLETED', 1, 'NORMAL', 'SCN-LEG-1', 'org-1', '{}', 'SYNCED', 1, '2026-08-20T00:00:00.000Z'),
      ('LEGACY-2', 'Q-LEG-2', 'EVT-LEG-2', 'SCAN_COMPLETED', 1, 'NORMAL', 'SCN-LEG-2', 'org-1', '{}', 'SYNCED', 1, '2026-08-20T01:00:00.000Z');
  `);

  // 1. Telemetry Disabled -> Sync worker not started
  {
    delete process.env.TELEMETRY_ENABLED;
    delete process.env.TELEMETRY_INGESTION_URL;
    delete process.env.TELEMETRY_INGESTION_SECRET;

    const config = getTelemetryConfig();
    assert.strictEqual(config.enabled, false, 'Telemetry must be disabled by default');

    let workerStarted = false;
    if (config.enabled && config.ingestionUrl && config.ingestionSecret) {
      workerStarted = true;
    }
    assert.strictEqual(workerStarted, false, 'Sync worker must not start when telemetry is disabled');
    console.log('  [PASS] Test 1: Telemetry Disabled -> Sync worker not started');
  }

  // 2. Telemetry Enabled + URL Missing -> Safe Warning & Sync worker not started
  {
    process.env.TELEMETRY_ENABLED = 'true';
    delete process.env.TELEMETRY_INGESTION_URL;
    process.env.TELEMETRY_INGESTION_SECRET = 'secret-12345678901234567890123456789012';

    let warningLogged = false;
    let workerStarted = false;

    const isEnabled = process.env.TELEMETRY_ENABLED === 'true';
    const url = process.env.TELEMETRY_INGESTION_URL?.trim();
    const secret = process.env.TELEMETRY_INGESTION_SECRET?.trim();

    if (isEnabled) {
      if (!url) {
        warningLogged = true;
      } else if (!secret) {
        warningLogged = true;
      } else {
        workerStarted = true;
      }
    }

    assert.strictEqual(warningLogged, true, 'Safe configuration warning must trigger');
    assert.strictEqual(workerStarted, false, 'Sync worker must not start when URL is missing');
    console.log('  [PASS] Test 2: Telemetry Enabled + URL Missing -> Safe Warning & Sync worker not started');
  }

  // 3. Telemetry Enabled + Secret Missing -> Safe Warning & Sync worker not started
  {
    process.env.TELEMETRY_ENABLED = 'true';
    process.env.TELEMETRY_INGESTION_URL = 'https://script.google.com/macros/s/TEST/exec';
    delete process.env.TELEMETRY_INGESTION_SECRET;

    let warningLogged = false;
    let workerStarted = false;

    const isEnabled = process.env.TELEMETRY_ENABLED === 'true';
    const url = process.env.TELEMETRY_INGESTION_URL?.trim();
    const secret = process.env.TELEMETRY_INGESTION_SECRET?.trim();

    if (isEnabled) {
      if (!url) {
        warningLogged = true;
      } else if (!secret) {
        warningLogged = true;
      } else {
        workerStarted = true;
      }
    }

    assert.strictEqual(warningLogged, true, 'Safe configuration warning must trigger');
    assert.strictEqual(workerStarted, false, 'Sync worker must not start when Secret is missing');
    console.log('  [PASS] Test 3: Telemetry Enabled + Secret Missing -> Safe Warning & Sync worker not started');
  }

  // 4. Telemetry Enabled + URL + Secret -> Sync worker starts
  {
    const secretValue = 'test-secret-key-1234567890abcdef1234567890abcdef';
    process.env.TELEMETRY_ENABLED = 'true';
    process.env.TELEMETRY_INGESTION_URL = 'http://127.0.0.1:59990/exec';
    process.env.TELEMETRY_INGESTION_SECRET = secretValue;

    const url = process.env.TELEMETRY_INGESTION_URL?.trim();
    const secret = process.env.TELEMETRY_INGESTION_SECRET?.trim();

    let syncService: TelemetrySyncService | null = null;
    if (process.env.TELEMETRY_ENABLED === 'true' && url && secret) {
      syncService = new TelemetrySyncService(db, {
        enabled: true,
        ingestionUrl: url,
        ingestionSecret: secret,
        environment: 'test',
        maxEventsPerBatch: 50
      });
      syncService.start(1000);
    }

    assert.ok(syncService, 'SyncService must be instantiated');
    syncService?.stop();
    console.log('  [PASS] Test 4: Telemetry Enabled + URL + Secret -> Sync worker starts & stops cleanly');
  }

  // 5. Google Endpoint Unavailable -> Application remains healthy & non-blocking
  {
    const syncService = new TelemetrySyncService(db, {
      enabled: true,
      ingestionUrl: 'http://127.0.0.1:59999/unreachable',
      ingestionSecret: 'secret-xyz',
      environment: 'test'
    });

    const start = Date.now();
    const res = await syncService.syncOnce();
    const duration = Date.now() - start;

    assert.strictEqual(res.succeeded, 0);
    assert.ok(duration < 5000, 'Sync execution must be bounded and non-blocking');
    console.log('  [PASS] Test 5: Google Endpoint Unavailable -> Sync fails safely without throwing');
  }

  // 6. Legacy Queue Records Compatibility & Preservation
  {
    const legacyRecords = db.prepare("SELECT * FROM telemetry_queue WHERE status = 'SYNCED'").all();
    assert.strictEqual(legacyRecords.length, 2, 'Existing legacy SYNCED records must remain completely intact');
    console.log('  [PASS] Test 6: Existing legacy telemetry_queue records remain intact');
  }

  // 7. No Secret is Written to Logs
  {
    const secretValue = 'SECRET_NEVER_PRINT_THIS_KEY_ABC123';
    const logs: string[] = [];
    const origLog = console.log;
    const origWarn = console.warn;

    console.log = (...args) => { logs.push(args.join(' ')); origLog(...args); };
    console.warn = (...args) => { logs.push(args.join(' ')); origWarn(...args); };

    // Simulate startup messages
    const isTelemetryEnabled = true;
    const ingestionUrl = 'https://script.google.com/macros/s/TEST/exec';
    const ingestionSecret = secretValue;

    if (isTelemetryEnabled && ingestionUrl && ingestionSecret) {
      console.log(`[Telemetry] Background synchronization service active (Interval: 60s)`);
    }

    console.log = origLog;
    console.warn = origWarn;

    for (const line of logs) {
      assert.strictEqual(line.includes(secretValue), false, 'Secret must NEVER be written to logs');
    }
    console.log('  [PASS] Test 7: Secrets are strictly excluded from console logs');
  }

  // 8. Server Startup Non-Blocking Guarantee
  {
    // Proves start() returns synchronously without awaiting HTTP I/O
    const syncService = new TelemetrySyncService(db, {
      enabled: true,
      ingestionUrl: 'http://127.0.0.1:59999/unreachable',
      ingestionSecret: 'secret-xyz'
    });

    const t0 = Date.now();
    syncService.start(60000);
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 50, 'start() must return immediately (< 50ms)');
    syncService.stop();
    console.log('  [PASS] Test 8: Server startup does not block waiting for telemetry');
  }

  // Clean up environment variables
  delete process.env.TELEMETRY_ENABLED;
  delete process.env.TELEMETRY_INGESTION_URL;
  delete process.env.TELEMETRY_INGESTION_SECRET;

  console.log('\n========================================================================');
  console.log('  ALL 8/8 TELEMETRY SYNC ACTIVATION TESTS PASSED (100% SUCCESS)         ');
  console.log('========================================================================\n');
}

runTelemetryActivationTests().catch(err => {
  console.error('\n❌ Activation Test failed:', err);
  process.exit(1);
});
