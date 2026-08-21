/**
 * FILE-SENTINEL — Phase T9: Live Scan, Assessment & Telemetry E2E Verification
 */

import http from 'node:http';
import assert from 'node:assert';
import { getDatabase } from '../backend/db.js';
import { TelemetryService } from '../backend/telemetry.js';
import { TelemetrySyncService } from '../backend/telemetry/telemetrySyncService.js';
import { LocalAnalyticsService } from '../backend/telemetry/localAnalytics.js';

async function runLiveVerification() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Phase T9 Live End-to-End Verification                 ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const orgId = 'org-live-e2e';
  const userId = 'usr-auditor-live';
  const deviceId = 'DEV-DESKTOP-LIVE';
  const now = new Date().toISOString();

  // Setup basic relational context
  db.exec(`
    INSERT INTO organizations (org_id, name, suspended, created_at) VALUES ('${orgId}', 'E2E Corp', 0, '${now}');
    INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at)
    VALUES ('${userId}', '${orgId}', 'liveuser', 'hash', 'ORG_ADMIN', 0, '${now}');
    INSERT INTO devices (device_id, org_id, device_name, registered_at)
    VALUES ('${deviceId}', '${orgId}', 'Auditor Machine', '${now}');
  `);

  const telemetryService = new TelemetryService(db);
  const queueRepo = telemetryService.getQueueRepo();
  const analyticsService = new LocalAnalyticsService(db);

  // 1. Emulate Scan LifeCycle & Emission
  console.log('1. Recording Live Scan Execution...');
  telemetryService.recordScanStarted('SCN-LIVE-01', orgId, userId, deviceId, { source_count: 1 });
  telemetryService.recordScanCompleted('SCN-LIVE-01', orgId, userId, deviceId, {
    duration_ms: 1850,
    source_count: 1,
    file_count: 42,
    files_processed: 42,
    findings_count: 0,
    risk_score: 0.0
  });

  // 2. Emulate Endpoint Assessment LifeCycle & Emission
  console.log('2. Recording Live Endpoint Assessment...');
  telemetryService.recordEndpointAssessmentStarted('ASSESS-LIVE-01', orgId, deviceId, { platform: 'win32' });
  telemetryService.recordEndpointAssessmentCompleted(
    'ASSESS-LIVE-01',
    orgId,
    deviceId,
    {
      usb_status: 'DISABLED',
      usb_storage_detected: false,
      total_targets_tested: 21,
      accessible_count: 21,
      overall_compliance_score: 100
    },
    [
      { target: 'Google Drive', category: 'CLOUD_STORAGE', status: 'ACCESSIBLE', confidence: 'HIGH', network_reachable: true, policy_block_detected: false, service_identity_confirmed: true, response_time_ms: 120, probe_attempts: 1, reason_code: 'OK' },
      { target: 'OneDrive', category: 'CLOUD_STORAGE', status: 'ACCESSIBLE', confidence: 'HIGH', network_reachable: true, policy_block_detected: false, service_identity_confirmed: true, response_time_ms: 140, probe_attempts: 1, reason_code: 'OK' }
    ]
  );

  // 3. Emulate License & Report Events
  console.log('3. Recording License & Report Events...');
  telemetryService.recordLicenseEvent('LICENSE_ACTIVATED', orgId, deviceId, {
    license_id: 'LIC-LIVE-01',
    plan: 'ENTERPRISE',
    status: 'ACTIVE',
    issued_at: now,
    expires_at: new Date(Date.now() + 365 * 86400000).toISOString(),
    days_remaining: 365
  });
  telemetryService.recordReportGenerated('REP-LIVE-01', 'SCN-LIVE-01', orgId, userId, deviceId, {
    report_type: 'PDF',
    compliance_score: 100
  });

  // Verify Local SQLite Queue Stats Before Sync
  const healthInitial = analyticsService.getTelemetryHealthSummary();
  console.log('\nLocal Queue Status Before Sync:', healthInitial);
  assert.ok(healthInitial.events_pending >= 6, 'All 6 emitted events must be queued in local SQLite');
  assert.strictEqual(healthInitial.events_sent, 0, 'No events marked SENT before network transmission');

  // 4. Start Mock Google Apps Script Ingestion Endpoint
  const receivedBatches: any[] = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      receivedBatches.push(JSON.parse(body));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, processed_count: receivedBatches[0]?.events?.length || 0 }));
    });
  });

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as any).port;
  const ingestionUrl = `http://127.0.0.1:${port}/telemetry/ingest`;

  const syncService = new TelemetrySyncService(db, {
    enabled: true,
    environment: 'production',
    ingestionUrl,
    ingestionSecret: 'prod-secret-e2e-test',
    maxEventsPerBatch: 50
  });

  // 5. Execute Background Synchronization
  console.log('\n4. Executing Telemetry Synchronization...');
  const syncResult = await syncService.syncOnce();
  console.log('Sync Result:', syncResult);
  assert.strictEqual(syncResult.failed, 0, 'All events must sync without failure');
  assert.ok(syncResult.succeeded >= 6, 'All queued events marked SENT');

  // Verify Local SQLite Queue Stats After Sync
  const healthFinal = analyticsService.getTelemetryHealthSummary();
  console.log('\nLocal Queue Status After Sync:', healthFinal);
  assert.strictEqual(healthFinal.events_pending, 0, 'Zero pending events remaining');
  assert.ok(healthFinal.events_sent >= 6, 'All events successfully marked SENT in SQLite');

  // 6. Test Deduplication
  console.log('\n5. Testing Re-Sync Deduplication (No-Op)...');
  const syncAgain = await syncService.syncOnce();
  assert.strictEqual(syncAgain.processed, 0, 'No pending events to sync on second run');

  server.close();
  syncService.stop();

  console.log('\n========================================================================');
  console.log('  PHASE T9 LIVE E2E VERIFICATION COMPLETED (100% SUCCESS)              ');
  console.log('========================================================================\n');
}

runLiveVerification().catch(err => {
  console.error('\n❌ Live Verification failed:', err);
  process.exit(1);
});
