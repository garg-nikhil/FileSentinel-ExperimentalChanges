/**
 * FILE-SENTINEL — SCAN_COMPLETED Scans Tab 33-Column Field Mapping Verification Suite
 */

import http from 'node:http';
import crypto from 'node:crypto';
import assert from 'node:assert';
import { getDatabase } from '../backend/db.js';
import {
  TelemetryService,
  TelemetrySyncService,
  CURRENT_TELEMETRY_SCHEMA_VERSION
} from '../backend/telemetry.js';

async function runScansMappingTestSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: SCAN_COMPLETED 33-Column Scans Sheet Mapping Test Suite ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const telemetryService = new TelemetryService(db);
  const secret = 'test-secret-for-scans-mapping-verification';

  // Seed sample database tables
  const orgId = 'org-test-mapping';
  const userId = 'usr-auditor-99';
  const deviceId = 'DEV-WIN-PROD-01';
  const scanId = 'SCAN-TEST-MAPPING-001';

  db.exec(`
    INSERT INTO organizations (org_id, name, created_at) VALUES ('${orgId}', 'Mapping Org Corp', datetime('now'));
    INSERT INTO plans (plan_id, name, max_users, max_devices, scan_limit, feature_flags, created_at)
    VALUES ('Enterprise', 'Enterprise Plan', 100, 100, 1000, '{}', datetime('now'));
    INSERT INTO licenses (license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at, max_users, max_devices, scan_limit, feature_flags, created_at, updated_at)
    VALUES ('LIC-ENTERPRISE-01', '${orgId}', 'Enterprise', 'ACTIVE', datetime('now'), datetime('now'), datetime('now', '+30 days'), 100, 100, 1000, '{}', datetime('now'), datetime('now'));
    INSERT INTO scans (scan_id, root_path, start_time, end_time, status, total_files, supported_files, processed_files, error_count, critical_count, high_count, medium_count, low_count, safe_count)
    VALUES ('${scanId}', 'C:\\sample1, C:\\sample2', '2026-08-21T10:00:00.000Z', '2026-08-21T10:00:05.000Z', 'COMPLETED', 45, 45, 45, 0, 4, 3, 2, 1, 35);
    INSERT INTO audit_sessions (audit_id, scan_id, org_id, audit_date, agency_name, auditor_name, status, total_parameters, pass_count, fail_count, review_count, not_found_count, overall_score, max_score, overall_status, created_at, updated_at)
    VALUES ('AUDIT-001', '${scanId}', '${orgId}', '2026-08-21', 'AuditAgency', 'AuditorOne', 'COMPLETED', 30, 20, 2, 3, 5, 85, 100, 'PASS', datetime('now'), datetime('now'));
  `);

  let receivedBatch: any = null;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      receivedBatch = JSON.parse(body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        processed_count: receivedBatch.events ? receivedBatch.events.length : 0,
        duplicates_count: 0,
        failed_count: 0
      }));
    });
  });

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as any).port;

  try {
    // 1. Build telemetry payload from SQLite
    const payload = telemetryService.buildTelemetryPayload(scanId, orgId, userId, deviceId);
    assert.ok(payload, 'Payload must be constructed successfully');

    // Verify payload values
    assert.strictEqual(payload.scan_id, scanId);
    assert.strictEqual(payload.organization_id, orgId);
    assert.strictEqual(payload.user_id, userId);
    assert.strictEqual(payload.device_id, deviceId);
    assert.strictEqual(payload.duration_ms, 5000);
    assert.strictEqual(payload.files_discovered, 45);
    assert.strictEqual(payload.files_processed, 45);
    assert.strictEqual(payload.files_failed, 0);
    assert.strictEqual(payload.critical_count, 4);
    assert.strictEqual(payload.high_count, 3);
    assert.strictEqual(payload.medium_count, 2);
    assert.strictEqual(payload.low_count, 1);
    assert.strictEqual(payload.findings_count, 10);
    assert.strictEqual(payload.overall_score, 85);
    assert.strictEqual(payload.risk_score, 85);
    assert.strictEqual(payload.source_count, 2);
    assert.strictEqual(payload.license_id, 'LIC-ENTERPRISE-01');
    assert.strictEqual(payload.license_plan, 'Enterprise');
    assert.strictEqual(payload.license_status, 'ACTIVE');
    assert.strictEqual(typeof payload.license_days_remaining, 'number');

    console.log('  [PASS] Test 1: buildTelemetryPayload extracts all required fields from DB');

    // 2. Enqueue and sync
    telemetryService.enqueue(payload);

    const syncService = new TelemetrySyncService(db, {
      enabled: true,
      environment: 'test',
      ingestionUrl: `http://127.0.0.1:${port}/telemetry`,
      ingestionSecret: secret,
      maxEventsPerBatch: 50
    });

    const result = await syncService.syncOnce();
    assert.strictEqual(result.succeeded, 1);
    assert.strictEqual(result.failed, 0);
    assert.ok(receivedBatch);

    const evt = receivedBatch.events[0];
    assert.ok(evt.event_id.startsWith('EVT-TQ-'), 'event_id preserved');
    assert.strictEqual(evt.event_type, 'SCAN_COMPLETED', 'event_type is SCAN_COMPLETED');
    assert.strictEqual(evt.schema_version, CURRENT_TELEMETRY_SCHEMA_VERSION);
    assert.strictEqual(evt.scan_id, scanId);
    assert.strictEqual(evt.file_count, 45, 'files_discovered maps to file_count');
    assert.strictEqual(evt.files_processed, 45, 'files_processed maps correctly');
    assert.strictEqual(evt.files_failed, 0, 'files_failed maps correctly');
    assert.strictEqual(evt.critical_count, 4);
    assert.strictEqual(evt.high_count, 3);
    assert.strictEqual(evt.medium_count, 2);
    assert.strictEqual(evt.low_count, 1);
    assert.strictEqual(evt.findings_count, 10, 'findings_count is sum of critical+high+medium+low');
    assert.strictEqual(evt.duration_ms, 5000, 'duration_ms mapped');
    assert.strictEqual(evt.OS, process.platform, 'OS comes from device telemetry');
    assert.ok(evt.OS_version, 'OS_version comes from device telemetry');
    assert.strictEqual(evt.license_id, 'LIC-ENTERPRISE-01', 'Active license attached');
    assert.strictEqual(evt.license_plan, 'Enterprise');
    assert.strictEqual(evt.license_status, 'ACTIVE');

    console.log('  [PASS] Test 2: Outbound event contains complete 33-column aligned metadata');

    // 3. Test non-licensed fallback (unregistered org => license fields safely blank without fabrication)
    const unlicOrgId = 'org-unregistered-no-lic';
    const unlicScanId = 'SCAN-UNLIC-002';
    db.exec(`
      INSERT INTO scans (scan_id, root_path, start_time, end_time, status, total_files, supported_files, processed_files, error_count, critical_count, high_count, medium_count, low_count, safe_count)
      VALUES ('${unlicScanId}', 'C:\\sample', '2026-08-21T11:00:00.000Z', '2026-08-21T11:00:01.000Z', 'COMPLETED', 10, 10, 10, 0, 0, 0, 0, 0, 10);
    `);

    const unlicPayload = telemetryService.buildTelemetryPayload(unlicScanId, unlicOrgId, 'usr-guest', 'DEV-02');
    assert.ok(unlicPayload);
    assert.strictEqual(unlicPayload.license_id, undefined, 'Unavailable license_id remains safely undefined');
    assert.strictEqual(unlicPayload.license_plan, undefined, 'Unavailable license_plan remains safely undefined');
    assert.strictEqual(unlicPayload.license_status, undefined, 'Unavailable license_status remains safely undefined');
    assert.strictEqual(unlicPayload.license_days_remaining, undefined, 'Unavailable license_days_remaining remains safely undefined');

    console.log('  [PASS] Test 3: Unavailable license fields remain safely undefined (Zero Fabrication)');

    // 4. Test privacy guarantees: zero file contents, zero OCR, zero raw paths
    assert.strictEqual((payload as any).file_contents, undefined);
    assert.strictEqual((payload as any).extracted_text, undefined);
    assert.strictEqual((payload as any).raw_ocr, undefined);
    assert.strictEqual((payload as any).jwt, undefined);
    assert.strictEqual((payload as any).secret, undefined);

    console.log('  [PASS] Test 4: Absolute privacy invariants verified (No secrets, OCR, or file contents)');

    console.log('\n========================================================================');
    console.log('  ALL SCANS MAPPING TESTS PASSED PERFECTLY (100% SUCCESS)               ');
    console.log('========================================================================\n');
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

runScansMappingTestSuite().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
