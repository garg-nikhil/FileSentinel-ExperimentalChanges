/**
 * FILE-SENTINEL — Phase T2 Unit Tests: Telemetry Service Event Recording Suite
 */

import { DatabaseSync } from 'node:sqlite';
import assert from 'node:assert';
import { getDatabase } from '../backend/db.js';
import { TelemetryService } from '../backend/telemetry.js';

async function runTelemetryServiceEventTests() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Phase T2 Telemetry Service Event Test Suite           ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const service = new TelemetryService(db);
  const queueRepo = service.getQueueRepo();

  const orgId = 'org-acme-corp';
  const userId = 'usr-admin-01';
  const deviceId = 'DESKTOP-FINANCE-01';

  // Test 1: recordScanStarted
  {
    const res = service.recordScanStarted('SCAN-START-01', orgId, userId, deviceId, {
      scan_type: 'SECRETS',
      checklist_id: 'CHK-FIN-2026',
      checklist_version: '1.2.0',
      source_count: 3,
      offline_mode: false
    });
    assert.strictEqual(res.success, true, 'recordScanStarted must succeed');
    assert.ok(res.event_id?.startsWith('EVT-SCN-START-'), 'Event ID must have scan start prefix');

    const row = db.prepare('SELECT payload_json FROM telemetry_queue WHERE event_id = ?').get(res.event_id!) as any;
    assert.ok(row, 'Event must exist in telemetry queue');
    const parsed = JSON.parse(row.payload_json);
    assert.strictEqual(parsed.event_type, 'SCAN_STARTED');
    assert.strictEqual(parsed.scan_id, 'SCAN-START-01');
    assert.strictEqual(parsed.checklist_id, 'CHK-FIN-2026');
    assert.strictEqual(parsed.source_count, 3);
    assert.ok(parsed.endpoint_id.startsWith('EP-'), 'Endpoint ID must be pseudonymous');
    console.log('  [PASS] Test 1: recordScanStarted Event Dispatch');
  }

  // Test 2: recordScanCompleted with Full Aggregates
  {
    const res = service.recordScanCompleted('SCAN-COMP-01', orgId, userId, deviceId, {
      scan_type: 'FULL',
      duration_ms: 3450,
      source_count: 2,
      file_count: 120,
      files_processed: 120,
      files_skipped: 0,
      files_failed: 0,
      findings_count: 5,
      critical_count: 1,
      high_count: 2,
      medium_count: 1,
      low_count: 1,
      risk_score: 38.5,
      checklist_id: 'CHK-COMP-2026',
      checklist_version: '2.0.0',
      offline_mode: true,
      license_id: 'LIC-ENT-001',
      license_plan: 'ENTERPRISE',
      license_status: 'ACTIVE',
      license_days_remaining: 180
    });
    assert.strictEqual(res.success, true, 'recordScanCompleted must succeed');

    const row = db.prepare('SELECT payload_json FROM telemetry_queue WHERE event_id = ?').get(res.event_id!) as any;
    const parsed = JSON.parse(row.payload_json);
    assert.strictEqual(parsed.event_type, 'SCAN_COMPLETED');
    assert.strictEqual(parsed.scan_id, 'SCAN-COMP-01');
    assert.strictEqual(parsed.duration_ms, 3450);
    assert.strictEqual(parsed.files_processed, 120);
    assert.strictEqual(parsed.critical_count, 1);
    assert.strictEqual(parsed.risk_score, 38.5);
    assert.strictEqual(parsed.license_plan, 'ENTERPRISE');
    assert.strictEqual(parsed.offline_mode, true);
    console.log('  [PASS] Test 2: recordScanCompleted Full Aggregates Event Dispatch');
  }

  // Test 3: recordScanFailed
  {
    const res = service.recordScanFailed('SCAN-FAIL-01', orgId, userId, deviceId, {
      scan_type: 'PII',
      duration_ms: 120,
      error_code: 'ERR_PERMISSION_DENIED',
      sanitized_error_category: 'FILESYSTEM_ACCESS',
      offline_mode: false
    });
    assert.strictEqual(res.success, true, 'recordScanFailed must succeed');

    const row = db.prepare('SELECT payload_json FROM telemetry_queue WHERE event_id = ?').get(res.event_id!) as any;
    const parsed = JSON.parse(row.payload_json);
    assert.strictEqual(parsed.event_type, 'SCAN_FAILED');
    assert.strictEqual(parsed.error_code, 'ERR_PERMISSION_DENIED');
    assert.strictEqual(parsed.sanitized_error_category, 'FILESYSTEM_ACCESS');
    console.log('  [PASS] Test 3: recordScanFailed Event Dispatch');
  }

  // Test 4: recordEndpointAssessmentStarted
  {
    const res = service.recordEndpointAssessmentStarted('ASSESS-001', orgId, deviceId, { platform: 'win32' });
    assert.strictEqual(res.success, true);

    const row = db.prepare('SELECT payload_json FROM telemetry_queue WHERE event_id = ?').get(res.event_id!) as any;
    const parsed = JSON.parse(row.payload_json);
    assert.strictEqual(parsed.event_type, 'ENDPOINT_ASSESSMENT_STARTED');
    assert.strictEqual(parsed.assessment_id, 'ASSESS-001');
    console.log('  [PASS] Test 4: recordEndpointAssessmentStarted Event Dispatch');
  }

  // Test 5: recordEndpointAssessmentCompleted (Aggregate + Target Probes)
  {
    const targetProbes: any[] = [
      {
        category: 'SOCIAL_MEDIA',
        target: 'facebook.com',
        status: 'ACCESSIBLE',
        confidence: 'HIGH',
        network_reachable: true,
        policy_block_detected: false,
        service_identity_confirmed: true,
        response_time_ms: 142,
        probe_attempts: 1,
        reason_code: 'HTTP_200_VALID_BODY'
      },
      {
        category: 'CLOUD_STORAGE',
        target: 'drive.google.com',
        status: 'ACCESSIBLE',
        confidence: 'HIGH',
        network_reachable: true,
        policy_block_detected: false,
        service_identity_confirmed: true,
        response_time_ms: 110,
        probe_attempts: 1,
        reason_code: 'HTTP_200_VALID_BODY'
      }
    ];

    const res = service.recordEndpointAssessmentCompleted(
      'ASSESS-001',
      orgId,
      deviceId,
      {
        usb_status: 'DISABLED',
        usb_storage_detected: false,
        total_targets_tested: 21,
        accessible_count: 21,
        blocked_count: 0,
        unreachable_count: 0,
        indeterminate_count: 0,
        social_media_accessible_count: 5,
        social_media_blocked_count: 0,
        social_media_unreachable_count: 0,
        social_media_indeterminate_count: 0,
        personal_email_accessible_count: 4,
        personal_email_blocked_count: 0,
        personal_email_unreachable_count: 0,
        personal_email_indeterminate_count: 0,
        messaging_accessible_count: 4,
        messaging_blocked_count: 0,
        messaging_unreachable_count: 0,
        messaging_indeterminate_count: 0,
        cloud_storage_accessible_count: 5,
        cloud_storage_blocked_count: 0,
        cloud_storage_unreachable_count: 0,
        cloud_storage_indeterminate_count: 0,
        overall_compliance_score: 95.0,
        assessment_duration_ms: 1800
      },
      targetProbes
    );
    assert.strictEqual(res.success, true);

    const row = db.prepare('SELECT payload_json FROM telemetry_queue WHERE event_id = ?').get(res.event_id!) as any;
    const parsed = JSON.parse(row.payload_json);
    assert.strictEqual(parsed.event_type, 'ENDPOINT_ASSESSMENT_COMPLETED');
    assert.strictEqual(parsed.usb_status, 'DISABLED');
    assert.strictEqual(parsed.usb_storage_detected, false);
    assert.strictEqual(parsed.total_targets_tested, 21);
    assert.strictEqual(parsed.overall_compliance_score, 95.0);

    // Verify target probes were queued as separate items
    const targetRows = db.prepare("SELECT payload_json FROM telemetry_queue WHERE payload_json LIKE '%facebook.com%'").all() as any[];
    assert.strictEqual(targetRows.length, 1, 'Target probe for facebook.com must be queued');
    const targetParsed = JSON.parse(targetRows[0].payload_json);
    assert.strictEqual(targetParsed.target, 'facebook.com');
    assert.strictEqual(targetParsed.status, 'ACCESSIBLE');
    assert.strictEqual(targetParsed.network_reachable, true);
    console.log('  [PASS] Test 5: recordEndpointAssessmentCompleted (Aggregate + Endpoint_Targets) Event Dispatch');
  }

  // Test 6: recordLicenseEvent (All 5 Lifecycle States)
  {
    const states: ('LICENSE_ACTIVATED' | 'LICENSE_RENEWED' | 'LICENSE_EXPIRING' | 'LICENSE_EXPIRED' | 'LICENSE_REVALIDATED')[] = [
      'LICENSE_ACTIVATED',
      'LICENSE_RENEWED',
      'LICENSE_EXPIRING',
      'LICENSE_EXPIRED',
      'LICENSE_REVALIDATED'
    ];

    for (const st of states) {
      const res = service.recordLicenseEvent(st, orgId, deviceId, {
        license_id: 'LIC-TEST-123',
        plan: 'ENTERPRISE',
        status: 'ACTIVE',
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
        days_remaining: 30,
        device_count: 3,
        max_devices: 10
      });
      assert.strictEqual(res.success, true, `recordLicenseEvent for ${st} must succeed`);
    }
    console.log('  [PASS] Test 6: recordLicenseEvent (All 5 License Lifecycle States) Event Dispatch');
  }

  // Test 7: recordAppLifecycle (APP_STARTED)
  {
    const res = service.recordAppLifecycle('APP_STARTED', orgId, deviceId, {
      application_version: '8.2.0',
      OS: 'Windows',
      OS_version: '11.0.22631',
      machine_type: 'x64',
      architecture: 'x64'
    });
    assert.strictEqual(res.success, true);
    console.log('  [PASS] Test 7: recordAppLifecycle (APP_STARTED) Event Dispatch');
  }

  // Test 8: recordReportGenerated
  {
    const res = service.recordReportGenerated('RPT-AUDIT-999', 'SCAN-COMP-01', orgId, userId, deviceId, {
      report_type: 'PDF_CERTIFICATE',
      compliance_score: 98.2
    });
    assert.strictEqual(res.success, true);
    console.log('  [PASS] Test 8: recordReportGenerated Event Dispatch');
  }

  // Test 9: recordChecklistToggled
  {
    const resOn = service.recordChecklistToggled('CHK-HIPAA', '2026.2', true, orgId, userId, deviceId);
    assert.strictEqual(resOn.success, true);
    const resOff = service.recordChecklistToggled('CHK-HIPAA', '2026.2', false, orgId, userId, deviceId);
    assert.strictEqual(resOff.success, true);
    console.log('  [PASS] Test 9: recordChecklistToggled (Enabled / Disabled) Event Dispatch');
  }

  // Test 10: recordError (Sanitized)
  {
    const res = service.recordError(
      'E_SQLITE_BUSY',
      'DATABASE_LOCK',
      'Database locked while reading C:\\Users\\Administrator\\Secret\\token.key with bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      orgId,
      userId,
      deviceId
    );
    assert.strictEqual(res.success, true);

    const row = db.prepare('SELECT payload_json FROM telemetry_queue WHERE event_id = ?').get(res.event_id!) as any;
    const parsed = JSON.parse(row.payload_json);
    assert.strictEqual(parsed.event_type, 'ERROR');
    assert.ok(parsed.sanitized_message.includes('[REDACTED_PATH]'), 'File path in error message must be redacted');
    assert.ok(parsed.sanitized_message.includes('[REDACTED_JWT]'), 'JWT in error message must be redacted');
    console.log('  [PASS] Test 10: recordError Sanitized Event Dispatch');
  }

  console.log('\n========================================================================');
  console.log('  ALL 10/10 PHASE T2 TELEMETRY SERVICE EVENT TESTS PASSED (100% SUCCESS)');
  console.log('========================================================================\n');
}

runTelemetryServiceEventTests().catch(err => {
  console.error('\n❌ Test failed:', err);
  process.exit(1);
});
