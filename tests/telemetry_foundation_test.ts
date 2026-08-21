/**
 * FILE-SENTINEL — Phase T1 & T1.5 Unit Tests: Telemetry Foundation, Privacy, and Local Queue
 */

import { DatabaseSync } from 'node:sqlite';
import assert from 'node:assert';
import { getDatabase } from '../backend/db.js';
import {
  filterAndSanitizeEvent,
  generateEndpointId,
  getOrCreateInstallationIdentity,
  getTelemetryConfig,
  getEventPriority,
  MAX_EVENT_SIZE_BYTES,
  MAX_QUEUE_CAPACITY
} from '../backend/telemetry/telemetryPrivacy.js';
import { TelemetryQueueRepository } from '../backend/telemetry/telemetryQueue.js';
import {
  CURRENT_TELEMETRY_SCHEMA_VERSION,
  ScanCompletedPayload,
  EndpointAssessmentCompletedPayload,
  LicenseEventPayload,
  AppStartedPayload,
  ErrorEventPayload
} from '../backend/telemetry/telemetryTypes.js';

async function runTelemetryFoundationTests() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Phase T1 & T1.5 Telemetry Foundation Test Suite       ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const queueRepo = new TelemetryQueueRepository(db, 10); // small queue limit for eviction testing

  const { installationId, installationSecret } = getOrCreateInstallationIdentity(db);
  assert.ok(installationId.startsWith('INST-'), 'Installation ID must be generated with INST- prefix');
  assert.ok(installationSecret.length >= 32, 'Installation secret must be secure random hex string');

  // Test 1: Stable pseudonymous endpoint_id derivation
  {
    const epId1 = generateEndpointId('DESKTOP-ABC1234', installationSecret);
    const epId2 = generateEndpointId('DESKTOP-ABC1234', installationSecret);
    assert.strictEqual(epId1, epId2, 'Endpoint ID must be deterministic and stable for same device');
    assert.ok(epId1.startsWith('EP-'), 'Endpoint ID must follow EP- format');
    assert.strictEqual(epId1.includes('DESKTOP'), false, 'Endpoint ID must not leak raw device name');
    console.log('  [PASS] Test 1: Stable Pseudonymous Endpoint ID Derivation');
  }

  // Test 2: Installation Identity Persistence
  {
    const identity2 = getOrCreateInstallationIdentity(db);
    assert.strictEqual(identity2.installationId, installationId, 'Installation ID must be persisted');
    assert.strictEqual(identity2.installationSecret, installationSecret, 'Installation secret must be persisted');
    console.log('  [PASS] Test 2: Installation Identity Persistence');
  }

  // Test 3: Allowlist Enforcement (Strips Unpermitted Fields)
  {
    const rawScanPayload: any = {
      event_id: 'EVT-SCAN-001',
      event_type: 'SCAN_COMPLETED',
      schema_version: CURRENT_TELEMETRY_SCHEMA_VERSION,
      timestamp_utc: new Date().toISOString(),
      installation_id: installationId,
      organization_id: 'org-alpha',
      device_id: 'dev-01',
      endpoint_id: 'EP-1234567890ABCDEF',
      scan_id: 'SCAN-001',
      scan_type: 'FULL',
      duration_ms: 1200,
      machine_type: 'x64',
      OS: 'Windows',
      OS_version: '10.0.19045',
      architecture: 'x64',
      application_version: '1.0.0',
      source_count: 1,
      file_count: 10,
      files_processed: 10,
      files_skipped: 0,
      files_failed: 0,
      findings_count: 2,
      critical_count: 0,
      high_count: 0,
      medium_count: 1,
      low_count: 1,
      risk_score: 15.5,
      offline_mode: false,
      // UNPERMITTED SENSITIVE FIELDS:
      raw_file_contents: 'Top Secret Contract Details',
      ocr_extracted_text: 'Social Security Number: 123-45-6789',
      full_file_path: 'C:\\Users\\Alice\\Documents\\Confidential.pdf',
      document_name: 'Confidential.pdf',
      user_password_hash: '5f4dcc3b5aa765d61d8327deb882cf99'
    };

    const sanitized = filterAndSanitizeEvent(rawScanPayload);
    assert.ok(sanitized, 'Sanitized payload must exist');
    assert.strictEqual(sanitized.event_id, 'EVT-SCAN-001');
    assert.strictEqual(sanitized.scan_id, 'SCAN-001');
    assert.strictEqual((sanitized as any).raw_file_contents, undefined, 'File contents MUST be removed');
    assert.strictEqual((sanitized as any).ocr_extracted_text, undefined, 'OCR text MUST be removed');
    assert.strictEqual((sanitized as any).full_file_path, undefined, 'Full file paths MUST be removed');
    assert.strictEqual((sanitized as any).document_name, undefined, 'Document names MUST be removed');
    assert.strictEqual((sanitized as any).user_password_hash, undefined, 'Passwords MUST be removed');
    console.log('  [PASS] Test 3: Strict Schema Allowlist Enforcement');
  }

  // Test 4: Sensitive Data Sanitizer (Second Defense Layer)
  {
    const rawErrorPayload: any = {
      event_id: 'EVT-ERR-001',
      event_type: 'ERROR',
      schema_version: CURRENT_TELEMETRY_SCHEMA_VERSION,
      timestamp_utc: new Date().toISOString(),
      installation_id: installationId,
      organization_id: 'org-alpha',
      device_id: 'dev-01',
      endpoint_id: 'EP-1234567890ABCDEF',
      error_code: 'ERR_ACCESS_DENIED',
      error_category: 'FILE_IO',
      sanitized_message: 'Failed to access C:\\Users\\Administrator\\Secret\\token.key with bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c for user alice@corporate.internal'
    };

    const sanitized = filterAndSanitizeEvent(rawErrorPayload);
    assert.ok(sanitized, 'Sanitized error event must exist');
    assert.ok(sanitized.sanitized_message.includes('[REDACTED_PATH]'), 'Windows path must be redacted');
    assert.ok(sanitized.sanitized_message.includes('[REDACTED_JWT]'), 'JWT must be redacted');
    assert.ok(sanitized.sanitized_message.includes('[REDACTED_EMAIL]'), 'Email must be redacted');
    assert.strictEqual(sanitized.sanitized_message.includes('alice@corporate.internal'), false, 'Plaintext email must not appear');
    console.log('  [PASS] Test 4: Sensitive Data Sanitizer (Path, JWT, Email Redaction)');
  }

  // Test 5: Payload Size Limit (Max 64KB)
  {
    const oversizedPayload: any = {
      event_id: 'EVT-LARGE-001',
      event_type: 'ERROR',
      schema_version: CURRENT_TELEMETRY_SCHEMA_VERSION,
      timestamp_utc: new Date().toISOString(),
      installation_id: installationId,
      organization_id: 'org-alpha',
      device_id: 'dev-01',
      endpoint_id: 'EP-1234567890ABCDEF',
      error_code: 'ERR_MASSIVE',
      error_category: 'OVERFLOW',
      sanitized_message: 'X'.repeat(MAX_EVENT_SIZE_BYTES + 1024)
    };

    const sanitized = filterAndSanitizeEvent(oversizedPayload);
    assert.strictEqual(sanitized, null, 'Oversized event > 64KB must be rejected');
    console.log('  [PASS] Test 5: Payload Size Limit Enforced (> 64KB Rejected)');
  }

  // Test 6: Telemetry Queue Persistence & Insertion
  {
    const validScan: any = {
      event_id: 'EVT-SCAN-100',
      event_type: 'SCAN_COMPLETED',
      schema_version: CURRENT_TELEMETRY_SCHEMA_VERSION,
      timestamp_utc: new Date().toISOString(),
      installation_id: installationId,
      organization_id: 'org-alpha',
      device_id: 'dev-01',
      endpoint_id: 'EP-1234567890ABCDEF',
      scan_id: 'SCAN-100',
      scan_type: 'FULL',
      duration_ms: 2500,
      machine_type: 'x64',
      OS: 'Linux',
      OS_version: '5.15.0',
      architecture: 'x64',
      application_version: '1.0.0',
      source_count: 1,
      file_count: 50,
      files_processed: 50,
      files_skipped: 0,
      files_failed: 0,
      findings_count: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      risk_score: 0,
      offline_mode: true
    };

    const res = queueRepo.enqueue(validScan);
    if (!res.success) {
      console.error('Enqueue error detail:', res.error);
    }
    assert.strictEqual(res.success, true, 'Enqueue must succeed');
    assert.strictEqual(res.event_id, 'EVT-SCAN-100');

    // Duplicate enqueue (Idempotency)
    const dupRes = queueRepo.enqueue(validScan);
    assert.strictEqual(dupRes.success, true, 'Duplicate enqueue must return idempotent success');

    const stats = queueRepo.getHealthStats();
    assert.strictEqual(stats.events_pending, 1, 'Queue must hold 1 pending event');
    console.log('  [PASS] Test 6: Telemetry Queue Persistence & Idempotency');
  }

  // Test 7: Batch Claim and Mark Sent
  {
    const claimed = queueRepo.claimBatch(10);
    assert.strictEqual(claimed.length, 1);
    assert.strictEqual(claimed[0].status, 'SENDING');

    queueRepo.markBatchSent([claimed[0].event_id]);
    const afterStats = queueRepo.getHealthStats();
    assert.strictEqual(afterStats.events_pending, 0);
    assert.strictEqual(afterStats.events_sent, 1);
    console.log('  [PASS] Test 7: Batch Claim (SENDING) and Resolution (SENT)');
  }

  // Test 8: Stuck SENDING State Recovery (> 5 min timeout)
  {
    // Insert a fake event stuck in SENDING
    const oldDate = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    db.prepare(`
      INSERT INTO telemetry_queue (
        id, event_id, event_type, schema_version, priority, payload_json,
        created_at, attempt_count, status, locked_at
      ) VALUES (?, ?, 'ERROR', 1, 'NORMAL', '{}', ?, 1, 'SENDING', ?)
    `).run('TQ-STUCK-01', 'EVT-STUCK-01', oldDate, oldDate);

    const recovered = queueRepo.recoverStuckSending(5);
    assert.strictEqual(recovered, 1, '1 stuck event must be recovered');

    const row = db.prepare('SELECT status, last_error FROM telemetry_queue WHERE event_id = ?').get('EVT-STUCK-01') as any;
    assert.strictEqual(row.status, 'PENDING', 'Stuck event must be reset to PENDING');
    console.log('  [PASS] Test 8: Stuck SENDING Recovery (Reset to PENDING)');
  }

  // Test 9: Deterministic Priority-Based Capacity Eviction (LOW -> NORMAL -> HIGH, never CRITICAL)
  {
    // Clear queue
    db.exec('DELETE FROM telemetry_queue;');

    // Fill small queue (capacity 10) with:
    // 4 LOW events
    // 4 NORMAL events
    // 2 CRITICAL events
    for (let i = 1; i <= 4; i++) {
      queueRepo.enqueue({
        event_id: `EVT-LOW-${i}`,
        event_type: 'APP_STARTED',
        schema_version: 1,
        timestamp_utc: new Date().toISOString(),
        installation_id: installationId,
        organization_id: 'org-alpha',
        device_id: 'dev-01',
        endpoint_id: 'EP-01',
        application_version: '1.0.0',
        OS: 'Windows',
        OS_version: '10',
        machine_type: 'x64',
        architecture: 'x64'
      }, 'LOW');
    }

    for (let i = 1; i <= 4; i++) {
      queueRepo.enqueue({
        event_id: `EVT-NORM-${i}`,
        event_type: 'REPORT_GENERATED',
        schema_version: 1,
        timestamp_utc: new Date().toISOString(),
        installation_id: installationId,
        organization_id: 'org-alpha',
        device_id: 'dev-01',
        endpoint_id: 'EP-01',
        report_id: `RPT-${i}`,
        scan_id: `SCN-${i}`,
        report_type: 'PDF',
        compliance_score: 88
      }, 'NORMAL');
    }

    for (let i = 1; i <= 2; i++) {
      queueRepo.enqueue({
        event_id: `EVT-CRIT-${i}`,
        event_type: 'LICENSE_EXPIRED',
        schema_version: 1,
        timestamp_utc: new Date().toISOString(),
        installation_id: installationId,
        organization_id: 'org-alpha',
        device_id: 'dev-01',
        endpoint_id: 'EP-01',
        license_id: `LIC-${i}`,
        plan: 'ENTERPRISE',
        status: 'EXPIRED',
        issued_at: new Date().toISOString(),
        expires_at: new Date().toISOString(),
        days_remaining: 0,
        device_count: 1,
        max_devices: 5
      }, 'CRITICAL');
    }

    // Queue is currently at exactly capacity = 10
    const countBefore = (db.prepare('SELECT COUNT(*) as cnt FROM telemetry_queue').get() as any).cnt;
    assert.strictEqual(countBefore, 10, 'Queue is at capacity (10)');

    // Now insert an 11th event -> triggers eviction of the oldest LOW priority event
    queueRepo.enqueue({
      event_id: 'EVT-NEW-HIGH',
      event_type: 'ERROR',
      schema_version: 1,
      timestamp_utc: new Date().toISOString(),
      installation_id: installationId,
      organization_id: 'org-alpha',
      device_id: 'dev-01',
      endpoint_id: 'EP-01',
      error_code: 'E01',
      error_category: 'SYS',
      sanitized_message: 'High error'
    }, 'HIGH');

    const countAfter = (db.prepare('SELECT COUNT(*) as cnt FROM telemetry_queue').get() as any).cnt;
    assert.strictEqual(countAfter, 10, 'Queue count stays bounded at capacity (10)');

    // Verify EVT-LOW-1 was evicted
    const low1 = db.prepare('SELECT id FROM telemetry_queue WHERE event_id = ?').get('EVT-LOW-1');
    assert.strictEqual(low1, undefined, 'Oldest LOW priority event was evicted');

    // Verify CRITICAL events are preserved
    const crit1 = db.prepare('SELECT id FROM telemetry_queue WHERE event_id = ?').get('EVT-CRIT-1');
    const crit2 = db.prepare('SELECT id FROM telemetry_queue WHERE event_id = ?').get('EVT-CRIT-2');
    assert.ok(crit1 && crit2, 'CRITICAL events are NEVER evicted');
    console.log('  [PASS] Test 9: Deterministic Priority Eviction (LOW evicted, CRITICAL preserved)');
  }

  // Test 10: Local Retention Purging of Old SENT Records
  {
    // Insert an old SENT record (40 days old)
    const fortyDaysAgo = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`
      INSERT INTO telemetry_queue (
        id, event_id, event_type, schema_version, priority, payload_json,
        created_at, status
      ) VALUES (?, ?, 'APP_STARTED', 1, 'LOW', '{}', ?, 'SENT')
    `).run('TQ-OLD-SENT', 'EVT-OLD-SENT', fortyDaysAgo);

    // Insert a recent SENT record (5 days old)
    const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`
      INSERT INTO telemetry_queue (
        id, event_id, event_type, schema_version, priority, payload_json,
        created_at, status
      ) VALUES (?, ?, 'APP_STARTED', 1, 'LOW', '{}', ?, 'SENT')
    `).run('TQ-RECENT-SENT', 'EVT-RECENT-SENT', fiveDaysAgo);

    const purged = queueRepo.purgeOldSent(30);
    assert.strictEqual(purged, 1, 'Only 1 old SENT record (>30 days) purged');

    const oldSent = db.prepare('SELECT id FROM telemetry_queue WHERE id = ?').get('TQ-OLD-SENT');
    const recentSent = db.prepare('SELECT id FROM telemetry_queue WHERE id = ?').get('TQ-RECENT-SENT');
    assert.strictEqual(oldSent, undefined, 'Old SENT record deleted');
    assert.ok(recentSent, 'Recent SENT record retained');
    console.log('  [PASS] Test 10: Local Retention Purging (SENT > 30 days)');
  }

  console.log('\n========================================================================');
  console.log('  ALL 10/10 PHASE T1 & T1.5 FOUNDATION TESTS PASSED (100% SUCCESS)     ');
  console.log('========================================================================\n');
}

runTelemetryFoundationTests().catch(err => {
  console.error('\n❌ Test failed:', err);
  process.exit(1);
});
