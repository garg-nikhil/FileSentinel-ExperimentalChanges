import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  DETECTION_CONFIDENCE_THRESHOLDS,
  classifyConfidence,
  classifyDetection,
  evaluateChecklistDetections,
  buildDetectionExplanation,
  findingToDetectionResult,
  buildAffectedFiles,
  mergeDetectionWithEvaluatorStatus,
  DetectionResult,
  DetectionResultStatus
} from '../backend/audit/detectionPolicy.js';
import { getDatabase } from '../backend/db.js';
import { EvidenceEngine } from '../backend/audit/evidenceEngine.js';
import { TelemetryService } from '../backend/telemetry.js';
import { AuditScoringEngine } from '../backend/audit/scoring.js';
import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { INITIAL_AUDIT_CHECKLIST, DETECTION_CHECKLIST_PARAMETERS } from '../backend/audit/checklist.js';

console.log('--- RUNNING DETECTION ENGINE + CHECKLIST SEMANTICS TEST SUITE (18 TESTS) ---');

let passedTests = 0;
async function test(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passedTests++;
  } catch (err: any) {
    console.error(`  ✕ FAIL: ${name}`);
    console.error(err);
    process.exit(1);
  }
}

async function runAll() {
  // ─── TEST 1: No PII detected → PASS ───────────────────────────────────
  await test('1. No PII detected → PASS', () => {
    const detections: DetectionResult[] = [];
    const status = evaluateChecklistDetections(detections);
    assert.strictEqual(status, 'PASS', 'Empty detections must evaluate to PASS');
  });

  // ─── TEST 2: Definitive PII detected (high confidence >= 0.85) → FAIL ──
  await test('2. Definitive PII detected (high confidence >= 0.85) → FAIL', () => {
    const highConfDetection: DetectionResult = {
      detected: true,
      classification: 'PII',
      confidence: 'HIGH',
      score: 0.95,
      rule_id: 'PII-003',
      matched_type: 'PAN-like Identifier',
      filename: 'user_pan.pdf',
      explanation: 'Format matching Permanent Account Number detected.',
      severity: 'HIGH'
    };
    const status = evaluateChecklistDetections([highConfDetection]);
    assert.strictEqual(status, 'FAIL', 'High confidence PII detection must evaluate to FAIL');
  });

  // ─── TEST 3: Low/medium confidence PII → REVIEW ───────────────────────
  await test('3. Low/medium confidence PII (< 0.85) → REVIEW', () => {
    const medConfDetection: DetectionResult = {
      detected: true,
      classification: 'PII',
      confidence: 'MEDIUM',
      score: 0.70,
      rule_id: 'PII-001',
      matched_type: 'Email Address',
      filename: 'support_email.txt',
      explanation: 'Heuristic email pattern detected.',
      severity: 'MEDIUM'
    };
    const status = evaluateChecklistDetections([medConfDetection]);
    assert.strictEqual(status, 'REVIEW', 'Medium confidence detection must evaluate to REVIEW');

    const lowConfDetection: DetectionResult = {
      detected: true,
      classification: 'PII',
      confidence: 'LOW',
      score: 0.40,
      rule_id: 'PII-002',
      matched_type: 'Phone Number',
      filename: 'notes.txt',
      explanation: 'Partial phone number matched.',
      severity: 'LOW'
    };
    const lowStatus = evaluateChecklistDetections([lowConfDetection]);
    assert.strictEqual(lowStatus, 'REVIEW', 'Low confidence detection must evaluate to REVIEW');
  });

  // ─── TEST 4: Multiple files, no detection → PASS ──────────────────────
  await test('4. Multiple files, no detection → PASS', () => {
    const files = ['clean1.pdf', 'clean2.docx', 'clean3.xlsx'];
    const allDetections: DetectionResult[] = []; // None detected in any file
    const status = evaluateChecklistDetections(allDetections);
    assert.strictEqual(status, 'PASS', 'Multiple clean files must evaluate to PASS');
  });

  // ─── TEST 5: Multiple files: review + no detection → REVIEW ───────────
  await test('5. Multiple files: review + no detection → REVIEW', () => {
    const detections: DetectionResult[] = [
      {
        detected: true,
        classification: 'PII',
        confidence: 'MEDIUM',
        score: 0.70,
        rule_id: 'PII-001',
        matched_type: 'Email Address',
        filename: 'file_with_review.txt',
        explanation: 'Possible email.',
        severity: 'MEDIUM'
      }
    ];
    const status = evaluateChecklistDetections(detections);
    assert.strictEqual(status, 'REVIEW', 'Mix of review and clean files must evaluate to REVIEW');
  });

  // ─── TEST 6: Multiple files: fail + review + pass → FAIL ───────────────
  await test('6. Multiple files: fail + review + pass → FAIL (Deterministic priority)', () => {
    const detections: DetectionResult[] = [
      {
        detected: true,
        classification: 'PII',
        confidence: 'HIGH',
        score: 0.95,
        rule_id: 'PII-007',
        matched_type: 'Credit Card Number',
        filename: 'card_data.csv',
        explanation: 'Credit card matched.',
        severity: 'CRITICAL'
      },
      {
        detected: true,
        classification: 'PII',
        confidence: 'MEDIUM',
        score: 0.70,
        rule_id: 'PII-001',
        matched_type: 'Email Address',
        filename: 'contact_info.txt',
        explanation: 'Email matched.',
        severity: 'MEDIUM'
      }
    ];
    const status = evaluateChecklistDetections(detections);
    assert.strictEqual(status, 'FAIL', 'Priority FAIL > REVIEW > PASS must result in FAIL');
  });

  // ─── TEST 7: Multiple definitive violating files (all retained) ────────
  await test('7. Multiple definitive violating files (all filenames retained)', () => {
    const detections: DetectionResult[] = [
      {
        detected: true,
        classification: 'PII',
        confidence: 'HIGH',
        score: 0.95,
        rule_id: 'PII-003',
        matched_type: 'PAN',
        filename: 'agency_pan1.pdf',
        explanation: 'PAN detected.',
        severity: 'HIGH'
      },
      {
        detected: true,
        classification: 'PII',
        confidence: 'HIGH',
        score: 0.95,
        rule_id: 'PII-004',
        matched_type: 'Aadhaar',
        filename: 'agency_aadhaar2.pdf',
        explanation: 'Aadhaar detected.',
        severity: 'HIGH'
      }
    ];
    const status = evaluateChecklistDetections(detections);
    assert.strictEqual(status, 'FAIL');
    const affected = buildAffectedFiles(detections);
    assert.strictEqual(affected.length, 2);
    const filenames = affected.map(a => a.filename);
    assert.ok(filenames.includes('agency_pan1.pdf'));
    assert.ok(filenames.includes('agency_aadhaar2.pdf'));
  });

  // ─── TEST 8: One file, multiple detections → Deterministic aggregation ─
  await test('8. One file, multiple detections → Deterministic aggregation', () => {
    const detections: DetectionResult[] = [
      {
        detected: true,
        classification: 'SECRETS',
        confidence: 'MEDIUM',
        score: 0.70,
        rule_id: 'SECRET-003',
        matched_type: 'JWT',
        filename: 'app_dump.log',
        explanation: 'Possible JWT.',
        severity: 'HIGH'
      },
      {
        detected: true,
        classification: 'SECRETS',
        confidence: 'HIGH',
        score: 0.95,
        rule_id: 'SECRET-001',
        matched_type: 'Password',
        filename: 'app_dump.log',
        explanation: 'Plaintext password detected.',
        severity: 'CRITICAL'
      }
    ];
    const status = evaluateChecklistDetections(detections);
    assert.strictEqual(status, 'FAIL', 'High confidence in same file must drive FAIL status');
  });

  // ─── TEST 9: Unreadable file ≠ PASS ────────────────────────────────────
  await test('9. Unreadable file ≠ PASS (error / not found status preserved)', () => {
    const notFoundMerged = mergeDetectionWithEvaluatorStatus('EVIDENCE_NOT_FOUND', 'PASS');
    assert.strictEqual(notFoundMerged, 'EVIDENCE_NOT_FOUND', 'EVIDENCE_NOT_FOUND must never turn into PASS');

    const naMerged = mergeDetectionWithEvaluatorStatus('NOT_APPLICABLE', 'PASS');
    assert.strictEqual(naMerged, 'NOT_APPLICABLE', 'NOT_APPLICABLE must never turn into PASS');
  });

  // ─── TEST 10: Technical scanner failure → error/review semantics ───────
  await test('10. Technical scanner failure → error/review semantics preserved', () => {
    const evalResult = mergeDetectionWithEvaluatorStatus('REVIEW', 'PASS');
    assert.strictEqual(evalResult, 'REVIEW', 'Evaluator REVIEW must not be downgraded by detection PASS');
  });

  // ─── TEST 11: FAIL result contains explanation ────────────────────────
  await test('11. FAIL result contains explanation and affected files detail', () => {
    const detections: DetectionResult[] = [
      {
        detected: true,
        classification: 'PII',
        confidence: 'HIGH',
        score: 0.95,
        rule_id: 'PII-003',
        matched_type: 'PAN',
        filename: 'violating_doc.pdf',
        explanation: 'PAN found.',
        severity: 'HIGH'
      }
    ];
    const affected = buildAffectedFiles(detections);
    const explanation = buildDetectionExplanation('FAIL', affected);
    assert.ok(explanation.length > 0, 'Explanation must not be empty');
    assert.ok(explanation.includes('Potential sensitive data was detected with high confidence'));
    assert.ok(explanation.includes('violating_doc.pdf') || explanation.includes('1 file(s)'));
  });

  // ─── TEST 12: REVIEW result contains explanation ──────────────────────
  await test('12. REVIEW result contains explanation and reason for uncertainty', () => {
    const detections: DetectionResult[] = [
      {
        detected: true,
        classification: 'PII',
        confidence: 'MEDIUM',
        score: 0.70,
        rule_id: 'PII-001',
        matched_type: 'Email',
        filename: 'ambiguous_memo.txt',
        explanation: 'Email matched.',
        severity: 'MEDIUM'
      }
    ];
    const affected = buildAffectedFiles(detections);
    const explanation = buildDetectionExplanation('REVIEW', affected);
    assert.ok(explanation.length > 0);
    assert.ok(explanation.includes('insufficient to classify it definitively'));
    assert.ok(explanation.includes('Manual review is recommended'));
  });

  // ─── TEST 13: PASS result indicates no matching detection ─────────────
  await test('13. PASS result indicates no matching detection', () => {
    const explanation = buildDetectionExplanation('PASS', []);
    assert.strictEqual(
      explanation,
      'No matching PII or sensitive data was detected in the scanned files.'
    );
  });

  // ─── TEST 14: Sensitive raw PII not in telemetry ──────────────────────
  await test('14. Sensitive raw PII not in telemetry payload', () => {
    const db = getDatabase();

    const scanId = `SCAN-PII-TEST-${Date.now()}`;
    db.prepare(`
      INSERT INTO scans (scan_id, org_id, root_path, start_time, end_time, status, total_files, processed_files, error_count, critical_count, high_count, medium_count, low_count, safe_count)
      VALUES (?, 'ORG-TEST', 'C:/test', datetime('now'), datetime('now'), 'COMPLETED', 1, 1, 0, 1, 0, 0, 0, 0)
    `).run(scanId);

    const fileId = `FILE-${Date.now()}`;
    db.prepare(`
      INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, risk_score, classification, scan_status)
      VALUES (?, ?, 'C:/test/raw_pan.pdf', 'raw_pan.pdf', '.pdf', 1024, 'abc123hash', 85, 'RESTRICTED', 'SUCCESS')
    `).run(fileId, scanId);

    db.prepare(`
      INSERT INTO findings (finding_id, file_id, rule_id, severity, category, title, description, evidence_json, confidence, source, created_at)
      VALUES (?, ?, 'PII-003', 'HIGH', 'PII', 'PAN Found', 'PAN ABCDE1234F was detected in plaintext', '{"snippet":"ABCDE1234F"}', 0.95, 'RULE', datetime('now'))
    `).run(`FND-${Date.now()}`, fileId);

    const telemetryService = new TelemetryService(db);
    const payload = telemetryService.buildTelemetryPayload(
      scanId,
      'ORG-TEST',
      'USER-TEST',
      'DEV-TEST',
      { debugFilenamesEnabled: false }
    );

    assert.ok(payload !== null, 'Telemetry payload should be created');
    const payloadStr = JSON.stringify(payload);
    assert.ok(!payloadStr.includes('ABCDE1234F'), 'Raw PII must NEVER appear in telemetry payload');
    assert.ok(!payloadStr.includes('raw_pan.pdf'), 'Raw file paths must NOT appear when debug filenames opt-in is false');
  });

  // ─── TEST 15: debug_filenames_opt_in privacy intact ───────────────────
  await test('15. debug_filenames_opt_in privacy intact (hashed file identifiers)', () => {
    const db = getDatabase();

    const scanId = `SCAN-OPTIN-TEST-${Date.now()}`;
    db.prepare(`
      INSERT INTO scans (scan_id, org_id, root_path, start_time, end_time, status, total_files, processed_files, error_count, critical_count, high_count, medium_count, low_count, safe_count)
      VALUES (?, 'ORG-TEST', 'C:/sensitive_docs', datetime('now'), datetime('now'), 'COMPLETED', 1, 1, 0, 0, 0, 0, 0, 1)
    `).run(scanId);

    const fileId = `FILE-OPT-${Date.now()}`;
    db.prepare(`
      INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, risk_score, classification, scan_status)
      VALUES (?, ?, 'C:/sensitive_docs/SecretPayroll.xlsx', 'SecretPayroll.xlsx', '.xlsx', 2048, 'hashxyz', 10, 'CONFIDENTIAL', 'SUCCESS')
    `).run(fileId, scanId);

    const telemetryService = new TelemetryService(db);
    const payload = telemetryService.buildTelemetryPayload(
      scanId,
      'ORG-TEST',
      'USER-TEST',
      'DEV-TEST',
      { debugFilenamesEnabled: true }
    );

    assert.ok(payload !== null);
    assert.strictEqual(payload.debug_filenames_opt_in, true);
    assert.ok(payload.debug_filenames && payload.debug_filenames.length > 0);
    assert.ok(!payload.debug_filenames[0].includes('SecretPayroll'), 'Raw filename must be masked/hashed even with opt-in');
    assert.ok(payload.debug_filenames[0].startsWith('file_'), 'Hashed filename should start with file_ prefix');
  });

  // ─── TEST 16: Scan-level counts reflect corrected states ───────────────
  await test('16. Scan-level counts reflect corrected states via EvidenceEngine integration', async () => {
    const db = getDatabase();
    const evidenceEngine = new EvidenceEngine(db);

    const scanId = `SCAN-AUDIT-INTEG-${Date.now()}`;
    db.prepare(`
      INSERT INTO scans (scan_id, org_id, root_path, start_time, end_time, status, total_files, processed_files, error_count, critical_count, high_count, medium_count, low_count, safe_count)
      VALUES (?, 'ORG-TEST', 'C:/agency_data', datetime('now'), datetime('now'), 'COMPLETED', 1, 1, 0, 1, 0, 0, 0, 0)
    `).run(scanId);

    const fileId = `FILE-PAN-${Date.now()}`;
    db.prepare(`
      INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, risk_score, classification, scan_status)
      VALUES (?, ?, 'C:/agency_data/pan_leak.txt', 'pan_leak.txt', '.txt', 500, 'sha256pan', 90, 'RESTRICTED', 'SUCCESS')
    `).run(fileId, scanId);

    db.prepare(`
      INSERT INTO findings (finding_id, file_id, rule_id, severity, category, title, description, evidence_json, confidence, source, created_at)
      VALUES (?, ?, 'PII-003', 'HIGH', 'PII', 'PAN Found', 'PAN detected in agency files', '{"snippet":"ABCDE1234F"}', 0.95, 'RULE', datetime('now'))
    `).run(`FND-${Date.now()}`, fileId);

    // Run audit scan for session
    const session = await evidenceEngine.runAuditScanForSession({
      scanId,
      orgId: 'ORG-TEST',
      agencyName: 'Test Agency',
      auditorName: 'Test Auditor',
      customChecklist: [...INITIAL_AUDIT_CHECKLIST, ...DETECTION_CHECKLIST_PARAMETERS]
    });

    assert.ok(session !== null, 'Audit session must be generated');
    const det001Result = session.parameter_results.find(p => p.parameter_id === 'DET-001');
    assert.ok(det001Result, 'DET-001 parameter must be present');
    assert.strictEqual(det001Result.status, 'FAIL', 'DET-001 must FAIL because high-confidence PII finding exists');
    assert.ok(det001Result.detection_results, 'detection_results must be attached');
    assert.strictEqual(det001Result.detection_results.status, 'FAIL');
    assert.ok(det001Result.detection_results.affected_files.length > 0);
  });

  // ─── TEST 17: Existing compliance calculations don't regress ──────────
  await test('17. Existing compliance calculations and score formulas remain intact', () => {
    const dummyResults = INITIAL_AUDIT_CHECKLIST.slice(0, 5).map(p => ({
      parameter_id: p.id,
      parameter: p,
      fatal: p.fatal,
      status: 'PASS' as const,
      score_earned: p.category_weight,
      max_score: p.category_weight,
      confidence: 1.0,
      reason: 'All requirements verified',
      evidence: [],
      missing_requirements: [],
      warnings: []
    }));

    const summary = AuditScoringEngine.calculateAuditSummary(
      'AUDIT-TEST-17',
      'Test Agency',
      'Test Auditor',
      '2026-08-22',
      dummyResults
    );

    assert.strictEqual(summary.pass_count, 5);
    assert.strictEqual(summary.fail_count, 0);
    assert.strictEqual(summary.overall_status, 'COMPLIANT');
    assert.ok(summary.overall_score > 0);
  });

  // ─── TEST 18: Centralized thresholds integrity ────────────────────────
  await test('18. Centralized thresholds integrity (single source of truth)', () => {
    assert.strictEqual(DETECTION_CONFIDENCE_THRESHOLDS.FAIL, 0.85);
    assert.strictEqual(DETECTION_CONFIDENCE_THRESHOLDS.REVIEW, 0.0);
    assert.strictEqual(classifyConfidence(0.95), 'HIGH');
    assert.strictEqual(classifyConfidence(0.85), 'HIGH');
    assert.strictEqual(classifyConfidence(0.70), 'MEDIUM');
    assert.strictEqual(classifyConfidence(0.40), 'LOW');
  });

  console.log(`\nAll ${passedTests} / 18 tests PASSED successfully! 🎉`);
}

runAll().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
