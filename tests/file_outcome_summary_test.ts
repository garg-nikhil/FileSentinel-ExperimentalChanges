import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateFileOutcome, aggregateFileOutcomes } from '../backend/audit/fileOutcome.js';

test('FILE OUTCOME: Clean file with 0 findings evaluates to PASS', () => {
  const result = evaluateFileOutcome({
    file_id: 'file-1',
    filename: 'clean_notes.txt',
    path: '/data/clean_notes.txt',
    scan_status: 'SUCCESS',
    findings: []
  });

  assert.equal(result.outcome, 'PASS');
  assert.equal(result.confidence, 'HIGH');
  assert.equal(result.findings_count, 0);
  assert.equal(result.violating_rules.length, 0);
  assert.equal(result.review_rules.length, 0);
  assert.match(result.reason, /Clean/i);
});

test('FILE OUTCOME: Definitive high-confidence finding evaluates to FAIL', () => {
  const result = evaluateFileOutcome({
    file_id: 'file-2',
    filename: 'customer_pan_cards.xlsx',
    path: '/data/customer_pan_cards.xlsx',
    scan_status: 'SUCCESS',
    findings: [
      {
        finding_id: 'find-1',
        rule_id: 'RULE-PAN-001',
        severity: 'CRITICAL',
        confidence: 0.98,
        evidence: { snippet: 'ABCDE1234F' }
      }
    ]
  });

  assert.equal(result.outcome, 'FAIL');
  assert.equal(result.confidence, 'HIGH');
  assert.equal(result.findings_count, 1);
  assert.deepEqual(result.violating_rules, ['RULE-PAN-001']);
  assert.equal(result.review_rules.length, 0);
  assert.match(result.reason, /Definitive violation/i);
});

test('FILE OUTCOME: Uncertain detection (< 0.85 confidence) evaluates to REVIEW', () => {
  const result = evaluateFileOutcome({
    file_id: 'file-3',
    filename: 'agent_logs.log',
    path: '/data/agent_logs.log',
    scan_status: 'SUCCESS',
    findings: [
      {
        finding_id: 'find-2',
        rule_id: 'RULE-POTENTIAL-KEY',
        severity: 'MEDIUM',
        confidence: 0.65,
        evidence: { snippet: 'possible token prefix' }
      }
    ]
  });

  assert.equal(result.outcome, 'REVIEW');
  assert.equal(result.confidence, 'MEDIUM');
  assert.equal(result.findings_count, 1);
  assert.equal(result.violating_rules.length, 0);
  assert.deepEqual(result.review_rules, ['RULE-POTENTIAL-KEY']);
  assert.match(result.reason, /Uncertain detection|Review/i);
});

test('FILE OUTCOME: Priority precedence FAIL > REVIEW > PASS when file has both', () => {
  const result = evaluateFileOutcome({
    file_id: 'file-4',
    filename: 'mixed_leak.csv',
    path: '/data/mixed_leak.csv',
    scan_status: 'SUCCESS',
    findings: [
      {
        finding_id: 'find-3',
        rule_id: 'RULE-POTENTIAL-KEY',
        severity: 'MEDIUM',
        confidence: 0.60
      },
      {
        finding_id: 'find-4',
        rule_id: 'RULE-AADHAAR-001',
        severity: 'CRITICAL',
        confidence: 0.95
      }
    ]
  });

  assert.equal(result.outcome, 'FAIL');
  assert.equal(result.confidence, 'HIGH');
  assert.ok(result.violating_rules.includes('RULE-AADHAAR-001'));
  assert.ok(result.review_rules.includes('RULE-POTENTIAL-KEY'));
});

test('FILE OUTCOME: scan_status ERROR evaluates to ERROR', () => {
  const result = evaluateFileOutcome({
    file_id: 'file-5',
    filename: 'corrupted.zip',
    path: '/data/corrupted.zip',
    scan_status: 'ERROR',
    warnings: ['Read timeout or corrupted header']
  });

  assert.equal(result.outcome, 'ERROR');
  assert.match(result.reason, /Corrupted|Read timeout|Error|Unreadable/i);
});

test('FILE OUTCOME: scan_status SKIPPED evaluates to SKIPPED', () => {
  const result = evaluateFileOutcome({
    file_id: 'file-6',
    filename: 'massive_video.mp4',
    path: '/data/massive_video.mp4',
    scan_status: 'SKIPPED',
    warnings: ['Exceeds maximum size threshold (500MB)']
  });

  assert.equal(result.outcome, 'SKIPPED');
  assert.match(result.reason, /Skipped/i);
});

test('FILE OUTCOME AGGREGATION: Mixed dataset calculates exact file counts & percentages', () => {
  const files = [
    // 5 clean files
    { file_id: 'f1', filename: 'clean1.txt', path: '/clean1.txt', scan_status: 'SUCCESS', findings: [] },
    { file_id: 'f2', filename: 'clean2.txt', path: '/clean2.txt', scan_status: 'SUCCESS', findings: [] },
    { file_id: 'f3', filename: 'clean3.txt', path: '/clean3.txt', scan_status: 'SUCCESS', findings: [] },
    { file_id: 'f4', filename: 'clean4.txt', path: '/clean4.txt', scan_status: 'SUCCESS', findings: [] },
    { file_id: 'f5', filename: 'clean5.txt', path: '/clean5.txt', scan_status: 'SUCCESS', findings: [] },
    // 2 failed files
    { file_id: 'f6', filename: 'fail1.csv', path: '/fail1.csv', scan_status: 'SUCCESS', findings: [{ rule_id: 'R1', severity: 'HIGH', confidence: 0.9 }] },
    { file_id: 'f7', filename: 'fail2.csv', path: '/fail2.csv', scan_status: 'SUCCESS', findings: [{ rule_id: 'R2', severity: 'CRITICAL', confidence: 0.99 }] },
    // 1 review file
    { file_id: 'f8', filename: 'rev1.log', path: '/rev1.log', scan_status: 'SUCCESS', findings: [{ rule_id: 'R3', severity: 'LOW', confidence: 0.5 }] },
    // 1 skipped file
    { file_id: 'f9', filename: 'big.iso', path: '/big.iso', scan_status: 'SKIPPED' },
    // 1 error file
    { file_id: 'f10', filename: 'broken.db', path: '/broken.db', scan_status: 'ERROR' }
  ];

  const { summary, details } = aggregateFileOutcomes(files);

  assert.equal(details.length, 10);
  assert.equal(summary.total_discovered, 10);
  assert.equal(summary.total_scanned, 8); // 5 pass + 2 fail + 1 review
  assert.equal(summary.passed, 5);
  assert.equal(summary.failed, 2);
  assert.equal(summary.review, 1);
  assert.equal(summary.skipped, 1);
  assert.equal(summary.errors, 1);

  // Invariant verification: total_discovered = passed + failed + review + skipped + errors
  assert.equal(summary.total_discovered, summary.passed + summary.failed + summary.review + summary.skipped + summary.errors);

  // Percentage calculations on evaluated files (8 total):
  // 5 / 8 = 62.5%
  // 2 / 8 = 25.0%
  // 1 / 8 = 12.5%
  assert.equal(summary.passed_pct, 62.5);
  assert.equal(summary.failed_pct, 25);
  assert.equal(summary.review_pct, 12.5);
  assert.equal(summary.passed_pct + summary.failed_pct + summary.review_pct, 100);
});

test('FILE OUTCOME AGGREGATION: 0 files dataset returns 0 counts and 0 percentages without NaN', () => {
  const { summary, details } = aggregateFileOutcomes([]);

  assert.equal(details.length, 0);
  assert.equal(summary.total_discovered, 0);
  assert.equal(summary.total_scanned, 0);
  assert.equal(summary.passed, 0);
  assert.equal(summary.failed, 0);
  assert.equal(summary.review, 0);
  assert.equal(summary.skipped, 0);
  assert.equal(summary.errors, 0);
  assert.equal(summary.passed_pct, 0);
  assert.equal(summary.failed_pct, 0);
  assert.equal(summary.review_pct, 0);
  assert.ok(!Number.isNaN(summary.passed_pct));
});

test('FILE OUTCOME AGGREGATION: 100% clean files returns 100% passed and 0% fail/review', () => {
  const files = [
    { file_id: 'c1', filename: 'a.txt', path: '/a.txt', scan_status: 'SUCCESS', findings: [] },
    { file_id: 'c2', filename: 'b.txt', path: '/b.txt', scan_status: 'SUCCESS', findings: [] }
  ];

  const { summary } = aggregateFileOutcomes(files);

  assert.equal(summary.total_scanned, 2);
  assert.equal(summary.passed, 2);
  assert.equal(summary.failed, 0);
  assert.equal(summary.review, 0);
  assert.equal(summary.passed_pct, 100);
  assert.equal(summary.failed_pct, 0);
  assert.equal(summary.review_pct, 0);
});

test('FILE OUTCOME AGGREGATION: 100% failed files returns 100% failed and 0% passed/review', () => {
  const files = [
    { file_id: 'f1', filename: 'bad1.txt', path: '/bad1.txt', scan_status: 'SUCCESS', findings: [{ rule_id: 'R1', severity: 'CRITICAL', confidence: 0.95 }] },
    { file_id: 'f2', filename: 'bad2.txt', path: '/bad2.txt', scan_status: 'SUCCESS', findings: [{ rule_id: 'R2', severity: 'HIGH', confidence: 0.88 }] }
  ];

  const { summary } = aggregateFileOutcomes(files);

  assert.equal(summary.total_scanned, 2);
  assert.equal(summary.passed, 0);
  assert.equal(summary.failed, 2);
  assert.equal(summary.review, 0);
  assert.equal(summary.passed_pct, 0);
  assert.equal(summary.failed_pct, 100);
  assert.equal(summary.review_pct, 0);
});

test('FILE OUTCOME AGGREGATION: Distinction between checklist parameters and file-level outcomes', () => {
  // Scenario: 1 file contains 5 violations across multiple rules
  const files = [
    {
      file_id: 'single-file',
      filename: 'multi_violation.xlsx',
      path: '/multi_violation.xlsx',
      scan_status: 'SUCCESS',
      findings: [
        { rule_id: 'RULE-1', severity: 'CRITICAL', confidence: 0.9 },
        { rule_id: 'RULE-2', severity: 'HIGH', confidence: 0.9 },
        { rule_id: 'RULE-3', severity: 'CRITICAL', confidence: 0.9 },
        { rule_id: 'RULE-4', severity: 'HIGH', confidence: 0.9 },
        { rule_id: 'RULE-5', severity: 'MEDIUM', confidence: 0.9 }
      ]
    }
  ];

  const { summary, details } = aggregateFileOutcomes(files);

  // The file count must be 1 (NOT 5)
  assert.equal(summary.total_scanned, 1);
  assert.equal(summary.failed, 1);
  assert.equal(summary.passed, 0);
  assert.equal(details.length, 1);
  assert.equal(details[0].violating_rules.length, 5);
  assert.equal(summary.failed_pct, 100);
});
