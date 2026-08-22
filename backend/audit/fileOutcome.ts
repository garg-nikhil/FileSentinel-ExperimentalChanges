/**
 * File Outcome Policy & Aggregation Engine
 *
 * Provides authoritative, single-source-of-truth file-level compliance outcome evaluation:
 *   - PASS: File successfully processed with 0 sensitive findings/violations.
 *   - FAIL: File has at least 1 definitive sensitive finding / high-confidence violation.
 *   - REVIEW: File successfully processed with ambiguous / medium-confidence findings.
 *   - ERROR: File could not be read or extracted.
 *   - SKIPPED: File was excluded/skipped (e.g., exceeded size limit).
 *
 * Deterministic Precedence:
 *   FAIL > REVIEW > PASS
 */

import { DETECTION_CONFIDENCE_THRESHOLDS } from './detectionPolicy.js';

export type FileOutcomeStatus = 'PASS' | 'FAIL' | 'REVIEW' | 'ERROR' | 'SKIPPED' | 'PROCESSING';

export interface FileOutcomeDetail {
  file_id: string;
  filename: string;
  path: string;
  outcome: FileOutcomeStatus;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  confidence_score: number;
  reason: string;
  violating_rules: string[];
  review_rules: string[];
  findings_count: number;
  scan_status: string;
  findings?: any[];
}

export interface FileOutcomeSummary {
  /** Total evaluated files (passed + failed + review) */
  total_scanned: number;
  /** Files evaluated clean with no violations */
  passed: number;
  /** Files evaluated with definitive violations */
  failed: number;
  /** Files evaluated requiring human review / ambiguous detections */
  review: number;
  /** Files skipped during scanning (e.g. oversize, unsupported) */
  skipped: number;
  /** Files that failed processing/extraction */
  errors: number;
  /** Total files discovered in scan session */
  total_discovered: number;
  /** Percentage of evaluated files that passed (0.0 to 100.0) */
  passed_pct: number;
  /** Percentage of evaluated files that failed (0.0 to 100.0) */
  failed_pct: number;
  /** Percentage of evaluated files requiring review (0.0 to 100.0) */
  review_pct: number;
}

export interface FileInputItem {
  file_id: string;
  filename?: string;
  path?: string;
  scan_status?: string;
  findings?: Array<{
    finding_id?: string;
    rule_id?: string;
    severity?: string;
    category?: string;
    title?: string;
    description?: string;
    confidence?: number;
    evidence?: any;
    evidence_json?: string;
  }>;
  warnings?: string[];
  metadata?: Record<string, any>;
}

/**
 * Evaluate a single file's outcome based on its scan status and associated findings.
 */
export function evaluateFileOutcome(file: FileInputItem): FileOutcomeDetail {
  const filename = file.filename || (file.path ? file.path.split(/[/\\]/).pop() || 'unknown' : 'unknown');
  const filePath = file.path || filename;
  const scanStatus = (file.scan_status || 'SUCCESS').toUpperCase();
  const findings = file.findings || [];

  // 1. Check for skipped file status
  if (scanStatus === 'SKIPPED') {
    return {
      file_id: file.file_id,
      filename,
      path: filePath,
      outcome: 'SKIPPED',
      confidence: 'HIGH',
      confidence_score: 1.0,
      reason: 'File skipped (e.g. exceeded maximum scan size limit)',
      violating_rules: [],
      review_rules: [],
      findings_count: 0,
      scan_status: scanStatus,
      findings: []
    };
  }

  // 2. Check for error / unreadable file status
  if (scanStatus === 'ERROR') {
    const errorWarning = (file.warnings && file.warnings.length > 0)
      ? file.warnings.join('; ')
      : 'File processing/extraction error encountered';
    return {
      file_id: file.file_id,
      filename,
      path: filePath,
      outcome: 'ERROR',
      confidence: 'HIGH',
      confidence_score: 1.0,
      reason: errorWarning,
      violating_rules: [],
      review_rules: [],
      findings_count: 0,
      scan_status: scanStatus,
      findings: []
    };
  }

  // 3. Check for in-progress processing status
  if (scanStatus === 'PENDING' || scanStatus === 'PROCESSING') {
    return {
      file_id: file.file_id,
      filename,
      path: filePath,
      outcome: 'PROCESSING',
      confidence: 'LOW',
      confidence_score: 0.0,
      reason: 'File is currently being evaluated',
      violating_rules: [],
      review_rules: [],
      findings_count: 0,
      scan_status: scanStatus,
      findings: []
    };
  }

  // 4. Evaluated file (SUCCESS status) — inspect findings
  if (findings.length === 0) {
    return {
      file_id: file.file_id,
      filename,
      path: filePath,
      outcome: 'PASS',
      confidence: 'HIGH',
      confidence_score: 1.0,
      reason: 'Clean — No sensitive data or checklist violations detected',
      violating_rules: [],
      review_rules: [],
      findings_count: 0,
      scan_status: scanStatus,
      findings: []
    };
  }

  // Aggregate findings by confidence and severity
  const failingFindings: typeof findings = [];
  const reviewFindings: typeof findings = [];

  for (const f of findings) {
    const conf = typeof f.confidence === 'number' ? f.confidence : 1.0;
    const isHighConfidence = conf >= DETECTION_CONFIDENCE_THRESHOLDS.FAIL;
    const isCriticalOrHigh = f.severity === 'CRITICAL' || f.severity === 'HIGH';

    if (isHighConfidence || isCriticalOrHigh) {
      failingFindings.push(f);
    } else {
      reviewFindings.push(f);
    }
  }

  // Precedence: FAIL > REVIEW > PASS
  if (failingFindings.length > 0) {
    const ruleIds = Array.from(new Set(failingFindings.map(f => f.rule_id || f.title || 'UNKNOWN_RULE')));
    const titles = Array.from(new Set(failingFindings.map(f => f.title || f.category || 'Sensitive Data'))).join(', ');
    const maxConf = Math.max(...failingFindings.map(f => typeof f.confidence === 'number' ? f.confidence : 1.0));

    return {
      file_id: file.file_id,
      filename,
      path: filePath,
      outcome: 'FAIL',
      confidence: 'HIGH',
      confidence_score: maxConf,
      reason: `Definitive violation detected: ${titles} (${failingFindings.length} issue${failingFindings.length > 1 ? 's' : ''})`,
      violating_rules: ruleIds,
      review_rules: Array.from(new Set(reviewFindings.map(f => f.rule_id || f.title || 'UNKNOWN_RULE'))),
      findings_count: findings.length,
      scan_status: scanStatus,
      findings
    };
  }

  if (reviewFindings.length > 0) {
    const ruleIds = Array.from(new Set(reviewFindings.map(f => f.rule_id || f.title || 'UNKNOWN_RULE')));
    const titles = Array.from(new Set(reviewFindings.map(f => f.title || f.category || 'Potential Finding'))).join(', ');
    const maxConf = Math.max(...reviewFindings.map(f => typeof f.confidence === 'number' ? f.confidence : 0.7));

    return {
      file_id: file.file_id,
      filename,
      path: filePath,
      outcome: 'REVIEW',
      confidence: maxConf >= 0.50 ? 'MEDIUM' : 'LOW',
      confidence_score: maxConf,
      reason: `Uncertain detection requiring review: ${titles} (${reviewFindings.length} potential issue${reviewFindings.length > 1 ? 's' : ''})`,
      violating_rules: [],
      review_rules: ruleIds,
      findings_count: findings.length,
      scan_status: scanStatus,
      findings
    };
  }

  return {
    file_id: file.file_id,
    filename,
    path: filePath,
    outcome: 'PASS',
    confidence: 'HIGH',
    confidence_score: 1.0,
    reason: 'Clean — No sensitive data or checklist violations detected',
    violating_rules: [],
    review_rules: [],
    findings_count: 0,
    scan_status: scanStatus,
    findings: []
  };
}

/**
 * Aggregate outcomes for a collection of files into a comprehensive summary.
 */
export function aggregateFileOutcomes(files: FileInputItem[]): {
  summary: FileOutcomeSummary;
  details: FileOutcomeDetail[];
} {
  let passed = 0;
  let failed = 0;
  let review = 0;
  let skipped = 0;
  let errors = 0;
  let processing = 0;

  const details: FileOutcomeDetail[] = [];

  for (const file of files) {
    const detail = evaluateFileOutcome(file);
    details.push(detail);

    switch (detail.outcome) {
      case 'PASS':
        passed++;
        break;
      case 'FAIL':
        failed++;
        break;
      case 'REVIEW':
        review++;
        break;
      case 'SKIPPED':
        skipped++;
        break;
      case 'ERROR':
        errors++;
        break;
      case 'PROCESSING':
        processing++;
        break;
    }
  }

  const totalScanned = passed + failed + review;
  const totalDiscovered = totalScanned + skipped + errors + processing;

  // Calculate percentages based on evaluated files
  const passedPct = totalScanned > 0 ? Number(((passed / totalScanned) * 100).toFixed(1)) : 0;
  const failedPct = totalScanned > 0 ? Number(((failed / totalScanned) * 100).toFixed(1)) : 0;
  const reviewPct = totalScanned > 0 ? Number(((review / totalScanned) * 100).toFixed(1)) : 0;

  const summary: FileOutcomeSummary = {
    total_scanned: totalScanned,
    passed,
    failed,
    review,
    skipped,
    errors,
    total_discovered: totalDiscovered,
    passed_pct: passedPct,
    failed_pct: failedPct,
    review_pct: reviewPct
  };

  return { summary, details };
}
