/**
 * Detection Policy — Centralized confidence thresholds and detection-to-checklist evaluation.
 *
 * This module bridges scanner-level Finding[] results into checklist parameter
 * evaluation semantics (PASS / FAIL / REVIEW).
 *
 * IMPORTANT: Confidence thresholds are defined here and nowhere else.
 * Do NOT scatter magic numbers throughout the scanner or evaluator.
 */

// ─── Confidence Thresholds ────────────────────────────────────────────
// These thresholds determine how scanner detection confidence maps to
// checklist parameter status.
//
// Existing scanner confidence values:
//   0.95  — Regex rule match (high certainty)
//   0.90  — Structural document warning
//   0.70  — Heuristic / fallback keyword match
//
// Decision policy:
//   HIGH  confidence (≥ 0.85) + positive detection → FAIL
//   MEDIUM confidence (≥ 0.50, < 0.85)            → REVIEW
//   LOW   confidence (< 0.50)                      → REVIEW (any detection is noteworthy)
//   No detection                                   → PASS

export const DETECTION_CONFIDENCE_THRESHOLDS = {
  /** Minimum confidence for a definitive FAIL classification */
  FAIL: 0.85,
  /** Minimum confidence for a REVIEW classification (below FAIL threshold) */
  REVIEW: 0.0  // Any detection at all warrants at minimum a REVIEW
} as const;

// ─── Types ────────────────────────────────────────────────────────────

export type DetectionConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export type DetectionResultStatus = 'PASS' | 'FAIL' | 'REVIEW';

/**
 * Represents a single detection result from the scanner's Finding engine,
 * normalized for consumption by the checklist evaluation pipeline.
 */
export interface DetectionResult {
  /** Whether a prohibited/sensitive condition was detected */
  detected: boolean;
  /** Detection category (mirrors Finding.category) */
  classification: string;
  /** Human-readable confidence level */
  confidence: DetectionConfidenceLevel;
  /** Raw confidence score 0.0 - 1.0 (from Finding.confidence) */
  score: number;
  /** Scanner rule that triggered this detection */
  rule_id: string;
  /** Specific type matched, e.g. 'EMAIL', 'PASSWORD', 'PAN' */
  matched_type: string;
  /** Filename where detection occurred */
  filename: string;
  /** Human-readable explanation of what was detected */
  explanation: string;
  /** Redacted evidence snippet (safe for display, never raw PII) */
  evidence_summary?: string;
  /** Severity level from the triggering rule */
  severity: string;
}

/**
 * Detail about a single affected file within a checklist detection evaluation.
 */
export interface AffectedFileDetail {
  filename: string;
  detection_type: string;
  confidence: DetectionConfidenceLevel;
  reason: string;
  rule_id: string;
  severity: string;
  evidence_summary?: string;
}

/**
 * The detection-aware evaluation result for a single checklist parameter.
 * Attached to AuditParameterResult.detection_results when detection evidence exists.
 */
export interface ChecklistDetectionEvaluation {
  parameter_id: string;
  parameter_name: string;
  status: DetectionResultStatus;
  affected_files: AffectedFileDetail[];
  explanation: string;
}

// ─── Core Functions ───────────────────────────────────────────────────

/**
 * Classify a raw confidence score into HIGH / MEDIUM / LOW.
 */
export function classifyConfidence(score: number): DetectionConfidenceLevel {
  if (score >= DETECTION_CONFIDENCE_THRESHOLDS.FAIL) return 'HIGH';
  if (score >= 0.50) return 'MEDIUM';
  return 'LOW';
}

/**
 * Determine whether a single detection should be classified as FAIL or REVIEW.
 */
export function classifyDetection(detection: DetectionResult): DetectionResultStatus {
  if (!detection.detected) return 'PASS';
  if (detection.score >= DETECTION_CONFIDENCE_THRESHOLDS.FAIL) return 'FAIL';
  return 'REVIEW';
}

/**
 * Evaluate a set of detections for a single checklist parameter using
 * deterministic aggregation:
 *
 *   NO detections           → PASS
 *   ONLY REVIEW detections  → REVIEW
 *   ≥1 FAIL detection       → FAIL
 *
 * Priority: FAIL > REVIEW > PASS
 */
export function evaluateChecklistDetections(detections: DetectionResult[]): DetectionResultStatus {
  if (detections.length === 0) return 'PASS';

  let hasFail = false;
  let hasReview = false;

  for (const d of detections) {
    if (!d.detected) continue;
    const status = classifyDetection(d);
    if (status === 'FAIL') hasFail = true;
    else if (status === 'REVIEW') hasReview = true;
  }

  if (hasFail) return 'FAIL';
  if (hasReview) return 'REVIEW';
  return 'PASS';
}

/**
 * Build a human-readable explanation string for a detection evaluation result.
 */
export function buildDetectionExplanation(
  status: DetectionResultStatus,
  affectedFiles: AffectedFileDetail[]
): string {
  if (status === 'PASS') {
    return 'No matching PII or sensitive data was detected in the scanned files.';
  }

  if (status === 'FAIL') {
    const fileNames = affectedFiles
      .filter(f => f.confidence === 'HIGH')
      .map(f => f.filename)
      .filter((v, i, a) => a.indexOf(v) === i);
    const types = affectedFiles
      .map(f => f.detection_type)
      .filter((v, i, a) => a.indexOf(v) === i)
      .join(', ');
    return `Potential sensitive data was detected with high confidence in ${fileNames.length} file(s). Detection type(s): ${types}.`;
  }

  // REVIEW
  const fileNames = affectedFiles
    .map(f => f.filename)
    .filter((v, i, a) => a.indexOf(v) === i);
  return `The engine detected content that may represent sensitive data in ${fileNames.length} file(s), but confidence was insufficient to classify it definitively. Manual review is recommended.`;
}

/**
 * Convert a scanner Finding (from the findings table) into a normalized DetectionResult.
 *
 * @param finding  Raw finding row from the database
 * @param filename The filename of the file that produced this finding
 */
export function findingToDetectionResult(
  finding: {
    rule_id: string;
    severity: string;
    category: string;
    title: string;
    description: string;
    evidence_json?: string;
    confidence: number;
    source: string;
  },
  filename: string
): DetectionResult {
  let evidenceSummary: string | undefined;
  try {
    if (finding.evidence_json) {
      const ev = typeof finding.evidence_json === 'string'
        ? JSON.parse(finding.evidence_json)
        : finding.evidence_json;
      // Use the already-redacted snippet from the scanner engine
      evidenceSummary = ev.snippet || ev.match || undefined;
    }
  } catch {
    // Evidence parsing failure is non-fatal
  }

  return {
    detected: true,
    classification: finding.category || 'UNKNOWN',
    confidence: classifyConfidence(finding.confidence),
    score: finding.confidence,
    rule_id: finding.rule_id,
    matched_type: finding.title || finding.rule_id,
    filename,
    explanation: finding.description || `Detection triggered by rule ${finding.rule_id}.`,
    evidence_summary: evidenceSummary,
    severity: finding.severity
  };
}

/**
 * Build AffectedFileDetail[] from DetectionResult[].
 * Groups by filename and retains all individual detections.
 */
export function buildAffectedFiles(detections: DetectionResult[]): AffectedFileDetail[] {
  return detections
    .filter(d => d.detected)
    .map(d => ({
      filename: d.filename,
      detection_type: d.matched_type,
      confidence: d.confidence,
      reason: d.explanation,
      rule_id: d.rule_id,
      severity: d.severity,
      evidence_summary: d.evidence_summary
    }));
}

/**
 * Merge a detection-based status with an existing evaluator status.
 * Priority: FAIL > REVIEW > PASS
 * Technical errors (EVIDENCE_NOT_FOUND etc.) are preserved as-is.
 */
export function mergeDetectionWithEvaluatorStatus(
  evaluatorStatus: string,
  detectionStatus: DetectionResultStatus
): string {
  // Technical/error states are never overridden
  if (evaluatorStatus === 'EVIDENCE_NOT_FOUND' || evaluatorStatus === 'NOT_APPLICABLE') {
    return evaluatorStatus;
  }

  const priority: Record<string, number> = {
    'FAIL': 3,
    'REVIEW': 2,
    'PASS': 1
  };

  const evalPriority = priority[evaluatorStatus] || 0;
  const detPriority = priority[detectionStatus] || 0;

  return detPriority > evalPriority ? detectionStatus : evaluatorStatus;
}
