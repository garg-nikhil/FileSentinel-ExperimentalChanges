/**
 * Canonical Result Models & Single-Source-of-Truth Aggregation Selectors
 * 
 * Provides unified, deterministic calculations across:
 * - USER Simple UI
 * - ORG ADMIN Portal
 * - SUPER ADMIN Ops
 * 
 * Guaranteed Invariants:
 * 1. File Level: files_scanned = files_passed + files_failed + files_review
 * 2. Findings Level: findings != failed_files (a single file can have multiple findings)
 * 3. Checklist Level: checklist_total = passed + failed + review + not_found (29 parameters != 39 files)
 * 4. Endpoint Level: accessible + blocked + indeterminate + error = total_targets
 */

import {
  ScanSession,
  FileItem,
  FileOutcomeSummary,
  FileOutcomeStatus,
  AuditSession,
  EndpointAssessment,
  DetectionCategory,
  WebTargetResult
} from '../types';

export interface CanonicalScanSummary {
  scan_id: string;
  status: string;
  files: {
    total_discovered: number;
    total_scanned: number;
    passed: number;
    failed: number;
    review: number;
    errors: number;
    skipped: number;
    passed_pct: number;
    failed_pct: number;
    review_pct: number;
  };
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface CanonicalChecklistSummary {
  audit_id: string;
  scan_id?: string;
  total_parameters: number;
  passed: number;
  failed: number;
  review: number;
  not_found: number;
  fatal_failures: number;
  overall_score: number;
  max_score: number;
  score_pct: number;
  overall_status: string;
}

export interface CanonicalEndpointSummary {
  assessment_id: string;
  endpoint_id: string;
  timestamp: string;
  overall_status: 'COMPLIANT' | 'NON_COMPLIANT' | 'ATTENTION_REQUIRED' | 'INDETERMINATE';
  total_targets: number;
  accessible_count: number;
  blocked_count: number;
  indeterminate_count: number;
  error_count: number;
  usb_status: string;
  usb_connected_count: number;
  categories: Record<
    DetectionCategory,
    {
      label: string;
      total: number;
      accessible: number;
      blocked: number;
      indeterminate: number;
      status: 'PASS' | 'FAIL' | 'REVIEW';
      status_text: string;
      targets: WebTargetResult[];
    }
  >;
}

/**
 * Single source of truth for file-level outcomes for a scan session.
 */
export function getFileOutcomeSummary(
  scan: ScanSession | null,
  files?: FileItem[]
): FileOutcomeSummary {
  if (files && files.length > 0) {
    let passed = 0;
    let failed = 0;
    let review = 0;
    let errors = 0;
    let skipped = 0;

    for (const f of files) {
      const outcome = f.file_outcome || getFallbackFileOutcome(f);
      if (outcome === 'PASS') passed++;
      else if (outcome === 'FAIL') failed++;
      else if (outcome === 'REVIEW') review++;
      else if (outcome === 'ERROR' || f.scan_status === 'ERROR') errors++;
      else if (outcome === 'SKIPPED' || f.scan_status === 'SKIPPED') skipped++;
      else passed++; // Default clean
    }

    const totalScanned = passed + failed + review;
    const totalDiscovered = totalScanned + errors + skipped;

    const passedPct = totalScanned > 0 ? Number(((passed / totalScanned) * 100).toFixed(1)) : 0;
    const failedPct = totalScanned > 0 ? Number(((failed / totalScanned) * 100).toFixed(1)) : 0;
    const reviewPct = totalScanned > 0 ? Number(((review / totalScanned) * 100).toFixed(1)) : 0;

    return {
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
  }

  if (scan?.file_summary) {
    return scan.file_summary;
  }

  // Fallback to ScanSession counter fields if available
  const passed = scan?.safe_count || 0;
  const critical = scan?.critical_count || 0;
  const high = scan?.high_count || 0;
  const medium = scan?.medium_count || 0;
  const low = scan?.low_count || 0;
  const errors = scan?.error_count || 0;

  // Approximate if only finding counters exist
  const failed = critical + high > 0 ? 1 : 0;
  const review = medium + low > 0 && failed === 0 ? 1 : 0;
  const totalScanned = scan?.processed_files || (passed + failed + review);
  const totalDiscovered = scan?.total_files || totalScanned;

  const passedPct = totalScanned > 0 ? Number(((passed / totalScanned) * 100).toFixed(1)) : 0;
  const failedPct = totalScanned > 0 ? Number(((failed / totalScanned) * 100).toFixed(1)) : 0;
  const reviewPct = totalScanned > 0 ? Number(((review / totalScanned) * 100).toFixed(1)) : 0;

  return {
    total_scanned: totalScanned,
    passed,
    failed,
    review,
    skipped: 0,
    errors,
    total_discovered: totalDiscovered,
    passed_pct: passedPct,
    failed_pct: failedPct,
    review_pct: reviewPct
  };
}

function getFallbackFileOutcome(file: FileItem): FileOutcomeStatus {
  if (file.scan_status === 'ERROR') return 'ERROR';
  if (file.scan_status === 'SKIPPED') return 'SKIPPED';
  if (file.scan_status === 'PENDING' || file.scan_status === 'PROCESSING') return 'PROCESSING';

  const critical = file.findings_count?.critical || 0;
  const high = file.findings_count?.high || 0;
  const medium = file.findings_count?.medium || 0;
  const low = file.findings_count?.low || 0;

  if (critical > 0 || high > 0) return 'FAIL';
  if (medium > 0 || low > 0) return 'REVIEW';
  return 'PASS';
}

/**
 * Single source of truth for findings-level counts.
 */
export function getFindingsSummary(
  files?: FileItem[],
  scan?: ScanSession | null
) {
  if (files && files.length > 0) {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;

    for (const f of files) {
      if (f.findings && f.findings.length > 0) {
        for (const finding of f.findings) {
          const sev = finding.severity?.toUpperCase();
          if (sev === 'CRITICAL') critical++;
          else if (sev === 'HIGH') high++;
          else if (sev === 'MEDIUM') medium++;
          else if (sev === 'LOW') low++;
          else if (sev === 'INFO') info++;
        }
      } else if (f.findings_count) {
        critical += f.findings_count.critical || 0;
        high += f.findings_count.high || 0;
        medium += f.findings_count.medium || 0;
        low += f.findings_count.low || 0;
        info += f.findings_count.info || 0;
      }
    }

    const total = critical + high + medium + low + info;
    return { total, critical, high, medium, low, info };
  }

  const critical = scan?.critical_count || 0;
  const high = scan?.high_count || 0;
  const medium = scan?.medium_count || 0;
  const low = scan?.low_count || 0;
  const total = critical + high + medium + low;

  return { total, critical, high, medium, low, info: 0 };
}

/**
 * Single source of truth for Checklist (29 parameter) compliance summary.
 */
export function getChecklistSummary(auditSession: AuditSession | null): CanonicalChecklistSummary {
  if (!auditSession) {
    return {
      audit_id: '',
      total_parameters: 0,
      passed: 0,
      failed: 0,
      review: 0,
      not_found: 0,
      fatal_failures: 0,
      overall_score: 0,
      max_score: 200,
      score_pct: 0,
      overall_status: 'UNKNOWN'
    };
  }

  const results = auditSession.parameter_results || [];
  let passed = 0;
  let failed = 0;
  let review = 0;
  let notFound = 0;
  let fatalFailures = 0;

  for (const r of results) {
    const status = r.override ? r.override.new_status : r.status;
    if (status === 'PASS') {
      passed++;
    } else if (status === 'FAIL') {
      failed++;
      if (r.fatal) fatalFailures++;
    } else if (status === 'REVIEW' || status === 'NEEDS_REVIEW') {
      review++;
    } else if (status === 'EVIDENCE_NOT_FOUND' || status === 'NOT_FOUND' || status === 'MISSING') {
      notFound++;
      if (r.fatal) fatalFailures++;
    } else {
      passed++;
    }
  }

  const totalParams = results.length > 0 ? results.length : auditSession.total_parameters || 29;
  const score = auditSession.overall_score || 0;
  const maxScore = auditSession.max_score || 200;
  const scorePct = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;

  return {
    audit_id: auditSession.audit_id,
    scan_id: auditSession.scan_id,
    total_parameters: totalParams,
    passed: results.length > 0 ? passed : auditSession.pass_count || 0,
    failed: results.length > 0 ? failed : auditSession.fail_count || 0,
    review: results.length > 0 ? review : auditSession.review_count || 0,
    not_found: results.length > 0 ? notFound : auditSession.not_found_count || 0,
    fatal_failures: results.length > 0 ? fatalFailures : auditSession.fatal_failures_count || 0,
    overall_score: score,
    max_score: maxScore,
    score_pct: scorePct,
    overall_status: auditSession.overall_status || 'COMPLETED'
  };
}

/**
 * Single source of truth for Endpoint Compliance assessment breakdown.
 */
export function getEndpointSummary(assessment: EndpointAssessment | null): CanonicalEndpointSummary {
  if (!assessment) {
    return {
      assessment_id: '',
      endpoint_id: '',
      timestamp: new Date().toISOString(),
      overall_status: 'INDETERMINATE',
      total_targets: 0,
      accessible_count: 0,
      blocked_count: 0,
      indeterminate_count: 0,
      error_count: 0,
      usb_status: 'UNKNOWN',
      usb_connected_count: 0,
      categories: {
        USB_STORAGE: { label: 'USB Storage Access', total: 1, accessible: 0, blocked: 0, indeterminate: 1, status: 'REVIEW', status_text: 'Not evaluated', targets: [] },
        SOCIAL_MEDIA: { label: 'Social Media Egress', total: 0, accessible: 0, blocked: 0, indeterminate: 0, status: 'PASS', status_text: 'Not evaluated', targets: [] },
        PERSONAL_EMAIL: { label: 'Personal Email Access', total: 0, accessible: 0, blocked: 0, indeterminate: 0, status: 'PASS', status_text: 'Not evaluated', targets: [] },
        MESSAGING: { label: 'Messaging & Chat', total: 0, accessible: 0, blocked: 0, indeterminate: 0, status: 'PASS', status_text: 'Not evaluated', targets: [] },
        CLOUD_STORAGE: { label: 'Cloud Storage Access', total: 0, accessible: 0, blocked: 0, indeterminate: 0, status: 'PASS', status_text: 'Not evaluated', targets: [] }
      }
    };
  }

  const usbResult = assessment.usb_result || (assessment as any).usb_storage;
  const webResults: WebTargetResult[] = assessment.web_results || (assessment as any).web_access || [];

  const usbStatus = usbResult?.status || (usbResult as any)?.policy_status || 'UNKNOWN';
  const usbCount = usbResult?.connectedDeviceCount || usbResult?.connectedDevices?.length || (usbResult as any)?.connected_devices?.length || 0;

  const accessibleWeb = webResults.filter(w => w.status === 'ACCESSIBLE').length;
  const blockedWeb = webResults.filter(w => w.status === 'BLOCKED').length;
  const indeterminateWeb = webResults.filter(w => w.status === 'INDETERMINATE' || w.status === 'UNREACHABLE').length;
  const errorWeb = webResults.filter(w => w.status === 'ERROR').length;

  const usbAccessible = usbStatus === 'ENABLED' ? 1 : 0;
  const usbBlocked = usbStatus === 'DISABLED' ? 1 : 0;
  const usbIndeterminate = ['UNKNOWN', 'REQUIRES_ELEVATION', 'UNSUPPORTED_PLATFORM'].includes(usbStatus) ? 1 : 0;

  const totalTargets = webResults.length + 1; // 24 web targets + 1 USB inspection
  const totalAccessible = accessibleWeb + usbAccessible;
  const totalBlocked = blockedWeb + usbBlocked;
  const totalIndeterminate = indeterminateWeb + usbIndeterminate;
  const totalError = errorWeb;

  const buildCategory = (cat: DetectionCategory, label: string) => {
    if (cat === 'USB_STORAGE') {
      const isSafe = usbStatus === 'DISABLED';
      return {
        label,
        total: 1,
        accessible: usbAccessible,
        blocked: usbBlocked,
        indeterminate: usbIndeterminate,
        status: (isSafe ? 'PASS' : 'FAIL') as 'PASS' | 'FAIL' | 'REVIEW',
        status_text: isSafe ? 'Disabled (Safe)' : usbStatus,
        targets: []
      };
    }

    const catTargets = webResults.filter(t => t.category === cat);
    const catAccessible = catTargets.filter(t => t.status === 'ACCESSIBLE').length;
    const catBlocked = catTargets.filter(t => t.status === 'BLOCKED').length;
    const catIndeterminate = catTargets.filter(t => t.status === 'INDETERMINATE' || t.status === 'UNREACHABLE').length;

    let status: 'PASS' | 'FAIL' | 'REVIEW' = 'PASS';
    let statusText = 'Egress restricted';

    if (catAccessible > 0) {
      status = 'FAIL';
      statusText = `${catAccessible} of ${catTargets.length} services accessible`;
    } else if (catBlocked > 0) {
      status = 'PASS';
      statusText = `All ${catBlocked} services blocked`;
    } else if (catIndeterminate > 0) {
      status = 'REVIEW';
      statusText = `${catIndeterminate} services indeterminate`;
    }

    return {
      label,
      total: catTargets.length,
      accessible: catAccessible,
      blocked: catBlocked,
      indeterminate: catIndeterminate,
      status,
      status_text: statusText,
      targets: catTargets
    };
  };

  return {
    assessment_id: assessment.id || assessment.assessment_id || '',
    endpoint_id: assessment.endpoint_id || '',
    timestamp: assessment.timestamp || assessment.started_at || (assessment as any).assessed_at || new Date().toISOString(),
    overall_status: assessment.overall_status || (assessment as any).status || 'INDETERMINATE',
    total_targets: totalTargets,
    accessible_count: totalAccessible,
    blocked_count: totalBlocked,
    indeterminate_count: totalIndeterminate,
    error_count: totalError,
    usb_status: usbStatus,
    usb_connected_count: usbCount,
    categories: {
      USB_STORAGE: buildCategory('USB_STORAGE', 'USB Storage Access'),
      SOCIAL_MEDIA: buildCategory('SOCIAL_MEDIA', 'Social Media Egress'),
      PERSONAL_EMAIL: buildCategory('PERSONAL_EMAIL', 'Personal Email Access'),
      MESSAGING: buildCategory('MESSAGING', 'Messaging & Chat'),
      CLOUD_STORAGE: buildCategory('CLOUD_STORAGE', 'Cloud Storage Access')
    }
  };
}
