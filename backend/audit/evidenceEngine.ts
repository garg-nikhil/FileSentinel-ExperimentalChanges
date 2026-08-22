import crypto from 'node:crypto';
import { defaultRegistry } from '../extractors/registry.js';
import { INITIAL_AUDIT_CHECKLIST } from './checklist.js';
import { DateEvaluator } from './dateEvaluator.js';
import { EvidenceMatcher, calculateEvidencePriority, enrichEvidenceItemWithMetricsAndRole } from './evidenceMatcher.js';
import { AuditEvaluator } from './evaluator.js';
import { evaluateEvidenceWithGemini } from './aiClassifier.ts';
import { AuditScoringEngine } from './scoring.js';
import { EntityResolver } from './entityResolver.js';
import {
  AuditGap,
  AuditParameter,
  AuditParameterResult,
  AuditSession,
  EvidenceGap,
  EvidenceItem
} from './models.js';
import {
  findingToDetectionResult,
  evaluateChecklistDetections,
  buildAffectedFiles,
  buildDetectionExplanation,
  mergeDetectionWithEvaluatorStatus,
  DetectionResult,
  DetectionResultStatus
} from './detectionPolicy.js';
import { aggregateFileOutcomes } from './fileOutcome.js';

export interface RunAuditScanForSessionOptions {
  scanId: string;
  orgId: string;
  auditDate?: string;
  agencyName?: string;
  auditorName?: string;
  customChecklist?: AuditParameter[];
}

export class EvidenceEngine {
  private db: any;
  private matcher: EvidenceMatcher;
  private evaluator: AuditEvaluator;

  constructor(db: any) {
    this.db = db;
    this.matcher = new EvidenceMatcher();
    this.evaluator = new AuditEvaluator();
  }

  /**
   * Runs an Audit Scan over discovered/scanned files for a specific directory or existing database files
   */
  public async runAuditScan(
    filePaths: string[],
    auditDate: string = new Date().toISOString().split('T')[0],
    agencyName: string = 'Primary Telecalling & Collection Agency',
    auditorName: string = 'Automated Audit System',
    customChecklist?: AuditParameter[],
    aiPrivacyMode: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' = 'OFF',
    orgId?: string
  ): Promise<AuditSession> {
    const auditId = `AUDIT-${crypto.randomUUID().substring(0, 8)}`;
    const activeChecklist = customChecklist || INITIAL_AUDIT_CHECKLIST;

    console.log(`[Audit Engine] Starting Audit ${auditId} over ${filePaths.length} files with date ${auditDate}`);

    // Extract text and metadata for all target files
    const fileExtractions: { fileId: string; filePath: string; extraction: any }[] = [];

    for (let i = 0; i < filePaths.length; i++) {
      const filePath = filePaths[i];
      const fileId = `FILE-${crypto.randomUUID().substring(0, 8)}`;
      try {
        const extraction = await defaultRegistry.extract(filePath, 50);
        fileExtractions.push({ fileId, filePath, extraction });
      } catch (err) {
        console.warn(`[Audit Engine] Failed extracting file ${filePath}:`, err);
      }
    }

    return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName, undefined, aiPrivacyMode, orgId);
  }

  /**
   * Runs an Audit Scan over existing scan session data (already extracted evidence)
   */
  public async runAuditScanForSession(options: RunAuditScanForSessionOptions): Promise<AuditSession> {
    const {
      scanId,
      orgId,
      auditDate = new Date().toISOString().split('T')[0],
      agencyName = 'Primary Telecalling & Collection Agency',
      auditorName = 'Automated Audit System',
      customChecklist
    } = options;

    if (!scanId || typeof scanId !== 'string') {
      throw new Error('Scan ID is required for audit scan');
    }
    if (!orgId || typeof orgId !== 'string') {
      throw new Error('Organization ID is mandatory for audit scan');
    }

    const scanRow = this.db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(scanId) as any;
    if (!scanRow) {
      throw new Error('Scan record not found for audit scan');
    }
    if (scanRow.org_id && scanRow.org_id !== orgId) {
      throw new Error('Access denied: Cross-tenant audit scan forbidden');
    }

    const auditId = `AUDIT-${crypto.randomUUID().substring(0, 8)}`;
    const activeChecklist = customChecklist || INITIAL_AUDIT_CHECKLIST;
    
    console.log(`[Audit Engine] Starting Audit ${auditId} for Scan Session ${scanId} (Org: ${orgId})`);

    const rows = this.db.prepare('SELECT file_id, path, extracted_text, metadata_json FROM files WHERE scan_id = ?').all(scanId) as any[];
    
    const fileExtractions: { fileId: string; filePath: string; extraction: any }[] = [];
    
    for (const row of rows) {
      let metadata = {};
      try {
        if (row.metadata_json) {
          metadata = JSON.parse(row.metadata_json);
        }
      } catch(e) {}
      
      fileExtractions.push({
        fileId: row.file_id,
        filePath: row.path,
        extraction: {
          text: row.extracted_text || '',
          metadata: metadata
        }
      });
    }
    
    return this.evaluateChecklist(auditId, fileExtractions, activeChecklist, auditDate, agencyName, auditorName, scanId, 'OFF', orgId);
  }

  private async evaluateChecklist(
    auditId: string,
    fileExtractions: { fileId: string; filePath: string; extraction: any }[],
    activeChecklist: AuditParameter[],
    auditDate: string,
    agencyName: string,
    auditorName: string,
    scanId?: string,
    aiPrivacyMode: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' = 'OFF',
    orgId?: string
  ): Promise<AuditSession> {
    // Evaluate each parameter against all documents
    const parameterResults: AuditParameterResult[] = [];

    for (const param of activeChecklist) {
      if (!param.enabled) continue;

      const matchedEvidence: EvidenceItem[] = [];

      for (const item of fileExtractions) {
        const matched = this.matcher.matchDocumentToParameter(
          item.fileId,
          item.filePath,
          item.extraction,
          param
        );
        if (matched) {
          matchedEvidence.push(matched);
        }
      }

      // Sort evidence by multi-factor candidate priority
      matchedEvidence.sort((a, b) => calculateEvidencePriority(b, param) - calculateEvidencePriority(a, param));
      const enrichedEvidence = matchedEvidence.map((ev, index) => {
        const isPrimary = index === 0 && ev.validated;
        const isDuplicateOrParallel = index > 0 && ev.validated;
        return enrichEvidenceItemWithMetricsAndRole(ev, param, undefined, isPrimary, isDuplicateOrParallel);
      });

      // Deterministic Evaluation
      const result = this.evaluator.evaluateParameter(param, enrichedEvidence, auditDate);

      // Optional Gemini AI Assistance
      if (aiPrivacyMode !== 'OFF' && result.evidence_set && (result.evidence_set.primaryEvidence || result.evidence_set.supportingEvidence.length > 0)) {
        try {
          const evidenceForAi = {
             primary: result.evidence_set.primaryEvidence,
             supporting: result.evidence_set.supportingEvidence,
             contradictory: result.evidence_set.contradictoryEvidence
          };
          
          let aiText = '';
          if (aiPrivacyMode === 'FULL_TEXT') {
            const topFile = fileExtractions.find(f => f.fileId === result.evidence_set?.primaryEvidence?.file_id);
            aiText = topFile?.extraction?.text || '';
          } else {
             aiText = JSON.stringify(evidenceForAi, null, 2);
          }

          const filename = result.evidence_set?.primaryEvidence?.filename || 'aggregated_evidence.json';

          const aiRec = await evaluateEvidenceWithGemini(
            filename,
            aiText,
            param
          );
          if (aiRec) {
            result.ai_recommendation = aiRec;
          }
        } catch {
          // Silently fall back to deterministic evaluation result
        }
      }

      parameterResults.push(result);
    }

    // ─── DETECTION-BASED EVALUATION ─────────────────────────────────
    // Query scanner findings from the DB and apply detection policy
    // to DET-* parameters and overlay detection awareness on existing parameters.
    if (scanId && this.db) {
      try {
        await this.applyDetectionResults(scanId, parameterResults, fileExtractions);
      } catch (err) {
        console.error('[Audit Engine] Detection evaluation failed (non-blocking):', err);
      }
    }

    // Compute Overall Scoring and Summary
    const session = AuditScoringEngine.calculateAuditSummary(
      auditId,
      agencyName,
      auditorName,
      auditDate,
      parameterResults
    );
    if (scanId) {
      session.scan_id = scanId;
    }
    if (orgId) {
      (session as any).org_id = orgId;
    }

    // Perform True Session-Level Entity Resolution across all validated evidence
    const entityResolution = EntityResolver.resolveAuditSessionEntities(parameterResults, auditId);
    session.entities = entityResolution.entities;
    session.entity_conflicts = entityResolution.conflicts;
    session.entity_findings = entityResolution.entityFindings;
    session.entity_resolution = entityResolution;
    session.entityConflicts = entityResolution.conflicts;
    session.entityFindings = entityResolution.entityFindings;
    session.entityResolution = entityResolution;

    // ─── FILE OUTCOME SUMMARY ─────────────────────────────────────────
    if (scanId && this.db) {
      try {
        const fileRows = this.db.prepare('SELECT * FROM files WHERE scan_id = ?').all(scanId) as any[];
        const filesWithFindings = fileRows.map(f => {
          const findings = this.db.prepare('SELECT * FROM findings WHERE file_id = ?').all(f.file_id) as any[];
          return {
            file_id: f.file_id,
            filename: f.filename,
            path: f.path,
            scan_status: f.scan_status,
            warnings: f.warnings_json ? JSON.parse(f.warnings_json) : [],
            metadata: f.metadata_json ? JSON.parse(f.metadata_json) : {},
            findings
          };
        });
        const { summary, details } = aggregateFileOutcomes(filesWithFindings);
        session.file_summary = summary;
        session.file_outcomes = details;
        session.fileSummary = summary;
        session.fileOutcomes = details;
      } catch (err) {
        console.error('[Audit Engine] File outcome aggregation failed (non-blocking):', err);
      }
    } else if (fileExtractions.length > 0) {
      const synthFiles = fileExtractions.map(fe => ({
        file_id: fe.fileId,
        path: fe.filePath,
        filename: fe.filePath.split(/[/\\]/).pop(),
        scan_status: 'SUCCESS',
        findings: []
      }));
      const { summary, details } = aggregateFileOutcomes(synthFiles);
      session.file_summary = summary;
      session.file_outcomes = details;
      session.fileSummary = summary;
      session.fileOutcomes = details;
    }

    // If entity conflicts exist and overall status was compliant, flag that review is needed
    if (entityResolution.conflicts.length > 0 && session.overall_status === 'COMPLIANT') {
      session.overall_status = 'NEEDS_REVIEW';
    }

    this.saveAuditSessionToDb(session);

    return session;
  }

  // ─── Detection-Based Evaluation ───────────────────────────────────

  /** Category mapping: DET parameter ID → scanner Finding categories */
  private static readonly DET_CATEGORY_MAP: Record<string, string[]> = {
    'DET-001': ['PII'],
    'DET-002': ['SECRETS'],
    'DET-003': ['FINANCIAL'],
    'DET-004': ['SECURITY']
  };

  /**
   * Applies detection engine results (scanner findings) to checklist parameters.
   *
   * For DET-* parameters: evaluates purely from scanner findings.
   * For existing parameters: overlays detection awareness if evidence files contain violations.
   *
   * Detection does NOT overwrite technical errors (EVIDENCE_NOT_FOUND, NOT_APPLICABLE).
   * Score adjustments: FAIL → score_earned = 0, REVIEW (from PASS) → score_earned = 0
   */
  private async applyDetectionResults(
    scanId: string,
    parameterResults: AuditParameterResult[],
    fileExtractions: { fileId: string; filePath: string; extraction: any }[]
  ): Promise<void> {
    // 1. Query all findings from the DB for this scan's files
    const findingRows = this.db.prepare(`
      SELECT f.finding_id, f.file_id, f.rule_id, f.severity, f.category, f.title,
             f.description, f.evidence_json, f.confidence, f.source,
             fi.filename, fi.path, fi.scan_status
      FROM findings f
      JOIN files fi ON f.file_id = fi.file_id
      WHERE fi.scan_id = ?
    `).all(scanId) as any[];

    if (!findingRows || findingRows.length === 0) {
      // No findings at all — all DET-* parameters get PASS
      for (const result of parameterResults) {
        if (result.parameter_id.startsWith('DET-')) {
          result.status = 'PASS';
          result.confidence = 1.0;
          result.score_earned = result.max_score;
          result.reason = 'No matching sensitive data was detected in the scanned files.';
          result.detection_results = {
            status: 'PASS',
            affected_files: [],
            explanation: 'No matching PII or sensitive data was detected in the scanned files.'
          };
        }
      }
      return;
    }

    // 2. Convert DB finding rows into DetectionResult[]
    const allDetections: DetectionResult[] = findingRows.map(row =>
      findingToDetectionResult(row, row.filename || 'unknown')
    );

    // 3. Group detections by category for DET-* parameter evaluation
    const detectionsByCategory = new Map<string, DetectionResult[]>();
    for (const d of allDetections) {
      const cat = d.classification;
      if (!detectionsByCategory.has(cat)) {
        detectionsByCategory.set(cat, []);
      }
      detectionsByCategory.get(cat)!.push(d);
    }

    // 4. Evaluate DET-* parameters from scanner findings
    for (const result of parameterResults) {
      if (!result.parameter_id.startsWith('DET-')) continue;

      const targetCategories = EvidenceEngine.DET_CATEGORY_MAP[result.parameter_id] || [];
      const relevantDetections: DetectionResult[] = [];

      for (const cat of targetCategories) {
        const catDetections = detectionsByCategory.get(cat) || [];
        relevantDetections.push(...catDetections);
      }

      const detStatus = evaluateChecklistDetections(relevantDetections);
      const affectedFiles = buildAffectedFiles(relevantDetections);
      const explanation = buildDetectionExplanation(detStatus, affectedFiles);

      // Set the authoritative result
      result.status = detStatus;
      result.confidence = detStatus === 'PASS' ? 1.0 : (detStatus === 'FAIL' ? 0.95 : 0.80);
      result.score_earned = detStatus === 'PASS' ? result.max_score : 0;
      result.reason = explanation;
      result.evidence = []; // DET-* parameters don't use evidence-matching
      result.missing_requirements = [];
      result.warnings = detStatus !== 'PASS'
        ? [`Detection engine found ${relevantDetections.length} relevant finding(s)`]
        : [];

      result.detection_results = {
        status: detStatus,
        affected_files: affectedFiles,
        explanation
      };
    }

    // 5. Overlay detection awareness on existing (non-DET) parameters
    // If a file matched to an existing parameter also has violations, attach detection info
    for (const result of parameterResults) {
      if (result.parameter_id.startsWith('DET-')) continue;

      // Find files that are evidence for this parameter
      const evidenceFileIds = new Set(
        result.evidence.map(e => e.file_id).filter(Boolean)
      );

      if (evidenceFileIds.size === 0) continue;

      // Find detections in those specific evidence files
      const evidenceDetections = allDetections.filter(d => {
        // Match by filename against evidence filenames
        return result.evidence.some(e =>
          e.filename === d.filename || e.file_id === d.filename
        );
      });

      if (evidenceDetections.length === 0) continue;

      const detStatus = evaluateChecklistDetections(evidenceDetections);
      const affectedFiles = buildAffectedFiles(evidenceDetections);
      const explanation = buildDetectionExplanation(detStatus, affectedFiles);

      // Attach detection results for UI display
      result.detection_results = {
        status: detStatus,
        affected_files: affectedFiles,
        explanation
      };

      // Merge with existing status (FAIL > REVIEW > PASS, technical errors preserved)
      const mergedStatus = mergeDetectionWithEvaluatorStatus(result.status, detStatus);
      if (mergedStatus !== result.status) {
        result.warnings = [
          ...(result.warnings || []),
          `Detection engine elevated status from ${result.status} to ${mergedStatus}`
        ];
        result.status = mergedStatus as any;
        if (mergedStatus === 'FAIL' || mergedStatus === 'REVIEW') {
          result.score_earned = 0;
        }
      }
    }
  }

  /**
   * Generates actionable Evidence Gaps list for remediation planning
   */
  public generateEvidenceGaps(session: AuditSession): EvidenceGap[] {
    const gaps: EvidenceGap[] = [];
    if (!session.parameter_results) return gaps;

    for (const res of session.parameter_results) {
      const status = res.override ? res.override.new_status : res.status;
      if (status === 'FAIL' || status === 'REVIEW' || status === 'EVIDENCE_NOT_FOUND') {
        let priority: 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
        if (res.fatal) priority = 'HIGH';
        else if (status === 'FAIL') priority = 'HIGH';
        else if (status === 'EVIDENCE_NOT_FOUND') priority = 'MEDIUM';
        else priority = 'LOW';

        gaps.push({
          priority,
          parameter_id: res.parameter_id,
          parameter_title: res.parameter.parameter,
          category: res.parameter.category_name,
          fatal: res.fatal,
          status,
          missing: res.missing_requirements.join(', ') || 'Acceptable operational evidence',
          recommended_action: res.parameter.evaluation_rules[0] || 'Provide verified documentary evidence',
          fatal_impact: res.fatal && (status === 'FAIL' || status === 'EVIDENCE_NOT_FOUND')
        });
      }
    }

    return gaps;
  }

  /**
   * Persists Audit Session and parameter results in SQLite
   */
  private saveAuditSessionToDb(session: AuditSession): void {
    if (!this.db) return;

    try {
      let orgId = (session as any).org_id || null;
      if (session.scan_id) {
        const scanRow = this.db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(session.scan_id) as any;
        if (scanRow && scanRow.org_id) {
          if (orgId && scanRow.org_id !== orgId) {
            throw new Error(`Tenant mismatch: audit_sessions.org_id (${orgId}) does not match scans.org_id (${scanRow.org_id})`);
          }
          if (!orgId) {
            orgId = scanRow.org_id;
          }
        }
      }

      const stmt = this.db.prepare(`
        INSERT INTO audit_sessions (
          audit_id, scan_id, org_id, audit_date, agency_name, auditor_name, status,
          total_parameters, pass_count, fail_count, review_count, not_found_count,
          fatal_failures_count, overall_score, max_score, overall_status,
          category_scores_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        session.audit_id,
        session.scan_id || null,
        orgId,
        session.audit_date,
        session.agency_name,
        session.auditor_name,
        session.status,
        session.total_parameters,
        session.pass_count,
        session.fail_count,
        session.review_count,
        session.not_found_count,
        session.fatal_failures_count,
        session.overall_score,
        session.max_score,
        session.overall_status,
        JSON.stringify(session.category_scores),
        session.created_at,
        session.updated_at
      );

      const paramStmt = this.db.prepare(`
        INSERT INTO audit_parameter_results (
          audit_id, parameter_id, status, confidence, fatal,
          score_earned, max_score, policy_status, pv_status,
          evidence_json, reason, missing_requirements_json, warnings_json,
          ai_recommendation_json, override_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      if (session.parameter_results) {
        for (const res of session.parameter_results) {

          // Sanitize evidence before saving to DB
          const sanitizedEvidence = res.evidence.map(e => {
            const safeItem = { ...e };
            if (safeItem.extracted_fields) {
               safeItem.extracted_fields = { ...safeItem.extracted_fields };
               delete safeItem.extracted_fields.raw_text;
               delete safeItem.extracted_fields.fullText;
               delete safeItem.extracted_fields.documentText;
               delete safeItem.extracted_fields.extractedText;
               delete safeItem.extracted_fields.text;
            }
            if (safeItem.structured_fields) {
               safeItem.structured_fields = { ...safeItem.structured_fields };
               delete safeItem.structured_fields.raw_text;
               delete safeItem.structured_fields.fullText;
               delete safeItem.structured_fields.documentText;
               delete safeItem.structured_fields.extractedText;
               delete safeItem.structured_fields.text;
            }
            return safeItem;
          });

          // Also sanitize evidence_set
          let sanitizedEvidenceSet = undefined;
          if (res.evidence_set) {
            const sanitizeList = (list) => list.map(e => {
               const safeItem = { ...e };
               if (safeItem.extracted_fields) {
                  safeItem.extracted_fields = { ...safeItem.extracted_fields };
                  delete safeItem.extracted_fields.raw_text;
               }
               return safeItem;
            });
            sanitizedEvidenceSet = {
               ...res.evidence_set,
               primaryEvidence: res.evidence_set.primaryEvidence ? sanitizeList([res.evidence_set.primaryEvidence])[0] : null,
               supportingEvidence: sanitizeList(res.evidence_set.supportingEvidence || []),
               reviewEvidence: sanitizeList(res.evidence_set.reviewEvidence || []),
               contradictoryEvidence: sanitizeList(res.evidence_set.contradictoryEvidence || []),
               rejectedCandidates: sanitizeList(res.evidence_set.rejectedCandidates || [])
            };
          }

          paramStmt.run(
            session.audit_id,
            res.parameter_id,
            res.status,
            res.confidence,
            res.fatal ? 1 : 0,
            res.score_earned,
            res.max_score,
            res.policy_status || null,
            res.pv_status || null,
            JSON.stringify({ evidence: sanitizedEvidence, evidence_set: sanitizedEvidenceSet }),
            res.reason,
            JSON.stringify(res.missing_requirements),
            JSON.stringify(res.warnings),
            res.ai_recommendation ? JSON.stringify(res.ai_recommendation) : null,
            res.override ? JSON.stringify(res.override) : null
          );
        }
      }

      // Save Entities
      if (session.entities && session.entities.length > 0) {
        const entityStmt = this.db.prepare(`
          INSERT OR REPLACE INTO audit_entities (
            entity_id, audit_id, entity_type, display_name, normalized_name,
            identifiers_json, evidence_references_json, matching_signals_json,
            confidence, status, conflicts_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const ent of session.entities) {
          entityStmt.run(
            ent.entityId,
            session.audit_id,
            ent.entityType,
            ent.displayName,
            ent.normalizedName,
            JSON.stringify(ent.identifiers),
            JSON.stringify(ent.evidenceReferences),
            JSON.stringify(ent.matchingSignals),
            ent.confidence,
            ent.status,
            JSON.stringify(ent.conflicts),
            ent.createdAt
          );
        }
      }

      // Save Entity Conflicts
      if (session.entity_conflicts && session.entity_conflicts.length > 0) {
        const conflictStmt = this.db.prepare(`
          INSERT INTO audit_entity_conflicts (
            id, audit_id, entity_id, conflict_type, severity,
            title, description, reason, involved_evidence_json,
            conflicting_attributes_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const conf of session.entity_conflicts) {
          conflictStmt.run(
            `CONF-${crypto.randomUUID().substring(0, 8)}`,
            session.audit_id,
            conf.involvedEvidence[0]?.fileId || 'UNKNOWN_ENTITY',
            conf.conflictType,
            conf.severity,
            conf.title,
            conf.description,
            conf.reason,
            JSON.stringify(conf.involvedEvidence),
            JSON.stringify(conf.conflictingAttributes),
            new Date().toISOString()
          );
        }
      }
    } catch (err) {
      console.error('[Audit Engine] Database save error:', err);
    }
  }
}
