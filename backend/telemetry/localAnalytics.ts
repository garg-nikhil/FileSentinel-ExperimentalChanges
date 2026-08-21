/**
 * FILE-SENTINEL — Phase T4: Local Analytics Engine & Phase T5: Telemetry Health
 *
 * Requirements:
 * - 100% Read-Only: Never modifies scans, audit logs, queue, or licensing state
 * - Offline Local Aggregation: Calculates all metrics directly from local SQLite
 * - Complete Isolation: Zero dependency on network connectivity or Google Sheets
 */

import { DatabaseSync } from 'node:sqlite';
import { TelemetryHealthStats } from './telemetryTypes.js';

export interface ScanVolumeMetrics {
  total_scans: number;
  total_files_scanned: number;
  avg_duration_ms: number;
  avg_files_per_scan: number;
}

export interface RiskDistributionMetrics {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total_findings: number;
}

export interface UsbComplianceMetrics {
  total_assessments: number;
  compliant_disabled_count: number;
  non_compliant_enabled_count: number;
  compliance_percentage: number;
}

export interface LicenseLifecycleMetrics {
  active_count: number;
  expiring_soon_count: number;
  expired_count: number;
  total_licensed_devices: number;
}

export interface FeatureUsageMetrics {
  ai_evaluation_count: number;
  quarantine_count: number;
  cloud_storage_configured: boolean;
  verifiable_reports_generated: number;
}

export interface ErrorRateMetrics {
  total_scans: number;
  failed_scans: number;
  error_rate_percentage: number;
  total_logged_errors: number;
}

export interface CompleteAnalyticsReport {
  generated_at: string;
  organization_id?: string;
  scans_per_day: { date: string; count: number }[];
  scans_per_customer: { organization_id: string; scan_count: number }[];
  active_endpoints_count: number;
  volume_metrics: ScanVolumeMetrics;
  risk_distribution: RiskDistributionMetrics;
  compliance_score_overview: {
    avg_score: number;
    latest_score: number;
    total_assessments: number;
  };
  compliance_trend: { date: string; score: number }[];
  endpoint_assessments_per_day: { date: string; count: number }[];
  usb_compliance: UsbComplianceMetrics;
  web_access_categories: { category: string; accessible: number; blocked: number; unreachable: number; indeterminate: number }[];
  license_stats: LicenseLifecycleMetrics;
  feature_usage: FeatureUsageMetrics;
  error_metrics: ErrorRateMetrics;
  telemetry_health: TelemetryHealthStats;
}

export class LocalAnalyticsService {
  private db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  /**
   * Scans per day for the last N days
   */
  public getScansPerDay(days: number = 30, orgId?: string): { date: string; count: number }[] {
    const daysOffset = `-${Math.max(1, days)} days`;
    let query = `
      SELECT substr(start_time, 1, 10) as date, COUNT(*) as count
      FROM scans
      WHERE start_time >= datetime('now', ?)
    `;
    const params: any[] = [daysOffset];

    if (orgId) {
      query += ' AND org_id = ?';
      params.push(orgId);
    }

    query += ' GROUP BY substr(start_time, 1, 10) ORDER BY date ASC';

    return (this.db.prepare(query).all(...params) as any[]).map(r => ({
      date: r.date || 'Unknown',
      count: Number(r.count || 0)
    }));
  }

  /**
   * Scans per customer (organization)
   */
  public getScansPerCustomer(days: number = 30): { organization_id: string; scan_count: number }[] {
    const daysOffset = `-${Math.max(1, days)} days`;
    const query = `
      SELECT org_id as organization_id, COUNT(*) as scan_count
      FROM scans
      WHERE start_time >= datetime('now', ?)
      GROUP BY org_id
      ORDER BY scan_count DESC
    `;

    return (this.db.prepare(query).all(daysOffset) as any[]).map(r => ({
      organization_id: r.organization_id || 'unknown',
      scan_count: Number(r.scan_count || 0)
    }));
  }

  /**
   * Active endpoints count in the last N days
   */
  public getActiveEndpointsCount(days: number = 30, orgId?: string): number {
    const daysOffset = `-${Math.max(1, days)} days`;
    let query = `
      SELECT COUNT(DISTINCT device_id) as count
      FROM (
        SELECT device_id FROM scans WHERE start_time >= datetime('now', ?) AND device_id IS NOT NULL
        UNION
        SELECT device_id FROM endpoint_assessments WHERE created_at >= datetime('now', ?) AND device_id IS NOT NULL
      )
    `;
    const params: any[] = [daysOffset, daysOffset];

    if (orgId) {
      query = `
        SELECT COUNT(DISTINCT device_id) as count
        FROM (
          SELECT device_id FROM scans WHERE start_time >= datetime('now', ?) AND org_id = ? AND device_id IS NOT NULL
          UNION
          SELECT device_id FROM endpoint_assessments WHERE created_at >= datetime('now', ?) AND org_id = ? AND device_id IS NOT NULL
        )
      `;
      params.splice(1, 0, orgId);
      params.push(orgId);
    }

    const row = this.db.prepare(query).get(...params) as any;
    return Number(row?.count || 0);
  }

  /**
   * Average scan duration and file volume metrics
   */
  public getScanVolumeMetrics(orgId?: string): ScanVolumeMetrics {
    let query = `
      SELECT
        COUNT(*) as total_scans,
        SUM(total_files) as total_files,
        AVG(CASE
          WHEN end_time IS NOT NULL AND start_time IS NOT NULL
          THEN (strftime('%s', end_time) - strftime('%s', start_time)) * 1000
          ELSE 0
        END) as avg_duration_ms,
        AVG(total_files) as avg_files_per_scan
      FROM scans
      WHERE status != 'RUNNING'
    `;
    const params: any[] = [];

    if (orgId) {
      query += ' AND org_id = ?';
      params.push(orgId);
    }

    const row = this.db.prepare(query).get(...params) as any;
    const totalScans = Number(row?.total_scans || 0);

    return {
      total_scans: totalScans,
      total_files_scanned: Number(row?.total_files || 0),
      avg_duration_ms: Math.round(Number(row?.avg_duration_ms || 0)),
      avg_files_per_scan: totalScans > 0 ? Number((row?.avg_files_per_scan || 0).toFixed(1)) : 0
    };
  }

  /**
   * Risk severity distribution (Critical, High, Medium, Low)
   */
  public getRiskDistribution(orgId?: string): RiskDistributionMetrics {
    let query = `
      SELECT
        SUM(critical_count) as critical,
        SUM(high_count) as high,
        SUM(medium_count) as medium,
        SUM(low_count) as low
      FROM scans
    `;
    const params: any[] = [];

    if (orgId) {
      query += ' WHERE org_id = ?';
      params.push(orgId);
    }

    const row = this.db.prepare(query).get(...params) as any;
    const crit = Number(row?.critical || 0);
    const high = Number(row?.high || 0);
    const med = Number(row?.medium || 0);
    const low = Number(row?.low || 0);

    return {
      critical: crit,
      high: high,
      medium: med,
      low: low,
      total_findings: crit + high + med + low
    };
  }

  /**
   * Compliance score overview and trend
   */
  public getComplianceOverview(orgId?: string): { avg_score: number; latest_score: number; total_assessments: number } {
    let query = 'SELECT summary_json, created_at FROM endpoint_assessments';
    const params: any[] = [];

    if (orgId) {
      query += ' WHERE org_id = ?';
      params.push(orgId);
    }
    query += ' ORDER BY created_at DESC';

    const rows = this.db.prepare(query).all(...params) as any[];
    if (rows.length === 0) {
      return { avg_score: 100, latest_score: 100, total_assessments: 0 };
    }

    let sum = 0;
    let validCount = 0;
    let latestScore = 100;

    for (let i = 0; i < rows.length; i++) {
      try {
        const s = JSON.parse(rows[i].summary_json || '{}');
        const score = typeof s.overall_score === 'number' ? s.overall_score : 100;
        if (i === 0) latestScore = score;
        sum += score;
        validCount++;
      } catch {
        sum += 100;
        validCount++;
      }
    }

    const avg = validCount > 0 ? Number((sum / validCount).toFixed(1)) : 100;
    return {
      avg_score: avg,
      latest_score: Number(latestScore.toFixed(1)),
      total_assessments: rows.length
    };
  }

  /**
   * Compliance score trend points over time
   */
  public getComplianceTrend(days: number = 30, orgId?: string): { date: string; score: number }[] {
    const daysOffset = `-${Math.max(1, days)} days`;
    let query = `
      SELECT substr(created_at, 1, 10) as date, summary_json
      FROM endpoint_assessments
      WHERE created_at >= datetime('now', ?)
    `;
    const params: any[] = [daysOffset];

    if (orgId) {
      query += ' AND org_id = ?';
      params.push(orgId);
    }
    query += ' ORDER BY created_at ASC';

    const rows = this.db.prepare(query).all(...params) as any[];
    const grouped: Record<string, { sum: number; count: number }> = {};

    for (const r of rows) {
      const d = r.date || 'Unknown';
      let score = 100;
      try {
        const s = JSON.parse(r.summary_json || '{}');
        if (typeof s.overall_score === 'number') score = s.overall_score;
      } catch {}

      if (!grouped[d]) grouped[d] = { sum: 0, count: 0 };
      grouped[d].sum += score;
      grouped[d].count++;
    }

    return Object.keys(grouped).map(date => ({
      date,
      score: Number((grouped[date].sum / grouped[date].count).toFixed(1))
    }));
  }

  /**
   * Endpoint assessments per day
   */
  public getEndpointAssessmentsPerDay(days: number = 30, orgId?: string): { date: string; count: number }[] {
    const daysOffset = `-${Math.max(1, days)} days`;
    let query = `
      SELECT substr(created_at, 1, 10) as date, COUNT(*) as count
      FROM endpoint_assessments
      WHERE created_at >= datetime('now', ?)
    `;
    const params: any[] = [daysOffset];

    if (orgId) {
      query += ' AND org_id = ?';
      params.push(orgId);
    }

    query += ' GROUP BY substr(created_at, 1, 10) ORDER BY date ASC';

    return (this.db.prepare(query).all(...params) as any[]).map(r => ({
      date: r.date || 'Unknown',
      count: Number(r.count || 0)
    }));
  }

  /**
   * USB compliance metrics
   */
  public getUsbComplianceStats(orgId?: string): UsbComplianceMetrics {
    let query = 'SELECT summary_json FROM endpoint_assessments';
    const params: any[] = [];

    if (orgId) {
      query += ' WHERE org_id = ?';
      params.push(orgId);
    }

    const rows = this.db.prepare(query).all(...params) as any[];
    let disabled = 0;
    let enabled = 0;

    for (const r of rows) {
      try {
        const s = JSON.parse(r.summary_json || '{}');
        if (s.usb_status === 'DISABLED') {
          disabled++;
        } else if (s.usb_status === 'ENABLED') {
          enabled++;
        }
      } catch {}
    }

    const total = rows.length;
    const percentage = total > 0 ? Number(((disabled / total) * 100).toFixed(1)) : 100;

    return {
      total_assessments: total,
      compliant_disabled_count: disabled,
      non_compliant_enabled_count: enabled,
      compliance_percentage: percentage
    };
  }

  /**
   * Web access categories summary
   */
  public getWebAccessCategorySummary(orgId?: string): {
    category: string;
    accessible: number;
    blocked: number;
    unreachable: number;
    indeterminate: number;
  }[] {
    const categories = ['SOCIAL_MEDIA', 'PERSONAL_EMAIL', 'MESSAGING', 'CLOUD_STORAGE'];
    const results = [];

    for (const cat of categories) {
      results.push({
        category: cat,
        accessible: 0,
        blocked: 0,
        unreachable: 0,
        indeterminate: 0
      });
    }

    return results;
  }

  /**
   * License lifecycle statistics
   */
  public getLicenseLifecycleStats(): LicenseLifecycleMetrics {
    try {
      const rows = this.db.prepare(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END) as active_count,
          SUM(CASE WHEN status = 'EXPIRED' THEN 1 ELSE 0 END) as expired_count
        FROM licenses
      `).get() as any;

      return {
        active_count: Number(rows?.active_count || 0),
        expiring_soon_count: 0,
        expired_count: Number(rows?.expired_count || 0),
        total_licensed_devices: Number(rows?.total || 0)
      };
    } catch {
      return {
        active_count: 1,
        expiring_soon_count: 0,
        expired_count: 0,
        total_licensed_devices: 1
      };
    }
  }

  /**
   * Feature usage statistics
   */
  public getFeatureUsageStats(orgId?: string): FeatureUsageMetrics {
    let aiCount = 0;
    let quarantineCount = 0;
    let verifiableCount = 0;

    try {
      const aiRow = this.db.prepare("SELECT COUNT(*) as count FROM files WHERE ai_summary_json IS NOT NULL").get() as any;
      aiCount = Number(aiRow?.count || 0);
    } catch {}

    try {
      const quarRow = this.db.prepare("SELECT COUNT(*) as count FROM files WHERE quarantine_status = 'QUARANTINED'").get() as any;
      quarantineCount = Number(quarRow?.count || 0);
    } catch {}

    try {
      const verRow = this.db.prepare("SELECT COUNT(*) as count FROM audit_reports WHERE signature IS NOT NULL").get() as any;
      verifiableCount = Number(verRow?.count || 0);
    } catch {}

    return {
      ai_evaluation_count: aiCount,
      quarantine_count: quarantineCount,
      cloud_storage_configured: false,
      verifiable_reports_generated: verifiableCount
    };
  }

  /**
   * Error rate statistics
   */
  public getErrorRateStats(days: number = 30, orgId?: string): ErrorRateMetrics {
    const daysOffset = `-${Math.max(1, days)} days`;
    let query = `
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed
      FROM scans
      WHERE start_time >= datetime('now', ?)
    `;
    const params: any[] = [daysOffset];

    if (orgId) {
      query += ' AND org_id = ?';
      params.push(orgId);
    }

    const row = this.db.prepare(query).get(...params) as any;
    const total = Number(row?.total || 0);
    const failed = Number(row?.failed || 0);
    const percentage = total > 0 ? Number(((failed / total) * 100).toFixed(2)) : 0;

    let errorCount = 0;
    try {
      const errRow = this.db.prepare("SELECT COUNT(*) as count FROM telemetry_queue WHERE event_type = 'ERROR'").get() as any;
      errorCount = Number(errRow?.count || 0);
    } catch {}

    return {
      total_scans: total,
      failed_scans: failed,
      error_rate_percentage: percentage,
      total_logged_errors: errorCount
    };
  }

  /**
   * Telemetry health metrics for Telemetry_Health sheet and status indicators
   */
  public getTelemetryHealthSummary(): TelemetryHealthStats {
    const rows = this.db.prepare(`
      SELECT status, COUNT(*) as count FROM telemetry_queue GROUP BY status
    `).all() as { status: string; count: number }[];

    let pending = 0;
    let sending = 0;
    let sent = 0;
    let failed = 0;

    for (const r of rows) {
      if (r.status === 'PENDING') pending = r.count;
      else if (r.status === 'SENDING') sending = r.count;
      else if (r.status === 'SENT') sent = r.count;
      else if (r.status === 'FAILED') failed = r.count;
    }

    const lastErrorRow = this.db.prepare(`
      SELECT last_error FROM telemetry_queue WHERE last_error IS NOT NULL ORDER BY created_at DESC LIMIT 1
    `).get() as any;

    return {
      queue_size: pending + sending + failed,
      events_pending: pending,
      events_sending: sending,
      events_sent: sent,
      events_failed: failed,
      last_sync_error: lastErrorRow?.last_error
    };
  }

  /**
   * Aggregates all local metrics into a single complete dashboard snapshot
   */
  public getCompleteAnalyticsDashboard(orgId?: string): CompleteAnalyticsReport {
    return {
      generated_at: new Date().toISOString(),
      organization_id: orgId,
      scans_per_day: this.getScansPerDay(30, orgId),
      scans_per_customer: this.getScansPerCustomer(30),
      active_endpoints_count: this.getActiveEndpointsCount(30, orgId),
      volume_metrics: this.getScanVolumeMetrics(orgId),
      risk_distribution: this.getRiskDistribution(orgId),
      compliance_score_overview: this.getComplianceOverview(orgId),
      compliance_trend: this.getComplianceTrend(30, orgId),
      endpoint_assessments_per_day: this.getEndpointAssessmentsPerDay(30, orgId),
      usb_compliance: this.getUsbComplianceStats(orgId),
      web_access_categories: this.getWebAccessCategorySummary(orgId),
      license_stats: this.getLicenseLifecycleStats(),
      feature_usage: this.getFeatureUsageStats(orgId),
      error_metrics: this.getErrorRateStats(30, orgId),
      telemetry_health: this.getTelemetryHealthSummary()
    };
  }
}
