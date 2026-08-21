/**
 * FILE-SENTINEL — Phase T4 & T5 Unit Tests: Local Analytics Engine & Telemetry Health
 */

import assert from 'node:assert';
import { DatabaseSync } from 'node:sqlite';
import { getDatabase } from '../backend/db.js';
import { LocalAnalyticsService } from '../backend/telemetry/localAnalytics.js';

async function runLocalAnalyticsTests() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Phase T4 & T5 Local Analytics & Health Test Suite     ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const analyticsService = new LocalAnalyticsService(db);

  const orgA = 'org-corp-alpha';
  const orgB = 'org-corp-bravo';
  const now = new Date().toISOString();

  // Populate mock data into scans, endpoint_assessments, files, licenses
  db.exec(`
    INSERT INTO organizations (org_id, name, suspended, created_at) VALUES
      ('${orgA}', 'Alpha Corp', 0, '${now}'),
      ('${orgB}', 'Bravo Corp', 0, '${now}');

    INSERT INTO devices (device_id, org_id, device_name, registered_at) VALUES
      ('DEV-ALPHA-1', '${orgA}', 'Alpha Laptop 1', '${now}'),
      ('DEV-ALPHA-2', '${orgA}', 'Alpha Laptop 2', '${now}'),
      ('DEV-BRAVO-1', '${orgB}', 'Bravo Laptop 1', '${now}');

    INSERT INTO scans (
      scan_id, org_id, user_id, device_id, root_path,
      status, start_time, end_time, total_files, processed_files, error_count,
      critical_count, high_count, medium_count, low_count
    ) VALUES
      ('SCN-01', '${orgA}', 'usr-1', 'DEV-ALPHA-1', '/tmp', 'COMPLETED', datetime('now', '-2 days'), datetime('now', '-2 days', '+20 seconds'), 100, 100, 0, 1, 2, 3, 4),
      ('SCN-02', '${orgA}', 'usr-1', 'DEV-ALPHA-2', '/tmp', 'COMPLETED', datetime('now', '-1 days'), datetime('now', '-1 days', '+30 seconds'), 200, 200, 0, 0, 1, 1, 2),
      ('SCN-03', '${orgB}', 'usr-2', 'DEV-BRAVO-1', '/tmp', 'FAILED', datetime('now', '-1 days'), datetime('now', '-1 days', '+5 seconds'), 50, 10, 40, 0, 0, 0, 0);

    INSERT INTO endpoint_assessments (
      id, org_id, user_id, device_id, timestamp, created_at, platform, application_version, overall_status, summary_json
    ) VALUES
      ('ASSESS-01', '${orgA}', 'usr-1', 'DEV-ALPHA-1', datetime('now', '-2 days'), datetime('now', '-2 days'), 'win32', '1.0.0', 'COMPLIANT', '{"overall_score":95.0,"usb_status":"DISABLED","usb_storage_detected":false,"total_targets":21,"accessible_count":21,"blocked_count":0,"unreachable_count":0,"indeterminate_count":0}'),
      ('ASSESS-02', '${orgA}', 'usr-1', 'DEV-ALPHA-2', datetime('now', '-1 days'), datetime('now', '-1 days'), 'win32', '1.0.0', 'NON_COMPLIANT', '{"overall_score":65.0,"usb_status":"ENABLED","usb_storage_detected":true,"total_targets":21,"accessible_count":18,"blocked_count":2,"unreachable_count":1,"indeterminate_count":0}'),
      ('ASSESS-03', '${orgB}', 'usr-2', 'DEV-BRAVO-1', datetime('now', '-1 days'), datetime('now', '-1 days'), 'win32', '1.0.0', 'COMPLIANT', '{"overall_score":90.0,"usb_status":"DISABLED","usb_storage_detected":false,"total_targets":21,"accessible_count":20,"blocked_count":1,"unreachable_count":0,"indeterminate_count":0}');

    INSERT INTO telemetry_queue (
      id, event_id, event_type, schema_version, priority, payload_json, created_at, status
    ) VALUES
      ('TQ-1', 'EVT-1', 'SCAN_COMPLETED', 1, 'NORMAL', '{}', datetime('now', '-1 hours'), 'SENT'),
      ('TQ-2', 'EVT-2', 'SCAN_COMPLETED', 1, 'NORMAL', '{}', datetime('now', '-30 minutes'), 'PENDING'),
      ('TQ-3', 'EVT-3', 'ERROR', 1, 'HIGH', '{}', datetime('now', '-10 minutes'), 'FAILED');
  `);

  // Count records before to verify read-only guarantee
  const scansCountBefore = (db.prepare('SELECT COUNT(*) as count FROM scans').get() as any).count;
  const assessCountBefore = (db.prepare('SELECT COUNT(*) as count FROM endpoint_assessments').get() as any).count;

  // Test 1: Scans Per Day
  {
    const perDay = analyticsService.getScansPerDay(7);
    assert.ok(Array.isArray(perDay), 'Scans per day must be an array');
    const totalCount = perDay.reduce((acc, curr) => acc + curr.count, 0);
    assert.strictEqual(totalCount, 3, 'Total scans counted in perDay must equal 3');
    console.log('  [PASS] Test 1: Scans Per Day Aggregation');
  }

  // Test 2: Scans Per Customer (Org)
  {
    const perCust = analyticsService.getScansPerCustomer(7);
    assert.strictEqual(perCust.length, 2, 'Must return 2 organizations');
    const alpha = perCust.find(c => c.organization_id === orgA);
    const bravo = perCust.find(c => c.organization_id === orgB);
    assert.strictEqual(alpha?.scan_count, 2, 'Alpha must have 2 scans');
    assert.strictEqual(bravo?.scan_count, 1, 'Bravo must have 1 scan');
    console.log('  [PASS] Test 2: Scans Per Customer Aggregation');
  }

  // Test 3: Active Endpoints Count
  {
    const active = analyticsService.getActiveEndpointsCount(7);
    assert.strictEqual(active, 3, 'Must have 3 unique active endpoints');
    const activeAlpha = analyticsService.getActiveEndpointsCount(7, orgA);
    assert.strictEqual(activeAlpha, 2, 'Alpha has 2 active endpoints');
    console.log('  [PASS] Test 3: Active Endpoints Count Calculation');
  }

  // Test 4: Scan Duration and Volume Metrics
  {
    const vol = analyticsService.getScanVolumeMetrics();
    assert.strictEqual(vol.total_scans, 3);
    assert.strictEqual(vol.total_files_scanned, 350);
    assert.ok(vol.avg_duration_ms > 0, 'Average duration must be positive');
    console.log('  [PASS] Test 4: Scan Duration & Volume Metrics');
  }

  // Test 5: Risk Severity Distribution
  {
    const risk = analyticsService.getRiskDistribution();
    assert.strictEqual(risk.critical, 1, 'Critical findings must equal 1');
    assert.strictEqual(risk.high, 3, 'High findings must equal 3');
    assert.strictEqual(risk.medium, 4, 'Medium findings must equal 4');
    assert.strictEqual(risk.low, 6, 'Low findings must equal 6');
    assert.strictEqual(risk.total_findings, 14, 'Total findings must equal 14');
    console.log('  [PASS] Test 5: Risk Severity Distribution (Critical, High, Medium, Low)');
  }

  // Test 6: Compliance Overview & Trend
  {
    const overview = analyticsService.getComplianceOverview();
    assert.strictEqual(overview.total_assessments, 3);
    assert.ok(overview.avg_score > 80 && overview.avg_score < 90, 'Average compliance score calculated correctly');

    const trend = analyticsService.getComplianceTrend(7);
    assert.ok(trend.length >= 1, 'Compliance trend points returned');
    console.log('  [PASS] Test 6: Compliance Overview & Trend');
  }

  // Test 7: USB Compliance Percentage
  {
    const usb = analyticsService.getUsbComplianceStats();
    assert.strictEqual(usb.total_assessments, 3);
    assert.strictEqual(usb.compliant_disabled_count, 2);
    assert.strictEqual(usb.non_compliant_enabled_count, 1);
    assert.strictEqual(usb.compliance_percentage, 66.7);
    console.log('  [PASS] Test 7: USB Compliance Percentage Calculation');
  }

  // Test 8: Error Rate Statistics
  {
    const errStats = analyticsService.getErrorRateStats(7);
    assert.strictEqual(errStats.total_scans, 3);
    assert.strictEqual(errStats.failed_scans, 1);
    assert.strictEqual(errStats.error_rate_percentage, 33.33);
    assert.strictEqual(errStats.total_logged_errors, 1);
    console.log('  [PASS] Test 8: Error Rate Statistics (Failed Scans & Logged Errors)');
  }

  // Test 9: Telemetry Health Summary
  {
    const health = analyticsService.getTelemetryHealthSummary();
    assert.strictEqual(health.events_sent, 1);
    assert.strictEqual(health.events_pending, 1);
    assert.strictEqual(health.events_failed, 1);
    assert.strictEqual(health.queue_size, 2, 'Pending + Failed = 2 in active queue');
    console.log('  [PASS] Test 9: Telemetry Health Summary');
  }

  // Test 10: Complete Analytics Dashboard Snapshot & Read-Only Invariance
  {
    const dashboard = analyticsService.getCompleteAnalyticsDashboard();
    assert.ok(dashboard.generated_at, 'Snapshot must have generation timestamp');
    assert.strictEqual(dashboard.scans_per_customer.length, 2);
    assert.strictEqual(dashboard.active_endpoints_count, 3);

    // Verify Read-Only Guarantee: Scans and assessments counts unchanged
    const scansCountAfter = (db.prepare('SELECT COUNT(*) as count FROM scans').get() as any).count;
    const assessCountAfter = (db.prepare('SELECT COUNT(*) as count FROM endpoint_assessments').get() as any).count;

    assert.strictEqual(scansCountBefore, scansCountAfter, 'Local scans table must NOT be modified by analytics service');
    assert.strictEqual(assessCountBefore, assessCountAfter, 'Local endpoint_assessments table must NOT be modified by analytics service');
    console.log('  [PASS] Test 10: Complete Analytics Dashboard & Read-Only Invariance Guarantee');
  }

  console.log('\n========================================================================');
  console.log('  ALL 10/10 PHASE T4 & T5 LOCAL ANALYTICS TESTS PASSED (100% SUCCESS)  ');
  console.log('========================================================================\n');
}

runLocalAnalyticsTests().catch(err => {
  console.error('\n❌ Test failed:', err);
  process.exit(1);
});
