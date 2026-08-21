/**
 * FILE-SENTINEL — Phase T1: Telemetry Privacy & Data Sanitization Layer
 *
 * Enforcement Order:
 * Event
 *  → explicit event allowlist/schema filter
 *  → sensitive-data sanitizer (second defense layer)
 *  → payload-size validation
 *  → SQLite queue
 */

import crypto from 'node:crypto';
import os from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import {
  TelemetryEventType,
  TelemetryConfig,
  CURRENT_TELEMETRY_SCHEMA_VERSION,
  TelemetryPriority
} from './telemetryTypes.js';

export const MAX_EVENT_SIZE_BYTES = 64 * 1024; // 64 KB
export const MAX_METADATA_SIZE_BYTES = 8 * 1024; // 8 KB
export const MAX_BATCH_SIZE_BYTES = 1024 * 1024; // 1 MB
export const MAX_EVENTS_PER_BATCH = 50;
export const MAX_QUEUE_CAPACITY = 5000;
export const DEFAULT_LOCAL_RETENTION_DAYS = 30;

/**
 * Strict Allowlist: Only properties explicitly declared here may survive serialization.
 * Blacklist-only sanitization is strictly prohibited.
 */
export const EVENT_ALLOWED_FIELDS: Record<TelemetryEventType, Set<string>> = {
  SCAN_STARTED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'scan_id',
    'scan_type',
    'checklist_id',
    'checklist_version',
    'source_count',
    'offline_mode'
  ]),
  SCAN_COMPLETED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'machine_type',
    'OS',
    'OS_version',
    'architecture',
    'application_version',
    'license_id',
    'license_plan',
    'license_status',
    'license_days_remaining',
    'scan_id',
    'scan_type',
    'duration_ms',
    'source_count',
    'file_count',
    'files_processed',
    'files_skipped',
    'files_failed',
    'findings_count',
    'critical_count',
    'high_count',
    'medium_count',
    'low_count',
    'risk_score',
    'checklist_id',
    'checklist_version',
    'offline_mode'
  ]),
  SCAN_FAILED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'scan_id',
    'scan_type',
    'duration_ms',
    'error_code',
    'sanitized_error_category',
    'offline_mode'
  ]),
  ENDPOINT_ASSESSMENT_STARTED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'assessment_id',
    'platform'
  ]),
  ENDPOINT_ASSESSMENT_COMPLETED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'assessment_id',
    'OS',
    'machine_type',
    'usb_status',
    'usb_storage_detected',
    'social_media_accessible_count',
    'social_media_blocked_count',
    'social_media_unreachable_count',
    'social_media_indeterminate_count',
    'personal_email_accessible_count',
    'personal_email_blocked_count',
    'personal_email_unreachable_count',
    'personal_email_indeterminate_count',
    'messaging_accessible_count',
    'messaging_blocked_count',
    'messaging_unreachable_count',
    'messaging_indeterminate_count',
    'cloud_storage_accessible_count',
    'cloud_storage_blocked_count',
    'cloud_storage_unreachable_count',
    'cloud_storage_indeterminate_count',
    'total_targets_tested',
    'accessible_count',
    'blocked_count',
    'unreachable_count',
    'indeterminate_count',
    'overall_compliance_score',
    'assessment_duration_ms',
    // Per-target record fields when logged as target entry:
    'category',
    'target',
    'status',
    'confidence',
    'network_reachable',
    'policy_block_detected',
    'service_identity_confirmed',
    'response_time_ms',
    'probe_attempts',
    'reason_code'
  ]),
  LICENSE_ACTIVATED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'license_id',
    'plan',
    'status',
    'issued_at',
    'expires_at',
    'days_remaining',
    'device_count',
    'max_devices'
  ]),
  LICENSE_RENEWED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'license_id',
    'plan',
    'status',
    'issued_at',
    'expires_at',
    'days_remaining',
    'device_count',
    'max_devices'
  ]),
  LICENSE_EXPIRING: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'license_id',
    'plan',
    'status',
    'issued_at',
    'expires_at',
    'days_remaining',
    'device_count',
    'max_devices'
  ]),
  LICENSE_EXPIRED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'license_id',
    'plan',
    'status',
    'issued_at',
    'expires_at',
    'days_remaining',
    'device_count',
    'max_devices'
  ]),
  LICENSE_REVALIDATED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'license_id',
    'plan',
    'status',
    'issued_at',
    'expires_at',
    'days_remaining',
    'device_count',
    'max_devices'
  ]),
  APP_STARTED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'application_version',
    'OS',
    'OS_version',
    'machine_type',
    'architecture'
  ]),
  REPORT_GENERATED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'report_id',
    'scan_id',
    'report_type',
    'compliance_score'
  ]),
  CHECKLIST_ENABLED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'checklist_id',
    'checklist_version',
    'status'
  ]),
  CHECKLIST_DISABLED: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'checklist_id',
    'checklist_version',
    'status'
  ]),
  ERROR: new Set([
    'event_id',
    'event_type',
    'schema_version',
    'timestamp_utc',
    'installation_id',
    'organization_id',
    'device_id',
    'endpoint_id',
    'error_code',
    'error_category',
    'sanitized_message'
  ])
};

/**
 * Known sensitive tokens and path patterns to sanitize
 */
const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /jwt/i,
  /bearer/i,
  /cookie/i,
  /api[_-]?key/i,
  /private[_-]?key/i,
  /credential/i,
  /ocr/i,
  /content/i,
  /extracted_text/i,
  /file_path/i,
  /full_path/i,
  /filename/i,
  /history/i,
  /screenshot/i,
  /mac_address/i,
  /bios/i,
  /motherboard/i,
  /serial/i
];

/**
 * Sanitizes any raw string or nested structure by redacting file paths, tokens, and PII.
 */
export function sanitizeString(val: string): string {
  if (!val || typeof val !== 'string') return '';

  let sanitized = val;

  // Redact Windows absolute file paths (e.g. C:\Users\Alice\...)
  sanitized = sanitized.replace(/[a-zA-Z]:\\[^ \r\n\t:;,"']+/g, '[REDACTED_PATH]');

  // Redact Unix absolute file paths (e.g. /home/alice/..., /Users/alice/...)
  sanitized = sanitized.replace(/\/(home|Users|var|tmp|etc|usr|opt)\/[^ \r\n\t:;,"']+/g, '[REDACTED_PATH]');

  // Redact JWT tokens
  sanitized = sanitized.replace(/eyJ[a-zA-Z0-9_-]{3,}\.[a-zA-Z0-9_-]{3,}(\.[a-zA-Z0-9_-]*)?/g, '[REDACTED_JWT]');

  // Redact emails
  sanitized = sanitized.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]');

  return sanitized;
}

/**
 * Filter an event object through the strict schema allowlist and sanitization layer.
 * Any field not in the allowlist is completely removed.
 */
export function filterAndSanitizeEvent(rawEvent: Record<string, any>): Record<string, any> | null {
  if (!rawEvent || typeof rawEvent !== 'object') {
    return null;
  }

  const eventType = rawEvent.event_type as TelemetryEventType;
  const allowedSet = EVENT_ALLOWED_FIELDS[eventType];
  if (!allowedSet) {
    return null; // Unknown or unpermitted event type
  }

  const filtered: Record<string, any> = {};

  for (const key of Object.keys(rawEvent)) {
    if (!allowedSet.has(key)) {
      continue; // Drop unpermitted property (Allowlist enforcement)
    }

    // Check sensitive key patterns as second defense layer
    if (SENSITIVE_KEY_PATTERNS.some(pat => pat.test(key))) {
      // Allow only harmless metadata fields if in allowlist
      if (key !== 'error_code' && key !== 'error_category') {
        continue;
      }
    }

    const val = rawEvent[key];

    if (val === undefined || val === null) {
      continue;
    }

    if (typeof val === 'string') {
      filtered[key] = sanitizeString(val);
    } else if (typeof val === 'number' || typeof val === 'boolean') {
      filtered[key] = val;
    } else if (typeof val === 'object') {
      // If object, serialize and cap
      const jsonStr = JSON.stringify(val);
      if (jsonStr.length <= MAX_METADATA_SIZE_BYTES) {
        filtered[key] = sanitizeString(jsonStr);
      }
    }
  }

  // Ensure mandatory envelope fields are present
  const mandatory = ['event_id', 'event_type', 'schema_version', 'timestamp_utc', 'installation_id', 'organization_id', 'device_id', 'endpoint_id'];
  for (const m of mandatory) {
    if (!filtered[m]) {
      return null; // Invalid schema envelope
    }
  }

  // Payload size enforcement
  const serialized = JSON.stringify(filtered);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_EVENT_SIZE_BYTES) {
    return null; // Oversized event rejected
  }

  return filtered;
}

/**
 * Derives a stable, pseudonymous endpoint_id using HMAC-SHA256.
 * Guarantees zero transmission of raw hardware serials, MAC addresses, or BIOS IDs.
 */
export function generateEndpointId(rawDeviceId: string, installationSecret: string): string {
  const cleanInput = (rawDeviceId || os.hostname() || 'default-host').trim();
  const secret = (installationSecret || 'filesentinel-default-salt').trim();
  const hmac = crypto.createHmac('sha256', secret).update(cleanInput).digest('hex');
  return `EP-${hmac.substring(0, 16).toUpperCase()}`;
}

/**
 * Gets or creates the local installation_id and installation_secret from database.
 */
export function getOrCreateInstallationIdentity(db: DatabaseSync): {
  installationId: string;
  installationSecret: string;
} {
  db.exec(`
    CREATE TABLE IF NOT EXISTS system_identity (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  const now = new Date().toISOString();

  let idRow = db.prepare('SELECT value FROM system_identity WHERE key = ?').get('installation_id') as any;
  if (!idRow) {
    const newId = `INST-${crypto.randomUUID()}`;
    db.prepare('INSERT INTO system_identity (key, value, created_at) VALUES (?, ?, ?)').run('installation_id', newId, now);
    idRow = { value: newId };
  }

  let secretRow = db.prepare('SELECT value FROM system_identity WHERE key = ?').get('installation_secret') as any;
  if (!secretRow) {
    const newSecret = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO system_identity (key, value, created_at) VALUES (?, ?, ?)').run('installation_secret', newSecret, now);
    secretRow = { value: newSecret };
  }

  return {
    installationId: idRow.value,
    installationSecret: secretRow.value
  };
}

/**
 * Default telemetry configuration
 */
export function getTelemetryConfig(): TelemetryConfig {
  const env = (process.env.NODE_ENV || 'development').toLowerCase();
  const isProd = env === 'production';

  return {
    enabled: process.env.TELEMETRY_ENABLED !== undefined
      ? process.env.TELEMETRY_ENABLED === 'true' || process.env.TELEMETRY_ENABLED === '1'
      : false, // Default false in dev/test, configurable in prod
    collectIp: process.env.TELEMETRY_COLLECT_IP === 'true',
    collectGeo: process.env.TELEMETRY_COLLECT_GEO === 'true',
    localRetentionDays: parseInt(process.env.TELEMETRY_LOCAL_RETENTION_DAYS || '30', 10) || DEFAULT_LOCAL_RETENTION_DAYS,
    environment: (process.env.TELEMETRY_ENVIRONMENT as any) || (isProd ? 'production' : (env === 'test' ? 'test' : 'development')),
    maxQueueSize: MAX_QUEUE_CAPACITY,
    maxEventSizeBytes: MAX_EVENT_SIZE_BYTES,
    maxMetadataSizeBytes: MAX_METADATA_SIZE_BYTES,
    maxBatchSizeBytes: MAX_BATCH_SIZE_BYTES,
    maxEventsPerBatch: MAX_EVENTS_PER_BATCH,
    ingestionUrl: process.env.TELEMETRY_INGESTION_URL,
    ingestionSecret: process.env.TELEMETRY_INGESTION_SECRET
  };
}

/**
 * Maps an event type to its default priority for queue retention and eviction.
 */
export function getEventPriority(eventType: TelemetryEventType): TelemetryPriority {
  switch (eventType) {
    case 'LICENSE_ACTIVATED':
    case 'LICENSE_RENEWED':
    case 'LICENSE_EXPIRED':
    case 'ERROR':
      return 'HIGH';
    case 'SCAN_COMPLETED':
    case 'ENDPOINT_ASSESSMENT_COMPLETED':
    case 'REPORT_GENERATED':
      return 'NORMAL';
    case 'SCAN_STARTED':
    case 'ENDPOINT_ASSESSMENT_STARTED':
    case 'APP_STARTED':
    case 'CHECKLIST_ENABLED':
    case 'CHECKLIST_DISABLED':
    case 'LICENSE_EXPIRING':
    case 'LICENSE_REVALIDATED':
    case 'SCAN_FAILED':
    default:
      return 'LOW';
  }
}
