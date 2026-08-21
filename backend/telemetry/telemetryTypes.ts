/**
 * FILE-SENTINEL — Phase T1: Local-First Telemetry Type Definitions
 * Strict explicit schema definitions for privacy-preserving event telemetry.
 */

export type TelemetryEventType =
  | 'SCAN_STARTED'
  | 'SCAN_COMPLETED'
  | 'SCAN_FAILED'
  | 'ENDPOINT_ASSESSMENT_STARTED'
  | 'ENDPOINT_ASSESSMENT_COMPLETED'
  | 'LICENSE_ACTIVATED'
  | 'LICENSE_RENEWED'
  | 'LICENSE_EXPIRING'
  | 'LICENSE_EXPIRED'
  | 'LICENSE_REVALIDATED'
  | 'APP_STARTED'
  | 'REPORT_GENERATED'
  | 'CHECKLIST_ENABLED'
  | 'CHECKLIST_DISABLED'
  | 'ERROR';

export type TelemetryPriority = 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW';

export type TelemetryQueueStatus = 'PENDING' | 'SENDING' | 'SENT' | 'FAILED';

export const CURRENT_TELEMETRY_SCHEMA_VERSION = 1;

/**
 * Base envelope mandatory for every telemetry event.
 */
export interface BaseTelemetryEvent {
  event_id: string;
  event_type: TelemetryEventType;
  schema_version: number;
  timestamp_utc: string;
  installation_id: string;
  organization_id: string;
  device_id: string;
  endpoint_id: string;
}

/**
 * SCAN_STARTED Payload
 */
export interface ScanStartedPayload extends BaseTelemetryEvent {
  event_type: 'SCAN_STARTED';
  scan_id: string;
  scan_type: string;
  checklist_id?: string;
  checklist_version?: string;
  source_count: number;
  offline_mode: boolean;
}

/**
 * SCAN_COMPLETED Payload
 */
export interface ScanCompletedPayload extends BaseTelemetryEvent {
  event_type: 'SCAN_COMPLETED';
  machine_type: string;
  OS: string;
  OS_version: string;
  architecture: string;
  application_version: string;

  license_id?: string;
  license_plan?: string;
  license_status?: string;
  license_days_remaining?: number;

  scan_id: string;
  scan_type: string;
  duration_ms: number;

  source_count: number;
  file_count: number;
  files_processed: number;
  files_skipped: number;
  files_failed: number;

  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  risk_score: number;

  checklist_id?: string;
  checklist_version?: string;
  offline_mode: boolean;
}

/**
 * SCAN_FAILED Payload
 */
export interface ScanFailedPayload extends BaseTelemetryEvent {
  event_type: 'SCAN_FAILED';
  scan_id: string;
  scan_type: string;
  duration_ms: number;
  error_code: string;
  sanitized_error_category: string;
  offline_mode: boolean;
}

/**
 * ENDPOINT_ASSESSMENT_STARTED Payload
 */
export interface EndpointAssessmentStartedPayload extends BaseTelemetryEvent {
  event_type: 'ENDPOINT_ASSESSMENT_STARTED';
  assessment_id: string;
  platform: string;
}

/**
 * ENDPOINT_ASSESSMENT_COMPLETED Payload
 */
export interface EndpointAssessmentCompletedPayload extends BaseTelemetryEvent {
  event_type: 'ENDPOINT_ASSESSMENT_COMPLETED';
  assessment_id: string;
  OS: string;
  machine_type: string;

  usb_status: string;
  usb_storage_detected: boolean;

  social_media_accessible_count: number;
  social_media_blocked_count: number;
  social_media_unreachable_count: number;
  social_media_indeterminate_count: number;

  personal_email_accessible_count: number;
  personal_email_blocked_count: number;
  personal_email_unreachable_count: number;
  personal_email_indeterminate_count: number;

  messaging_accessible_count: number;
  messaging_blocked_count: number;
  messaging_unreachable_count: number;
  messaging_indeterminate_count: number;

  cloud_storage_accessible_count: number;
  cloud_storage_blocked_count: number;
  cloud_storage_unreachable_count: number;
  cloud_storage_indeterminate_count: number;

  total_targets_tested: number;
  accessible_count: number;
  blocked_count: number;
  unreachable_count: number;
  indeterminate_count: number;

  overall_compliance_score: number;
  assessment_duration_ms: number;
}

/**
 * Endpoint Target Compliance Probe Result (Endpoint_Targets Sheet)
 */
export interface EndpointTargetTelemetryPayload extends BaseTelemetryEvent {
  event_type: 'ENDPOINT_ASSESSMENT_COMPLETED';
  assessment_id: string;
  category: string;
  target: string;
  status: string;
  confidence: string;

  network_reachable: boolean;
  policy_block_detected: boolean;
  service_identity_confirmed: boolean;

  response_time_ms: number;
  probe_attempts: number;
  reason_code: string;
}

/**
 * LICENSE_* Payload
 */
export interface LicenseEventPayload extends BaseTelemetryEvent {
  event_type:
    | 'LICENSE_ACTIVATED'
    | 'LICENSE_RENEWED'
    | 'LICENSE_EXPIRING'
    | 'LICENSE_EXPIRED'
    | 'LICENSE_REVALIDATED';
  license_id: string;
  plan: string;
  status: string;
  issued_at: string;
  expires_at: string;
  days_remaining: number;
  device_count: number;
  max_devices: number;
}

/**
 * APP_STARTED Payload
 */
export interface AppStartedPayload extends BaseTelemetryEvent {
  event_type: 'APP_STARTED';
  application_version: string;
  OS: string;
  OS_version: string;
  machine_type: string;
  architecture: string;
}

/**
 * REPORT_GENERATED Payload
 */
export interface ReportGeneratedPayload extends BaseTelemetryEvent {
  event_type: 'REPORT_GENERATED';
  report_id: string;
  scan_id: string;
  report_type: string;
  compliance_score: number;
}

/**
 * CHECKLIST_ENABLED / CHECKLIST_DISABLED Payload
 */
export interface ChecklistTogglePayload extends BaseTelemetryEvent {
  event_type: 'CHECKLIST_ENABLED' | 'CHECKLIST_DISABLED';
  checklist_id: string;
  checklist_version: string;
  status: 'ENABLED' | 'DISABLED';
}

/**
 * ERROR Payload
 */
export interface ErrorEventPayload extends BaseTelemetryEvent {
  event_type: 'ERROR';
  error_code: string;
  error_category: string;
  sanitized_message: string;
}

export type TelemetryEventPayload =
  | ScanStartedPayload
  | ScanCompletedPayload
  | ScanFailedPayload
  | EndpointAssessmentStartedPayload
  | EndpointAssessmentCompletedPayload
  | LicenseEventPayload
  | AppStartedPayload
  | ReportGeneratedPayload
  | ChecklistTogglePayload
  | ErrorEventPayload;

/**
 * SQLite Local Telemetry Queue Record
 */
export interface TelemetryQueueRecord {
  id: string;
  event_id: string;
  event_type: TelemetryEventType;
  schema_version: number;
  priority: TelemetryPriority;
  payload_json: string;
  created_at: string;
  attempt_count: number;
  next_attempt_at?: string;
  status: TelemetryQueueStatus;
  locked_at?: string;
  last_error?: string;
}

/**
 * Telemetry Configuration
 */
export interface TelemetryConfig {
  enabled: boolean;
  collectIp: boolean;
  collectGeo: boolean;
  localRetentionDays: number;
  environment: 'development' | 'test' | 'production';
  maxQueueSize: number;
  maxEventSizeBytes: number;
  maxMetadataSizeBytes: number;
  maxBatchSizeBytes: number;
  maxEventsPerBatch: number;
  ingestionUrl?: string;
  ingestionSecret?: string;
}

export interface TelemetryHealthStats {
  queue_size: number;
  events_pending: number;
  events_sending: number;
  events_sent: number;
  events_failed: number;
  last_successful_sync?: string;
  last_sync_error?: string;
  sync_duration_ms?: number;
}
