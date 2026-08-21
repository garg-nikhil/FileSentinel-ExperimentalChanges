/**
 * FILE-SENTINEL — Production Google Apps Script Telemetry Ingestion Web App
 *
 * Deployment Target: Google Apps Script bound to the "FileSentinel Telemetry & Analytics" Google Spreadsheet.
 * Web App Access:
 *   - Execute as: "Me" (your Google Workspace account)
 *   - Who has access: "Anyone"
 *
 * Security & Reliability Controls:
 *   1. Body-Enclosed HMAC-SHA256 Signature Verification via Script Properties ('TELEMETRY_INGESTION_SECRET')
 *   2. Timestamp Freshness Window (rejects requests older/newer than 5 minutes)
 *   3. Nonce Replay Attack Prevention via CacheService
 *   4. Maximum 50 events per batch & 1 MB payload size limit
 *   5. Robust Deduplication by event_id across retry cycles
 *   6. Dynamic Case-Insensitive Header Mapping (supports snake_case, camelCase, PascalCase)
 *   7. Telemetry_Health records telemetry sync status using the exact 10-column schema
 *   8. Zero Logging of Secrets, Passwords, Keys, File Contents, Paths, or OCR Text
 */

// Configuration Constants
var MAX_BATCH_EVENTS = 50;
var MAX_PAYLOAD_BYTES = 1048576; // 1 MB
var TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000; // 5 minutes
var NONCE_EXPIRY_SECONDS = 600; // 10 minutes

// Existing Standard Schema Headers for Auto-Initialization
var DEFAULT_HEADERS = {
  'Scans': [
    'Event_ID', 'scan_id', 'Timestamp_UTC', 'Organization_ID', 'device_id', 'endpoint_id',
    'user_id', 'machine_type', 'OS', 'OS_version', 'application_version', 'license_id',
    'license_plan', 'license_status', 'license_days_remaining', 'scan_type', 'duration_ms',
    'source_count', 'file_count', 'files_processed', 'files_skipped', 'files_failed',
    'findings_count', 'critical_count', 'high_count', 'medium_count', 'low_count',
    'risk_score', 'checklist_id', 'checklist_version', 'offline_mode', 'started_at', 'completed_at'
  ],
  'Endpoint_Compliance': [
    'event_id', 'assessment_id', 'timestamp_utc', 'organization_id', 'device_id', 'endpoint_id',
    'user_id', 'machine_type', 'OS', 'OS_version', 'application_version', 'license_id',
    'license_plan', 'assessment_duration_ms', 'overall_compliance_score', 'usb_status',
    'usb_storage_detected', 'usb_remediation_status', 'social_media_accessible_count',
    'social_media_blocked_count', 'social_media_unreachable_count', 'social_media_indeterminate_count',
    'personal_email_accessible_count', 'personal_email_blocked_count', 'personal_email_unreachable_count',
    'personal_email_indeterminate_count', 'messaging_accessible_count', 'messaging_blocked_count',
    'messaging_unreachable_count', 'messaging_indeterminate_count', 'cloud_storage_accessible_count',
    'cloud_storage_blocked_count', 'cloud_storage_unreachable_count', 'cloud_storage_indeterminate_count',
    'total_targets_tested', 'accessible_count', 'blocked_count', 'unreachable_count', 'indeterminate_count'
  ],
  'Endpoint_Targets': [
    'event_id', 'assessment_id', 'timestamp_utc', 'organization_id', 'device_id', 'endpoint_id',
    'category', 'target', 'status', 'confidence', 'network_reachable', 'policy_block_detected',
    'service_identity_confirmed', 'response_time_ms', 'probe_attempts', 'reason_code'
  ],
  'License_Events': [
    'event_id', 'timestamp_utc', 'organization_id', 'device_id', 'license_id', 'plan',
    'event_type', 'license_status', 'issued_at', 'expires_at', 'days_remaining',
    'device_count', 'max_devices', 'activation_type', 'renewal_type', 'application_version'
  ],
  'App_Events': [
    'event_id', 'timestamp_utc', 'organization_id', 'device_id', 'endpoint_id', 'user_id',
    'event_type', 'application_version', 'OS', 'machine_type', 'license_plan', 'metadata_json'
  ],
  'Errors': [
    'event_id', 'timestamp_utc', 'organization_id', 'device_id', 'endpoint_id', 'application_version',
    'OS', 'component', 'error_code', 'error_category', 'severity', 'recoverable', 'operation', 'message_safe'
  ],
  'Telemetry_Health': [
    'timestamp_utc',
    'endpoint_id',
    'application_version',
    'queue_size',
    'events_pending',
    'events_sent',
    'events_failed',
    'last_successful_sync',
    'last_sync_error',
    'sync_duration_ms'
  ]
};

/**
 * Normalizes a header or key string for case-insensitive and format-agnostic matching.
 * Examples: 'timestamp_utc', 'Timestamp_UTC', 'timestampUtc' all map to 'timestamputc'.
 */
function normalizeKey(str) {
  if (!str) return '';
  return String(str).toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Health check GET handler
 */
function doGet(e) {
  return createJsonResponse(200, {
    service: "FileSentinel Telemetry Ingestion",
    status: "online",
    accepts: "POST"
  });
}

/**
 * Main Web App POST Handler with Body-Enclosed Authentication
 */
function doPost(e) {
  var startTime = new Date().getTime();

  try {
    if (!e || !e.postData || !e.postData.contents) {
      return createJsonResponse(400, { success: false, error: 'Empty or invalid request payload' });
    }

    var requestBody = e.postData.contents;
    if (requestBody.length > MAX_PAYLOAD_BYTES) {
      return createJsonResponse(413, { success: false, error: 'Payload exceeds maximum allowable size (1 MB)' });
    }

    // 1. Parse JSON Body
    var data = null;
    try {
      data = JSON.parse(requestBody);
    } catch (parseErr) {
      return createJsonResponse(400, { success: false, error: 'Malformed JSON in request payload' });
    }

    if (!data || typeof data !== 'object') {
      return createJsonResponse(400, { success: false, error: 'Invalid payload structure: Root object required' });
    }

    // 2. Extract and Validate Authentication Object
    if (!data.auth || typeof data.auth !== 'object') {
      return createJsonResponse(401, { success: false, error: 'Missing mandatory "auth" authentication object in request body' });
    }

    var timestamp = data.auth.timestamp;
    var nonce = data.auth.nonce;
    var signature = data.auth.signature;

    if (!timestamp || !nonce || !signature) {
      return createJsonResponse(401, { success: false, error: 'Missing timestamp, nonce, or signature in auth object' });
    }

    // 3. Validate Timestamp Freshness (Anti-Replay Window)
    var reqTime = parseInt(timestamp, 10);
    var now = new Date().getTime();
    if (isNaN(reqTime) || Math.abs(now - reqTime) > TIMESTAMP_TOLERANCE_MS) {
      return createJsonResponse(401, { success: false, error: 'Request timestamp is outside the valid 5-minute freshness window' });
    }

    // 4. Validate Nonce (Replay Attack Defense)
    var cache = CacheService.getScriptCache();
    var nonceKey = 'fs_nonce_' + nonce;
    if (cache.get(nonceKey)) {
      return createJsonResponse(403, { success: false, error: 'Duplicate nonce detected: Request replay rejected' });
    }
    cache.put(nonceKey, '1', NONCE_EXPIRY_SECONDS);

    // 5. Verify HMAC-SHA256 Signature using Deterministic Canonical Payload
    var scriptProperties = PropertiesService.getScriptProperties();
    var secret = scriptProperties.getProperty('TELEMETRY_INGESTION_SECRET');
    if (!secret) {
      return createJsonResponse(500, { success: false, error: 'Server configuration error: Ingestion secret not configured' });
    }

    var canonicalData = JSON.stringify({
      batch_id: data.batch_id,
      sent_at: data.sent_at,
      environment: data.environment,
      schema_version: data.schema_version,
      events: data.events
    });

    var canonicalPayload = timestamp + ':' + nonce + ':' + canonicalData;
    var expectedSignature = computeHmacSha256(secret, canonicalPayload);

    if (expectedSignature.toLowerCase() !== String(signature).toLowerCase()) {
      return createJsonResponse(403, { success: false, error: 'Invalid HMAC signature: Authentication failed' });
    }

    // 6. Validate Events Batch
    if (!data.events || !Array.isArray(data.events)) {
      return createJsonResponse(400, { success: false, error: 'Invalid body: "events" array is required' });
    }

    if (data.events.length > MAX_BATCH_EVENTS) {
      return createJsonResponse(400, { success: false, error: 'Batch exceeds maximum limit of 50 events' });
    }

    // 7. Ingest Events into Spreadsheets
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) {
      return createJsonResponse(500, { success: false, error: 'Active spreadsheet not accessible: Script must be bound to spreadsheet' });
    }

    var result = processBatchEvents(ss, data.events, cache);
    var durationMs = new Date().getTime() - startTime;

    // 8. Record Ingestion Heartbeat in Telemetry_Health (ONLY after auth/validation succeeds)
    var firstEvt = data.events[0] || {};
    recordHealthHeartbeat(ss, {
      timestamp_utc: new Date().toISOString(),
      endpoint_id: firstEvt.endpoint_id || firstEvt.device_id || 'dev-default',
      application_version: firstEvt.application_version || '8.2.0',
      queue_size: data.events.length,
      events_pending: result.duplicates,
      events_sent: result.processed,
      events_failed: result.failed,
      last_successful_sync: result.processed > 0 ? new Date().toISOString() : '',
      last_sync_error: result.errors.length > 0 ? result.errors.slice(0, 2).join('; ') : '',
      sync_duration_ms: durationMs
    });

    // 9. Return Explicit Success/Failure Response
    if (result.failed > 0 && result.processed === 0) {
      return createJsonResponse(500, {
        success: false,
        processed_count: result.processed,
        duplicates_count: result.duplicates,
        failed_count: result.failed,
        error: result.errors[0] || 'Batch processing failed'
      });
    }

    return createJsonResponse(200, {
      success: true,
      processed_count: result.processed,
      duplicates_count: result.duplicates,
      failed_count: result.failed,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    return createJsonResponse(500, {
      success: false,
      error: err.message || 'Internal ingestion failure'
    });
  }
}

/**
 * Process and dispatch a batch of events to appropriate Google Sheets tabs
 */
function processBatchEvents(ss, events, cache) {
  var processed = 0;
  var duplicates = 0;
  var failed = 0;
  var errors = [];
  var diagnostics = [];

  for (var i = 0; i < events.length; i++) {
    var evt = events[i];
    if (!evt || !evt.event_id || !evt.event_type) {
      failed++;
      errors.push('Malformed event at index ' + i + ': missing event_id or event_type');
      diagnostics.push({ success: false, error: 'Malformed event' });
      continue;
    }

    // Deduplication by event_id using Script Cache (7 days retention)
    var cacheKey = 'fs_evt_' + evt.event_id;
    if (cache && cache.get(cacheKey)) {
      duplicates++;
      diagnostics.push({ success: true, duplicate: true, event_id: evt.event_id });
      continue;
    }

    try {
      var diag = routeEventToSheet(ss, evt);
      diagnostics.push(diag);
      if (diag && diag.success) {
        if (cache) cache.put(cacheKey, '1', 86400 * 7);
        processed++;
      } else {
        failed++;
        errors.push('Failed to route event ' + evt.event_id + (diag && diag.error ? ': ' + diag.error : ''));
      }
    } catch (routeErr) {
      failed++;
      errors.push('Error routing event ' + evt.event_id + ': ' + routeErr.message);
      diagnostics.push({ success: false, error: routeErr.message });
    }
  }

  return {
    processed: processed,
    duplicates: duplicates,
    failed: failed,
    errors: errors,
    diagnostics: diagnostics
  };
}

/**
 * Routes an individual event payload to the target sheet based on event_type.
 * Returns structured diagnostic info including sheet name and row counts.
 */
function routeEventToSheet(ss, evt) {
  var type = evt.event_type;
  var targetSheet = 'App_Events';

  if (type === 'SCAN_COMPLETED') {
    targetSheet = 'Scans';
  } else if (type === 'ENDPOINT_ASSESSMENT_COMPLETED') {
    targetSheet = evt.target ? 'Endpoint_Targets' : 'Endpoint_Compliance';
  } else if (type && type.indexOf('LICENSE_') === 0) {
    targetSheet = 'License_Events';
  } else if (type === 'APP_STARTED') {
    targetSheet = 'App_Events';
  } else if (type === 'ERROR') {
    targetSheet = 'Errors';
  }

  return appendRow(ss, targetSheet, evt);
}

/**
 * Appends a row to target sheet using dynamic header-based mapping.
 * Reads row 1 headers, matches normalized keys, and places values in correct columns.
 * Returns structured diagnostic result.
 */
function appendRow(ss, sheetName, eventData) {
  var sheet = ss.getSheetByName(sheetName);

  // Initialize sheet with default headers if not present
  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
    var defaultHeaders = DEFAULT_HEADERS[sheetName] || ['Event_ID', 'Timestamp_UTC', 'Event_Type'];
    sheet.appendRow(defaultHeaders);
  }

  // Read existing headers from row 1
  var lastCol = sheet.getLastColumn();
  if (lastCol === 0) {
    var defaultHeaders = DEFAULT_HEADERS[sheetName] || ['Event_ID', 'Timestamp_UTC', 'Event_Type'];
    sheet.appendRow(defaultHeaders);
    lastCol = defaultHeaders.length;
  }

  var lastRowBefore = sheet.getLastRow();
  var headerRange = sheet.getRange(1, 1, 1, lastCol);
  var headerValues = headerRange.getValues()[0];

  // Build normalized lookup map from eventData
  var eventNormalizedMap = {};
  for (var key in eventData) {
    if (Object.prototype.hasOwnProperty.call(eventData, key)) {
      eventNormalizedMap[normalizeKey(key)] = eventData[key];
    }
  }

  // Construct row array matching header order
  var row = [];
  for (var c = 0; c < headerValues.length; c++) {
    var rawHeader = headerValues[c];
    var normHeader = normalizeKey(rawHeader);
    var val = eventNormalizedMap[normHeader];

    if (val === undefined || val === null) {
      row.push('');
    } else if (typeof val === 'boolean') {
      row.push(val ? 'TRUE' : 'FALSE');
    } else if (typeof val === 'object') {
      row.push(JSON.stringify(val));
    } else {
      row.push(val);
    }
  }

  sheet.appendRow(row);
  var lastRowAfter = sheet.getLastRow();

  return {
    success: (lastRowAfter > lastRowBefore),
    sheet: sheetName,
    row_written: (lastRowAfter > lastRowBefore),
    last_row_before: lastRowBefore,
    last_row_after: lastRowAfter
  };
}

/**
 * Records heartbeat into Telemetry_Health sheet matching the exact 10 columns:
 * [timestamp_utc, endpoint_id, application_version, queue_size, events_pending,
 *  events_sent, events_failed, last_successful_sync, last_sync_error, sync_duration_ms]
 */
function recordHealthHeartbeat(ss, healthData) {
  try {
    return appendRow(ss, 'Telemetry_Health', healthData);
  } catch (err) {
    // Health logging error should never throw or block
    return { success: false, error: err.message };
  }
}

/**
 * Computes HMAC-SHA256 hex string in Google Apps Script
 */
function computeHmacSha256(key, message) {
  var rawBytes = Utilities.computeHmacSha256Signature(message, key);
  var hex = '';
  for (var i = 0; i < rawBytes.length; i++) {
    var byteVal = (rawBytes[i] < 0) ? rawBytes[i] + 256 : rawBytes[i];
    var hexByte = byteVal.toString(16);
    if (hexByte.length === 1) hexByte = '0' + hexByte;
    hex += hexByte;
  }
  return hex;
}

/**
 * Constructs JSON response for Web App execution
 */
function createJsonResponse(statusCode, payload) {
  return ContentService.createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Diagnostic Verification Function
 * Run this directly in the Google Apps Script IDE to verify all required functions are present.
 */
function diagnoseFunctions() {
  var requiredFunctions = [
    'doGet',
    'doPost',
    'routeEventToSheet',
    'appendRow',
    'processBatchEvents',
    'recordHealthHeartbeat',
    'computeHmacSha256'
  ];

  var results = {};
  var allPresent = true;

  for (var i = 0; i < requiredFunctions.length; i++) {
    var fnName = requiredFunctions[i];
    var exists = typeof this[fnName] === 'function';
    results[fnName] = exists ? 'PRESENT' : 'MISSING';
    if (!exists) allPresent = false;
  }

  Logger.log('=== FILE-SENTINEL APPS SCRIPT FUNCTION DIAGNOSTIC ===');
  Logger.log(JSON.stringify(results, null, 2));
  Logger.log('Overall Status: ' + (allPresent ? 'ALL FUNCTIONS VERIFIED' : 'FAILURES DETECTED'));

  return {
    status: allPresent ? 'ALL_FUNCTIONS_VERIFIED' : 'MISSING_FUNCTIONS',
    functions: results
  };
}

/**
 * Test Scan Insertion Function
 * Run this directly in the Google Apps Script IDE to verify header mapping and live sheet writing.
 */
function testScanInsertion() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) {
    Logger.log('ERROR: No active spreadsheet. Script must be bound to the FileSentinel Google Sheet.');
    return { success: false, error: 'No active spreadsheet' };
  }

  var testEvent = {
    event_id: 'TEST-EVT-' + Math.random().toString(36).substring(2, 10),
    event_type: 'SCAN_COMPLETED',
    scan_id: 'TEST-SCAN-VERIFICATION',
    timestamp_utc: new Date().toISOString(),
    organization_id: 'org-test-verification',
    device_id: 'dev-test-verification',
    endpoint_id: 'end-test-verification',
    user_id: 'user-test-verification',
    machine_type: 'Laptop (Verification)',
    OS: 'Windows',
    OS_version: '11 Pro',
    application_version: '8.2.0',
    license_id: 'LIC-TEST-VERIFY',
    license_plan: 'Enterprise',
    license_status: 'ACTIVE',
    license_days_remaining: 365,
    scan_type: 'FULL_AUDIT',
    duration_ms: 1250,
    source_count: 1,
    file_count: 50,
    files_processed: 50,
    files_skipped: 0,
    files_failed: 0,
    findings_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    risk_score: 0,
    checklist_id: 'CHECKLIST-RBI-2026',
    checklist_version: '2026.1',
    offline_mode: false,
    started_at: new Date(Date.now() - 1250).toISOString(),
    completed_at: new Date().toISOString()
  };

  Logger.log('Inserting test event into Scans sheet...');
  var diag = appendRow(ss, 'Scans', testEvent);
  Logger.log('testScanInsertion result: ' + JSON.stringify(diag));

  return {
    success: diag.success,
    diagnostic: diag,
    test_event_id: testEvent.event_id,
    destination_sheet: 'Scans',
    timestamp: new Date().toISOString()
  };
}
