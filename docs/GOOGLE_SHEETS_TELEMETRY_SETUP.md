# Google Sheets Telemetry Setup Guide for FileSentinel

This guide details how to create and configure a private Google Sheets telemetry backend and Google Apps Script ingestion endpoint for FileSentinel.

---

## 1. Overview & Architecture

FileSentinel uses a **local-first** telemetry architecture:
1. Local operations (scanning, endpoint assessment, licensing, audits) record privacy-filtered events to an encrypted local SQLite queue.
2. An asynchronous background sync engine batches events (max 50) and transmits them to a Google Apps Script Web App.
3. Requests are authenticated using **HMAC-SHA256**, fresh timestamps (< 5 min), and unique nonces for replay attack prevention.
4. Google Sheets acts as a downstream analytics store and is **never** required for scanning or local operations.

---

## 2. Step-by-Step Setup

### Step 1: Create the Google Spreadsheet
1. Open [Google Sheets](https://sheets.new) in your organizational Google Workspace account.
2. Name the spreadsheet: `FileSentinel Telemetry & Analytics`.
3. Create the following required tabs (sheets):
   - `Scans`
   - `Endpoint_Compliance`
   - `Endpoint_Targets`
   - `License_Events`
   - `App_Events`
   - `Errors`
   - `Organizations` (Derived)
   - `Devices` (Derived)
   - `Daily_Summary` (Derived)
   - `Feature_Usage` (Derived)
   - `Telemetry_Health`

### Step 2: Configure Header Rows

#### `Scans`
```text
Event_ID | Timestamp_UTC | Organization_ID | User_ID | Device_ID | Endpoint_ID | Installation_ID | Scan_ID | Scan_Type | Duration_MS | Files_Processed | Findings_Count | Critical_Count | High_Count | Medium_Count | Low_Count | Risk_Score | Checklist_ID | Checklist_Version | License_Plan | OS | OS_Version | Machine_Type | App_Version | Offline_Mode
```

#### `Endpoint_Compliance`
```text
Event_ID | Timestamp_UTC | Organization_ID | Device_ID | Endpoint_ID | Assessment_ID | OS | Machine_Type | USB_Status | USB_Storage_Detected | Total_Tested | Accessible_Count | Blocked_Count | Unreachable_Count | Indeterminate_Count | Social_Media_Accessible | Personal_Email_Accessible | Messaging_Accessible | Cloud_Storage_Accessible | Compliance_Score | Duration_MS
```

#### `Endpoint_Targets`
```text
Event_ID | Timestamp_UTC | Organization_ID | Device_ID | Endpoint_ID | Assessment_ID | Category | Target | Status | Confidence | Network_Reachable | Policy_Block_Detected | Service_Identity_Confirmed | Response_Time_MS | Probe_Attempts | Reason_Code
```

#### `License_Events`
```text
Event_ID | Event_Type | Timestamp_UTC | Organization_ID | Device_ID | Endpoint_ID | License_ID | Plan | Status | Issued_At | Expires_At | Days_Remaining | Device_Count | Max_Devices
```

#### `App_Events`
```text
Event_ID | Event_Type | Timestamp_UTC | Organization_ID | Device_ID | Endpoint_ID | App_Version | OS | OS_Version | Machine_Type | Architecture
```

#### `Errors`
```text
Event_ID | Timestamp_UTC | Organization_ID | Device_ID | Endpoint_ID | Error_Code | Error_Category | Sanitized_Message
```

---

### Step 3: Deploy the Google Apps Script Web App
1. In your spreadsheet, click **Extensions** $\rightarrow$ **Apps Script**.
2. Replace the contents of `Code.gs` with the code in [`backend/telemetry/googleAppsScriptIngestion.js`](file:///c:/Users/nikhi/Downloads/New%20folder/FileSentinel-ExperimentalChanges/backend/telemetry/googleAppsScriptIngestion.js).
3. Click **Project Settings** (gear icon) $\rightarrow$ **Script Properties** $\rightarrow$ **Add script property**:
   - Property: `TELEMETRY_INGESTION_SECRET`
   - Value: `<Generate a strong 64-character random hex string>`
4. Click **Deploy** $\rightarrow$ **New deployment**:
   - Select type: **Web App**
   - Description: `FileSentinel Telemetry Ingestion v1.0`
   - Execute as: **Me** (`your-email@domain.com`)
   - Who has access: **Anyone**
5. Click **Deploy** and copy the **Web App URL** (e.g., `https://script.google.com/macros/s/.../exec`).

---

### Step 4: Configure FileSentinel Environment

In your FileSentinel configuration (`.env` or environment variables):

```bash
# Enable Telemetry Sync
TELEMETRY_ENABLED=true
TELEMETRY_ENVIRONMENT=production

# Google Apps Script Web App URL
TELEMETRY_INGESTION_URL="https://script.google.com/macros/s/AKfycb.../exec"

# Shared HMAC Ingestion Secret (Matches Script Property)
TELEMETRY_INGESTION_SECRET="your-64-character-hex-secret"

# Privacy Controls
TELEMETRY_COLLECT_IP=false
TELEMETRY_COLLECT_GEO=false
TELEMETRY_LOCAL_RETENTION_DAYS=30
```

---

## 3. Security & Anti-Replay Verification

FileSentinel computes an HMAC signature for every batch submission:
$$\text{Signature} = \text{HMAC-SHA256}\left(\text{Secret}, \text{Timestamp} + ":" + \text{Nonce} + ":" + \text{RequestBody}\right)$$

Apps Script enforces:
- **Freshness Window**: Requests with timestamps older than 5 minutes are rejected (`401`).
- **Replay Protection**: Nonces are stored in Google Apps Script `CacheService` for 10 minutes. Reused nonces are rejected (`403`).
- **Idempotency**: Event IDs are deduplicated in cache for 7 days. Duplicate events are silently acknowledged without adding duplicate rows.
- **Data Minimization**: Strict schema filtering in FileSentinel strips file paths, contents, OCR text, passwords, and private keys before queueing.

---

## 4. Credential Rotation

To rotate the `TELEMETRY_INGESTION_SECRET`:
1. In Google Apps Script, update the `TELEMETRY_INGESTION_SECRET` script property.
2. In FileSentinel instances, update `TELEMETRY_INGESTION_SECRET` in environment/config.
3. Any batches attempted with the old secret will temporarily fail and automatically retry once the configuration is updated.
