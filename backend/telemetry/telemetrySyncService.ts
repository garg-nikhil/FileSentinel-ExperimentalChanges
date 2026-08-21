/**
 * FILE-SENTINEL — Phase T3: Telemetry Synchronization Service
 *
 * Guarantees:
 * - Asynchronous, isolated background synchronization
 * - Batched sync: maximum 50 events per batch
 * - HMAC-SHA256 request authentication with timestamp & nonce replay protection
 * - Exponential backoff (1s -> 2s -> 4s -> ... max 1 hour)
 * - Idempotency by event_id (deduplication on Google Sheets side)
 * - Complete outage isolation (never fails scans, assessments, or user operations)
 */

import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { DatabaseSync } from 'node:sqlite';
import {
  TelemetryConfig,
  TelemetryQueueRecord,
  CURRENT_TELEMETRY_SCHEMA_VERSION,
  TelemetryHealthStats
} from './telemetryTypes.js';
import { getTelemetryConfig } from './telemetryPrivacy.js';
import { TelemetryQueueRepository } from './telemetryQueue.js';

export interface SyncResult {
  processed: number;
  succeeded: number;
  failed: number;
  duration_ms: number;
  error?: string;
}

export class TelemetrySyncService {
  private db: DatabaseSync;
  private queueRepo: TelemetryQueueRepository;
  private config: TelemetryConfig;
  private timer: NodeJS.Timeout | null = null;
  private isSyncing: boolean = false;
  private lastSuccessfulSync?: string;
  private lastSyncError?: string;
  private lastSyncDurationMs?: number;

  constructor(db: DatabaseSync, customConfig?: Partial<TelemetryConfig>) {
    this.db = db;
    this.queueRepo = new TelemetryQueueRepository(db);
    this.config = {
      ...getTelemetryConfig(),
      ...(customConfig || {})
    };
  }

  /**
   * Starts periodic background synchronization
   */
  public start(intervalMs: number = 60000): void {
    if (this.timer) {
      clearInterval(this.timer);
    }

    // Run stuck recovery on startup
    try {
      this.queueRepo.recoverStuckSending(5);
    } catch {}

    this.timer = setInterval(() => {
      this.syncOnce().catch(() => {});
    }, intervalMs);
  }

  /**
   * Stops periodic background synchronization
   */
  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public setConfig(updated: Partial<TelemetryConfig>): void {
    this.config = { ...this.config, ...updated };
  }

  public getConfig(): TelemetryConfig {
    return { ...this.config };
  }

  /**
   * Executes a single synchronization cycle.
   * Completely isolated: Never throws to the caller.
   */
  public async syncOnce(): Promise<SyncResult> {
    if (this.isSyncing) {
      return { processed: 0, succeeded: 0, failed: 0, duration_ms: 0 };
    }

    this.isSyncing = true;
    const startMs = Date.now();
    let currentBatch: TelemetryQueueRecord[] = [];

    try {
      // 1. Recover any stuck SENDING records (> 5 min)
      this.queueRepo.recoverStuckSending(5);

      // 2. Check if telemetry is enabled and ingestion URL is configured
      if (!this.config.enabled || !this.config.ingestionUrl) {
        this.isSyncing = false;
        return {
          processed: 0,
          succeeded: 0,
          failed: 0,
          duration_ms: Date.now() - startMs
        };
      }

      // 3. Claim batch of pending events (max 50)
      const maxBatch = Math.min(this.config.maxEventsPerBatch || 50, 50);
      currentBatch = this.queueRepo.claimBatch(maxBatch);

      if (currentBatch.length === 0) {
        this.isSyncing = false;
        return {
          processed: 0,
          succeeded: 0,
          failed: 0,
          duration_ms: Date.now() - startMs
        };
      }

      // 4. Construct payload envelope and canonical representation
      const events = currentBatch.map(b => {
        try {
          const parsed = JSON.parse(b.payload_json) || {};
          return {
            ...parsed,
            event_id: b.event_id,
            event_type: b.event_type,
            schema_version: b.schema_version || CURRENT_TELEMETRY_SCHEMA_VERSION
          };
        } catch {
          return null;
        }
      }).filter(Boolean);

      const batchId = `BAT-${crypto.randomUUID()}`;
      const sentAt = new Date().toISOString();
      const timestamp = Date.now().toString();
      const nonce = crypto.randomUUID();
      const secret = this.config.ingestionSecret || 'filesentinel-telemetry-default-secret';

      const canonicalData = JSON.stringify({
        batch_id: batchId,
        sent_at: sentAt,
        environment: this.config.environment,
        schema_version: CURRENT_TELEMETRY_SCHEMA_VERSION,
        events
      });

      const canonicalPayload = `${timestamp}:${nonce}:${canonicalData}`;
      const signature = crypto
        .createHmac('sha256', secret)
        .update(canonicalPayload)
        .digest('hex');

      const payloadObj = {
        batch_id: batchId,
        sent_at: sentAt,
        environment: this.config.environment,
        schema_version: CURRENT_TELEMETRY_SCHEMA_VERSION,
        auth: {
          timestamp,
          nonce,
          signature
        },
        events
      };

      const requestBody = JSON.stringify(payloadObj);

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'FileSentinel-Telemetry/8.2.0'
      };

      // 5. Transmit to Google Apps Script ingestion endpoint
      const response = await this.sendHttpRequest(this.config.ingestionUrl, requestBody, headers, 10000);

      const durationMs = Date.now() - startMs;
      this.lastSyncDurationMs = durationMs;

      // 6. Robust Application-Level Response Validation
      if (response.statusCode >= 200 && response.statusCode < 300) {
        let responseJson: any = null;
        try {
          responseJson = JSON.parse(response.body);
        } catch (jsonErr: any) {
          const errMsg = `Malformed JSON response: ${response.body.slice(0, 100)}`;
          this.lastSyncError = errMsg;
          this.handleBatchFailure(currentBatch, errMsg, false);
          this.isSyncing = false;
          return {
            processed: currentBatch.length,
            succeeded: 0,
            failed: currentBatch.length,
            duration_ms: durationMs,
            error: errMsg
          };
        }

        if (responseJson && responseJson.success === true && typeof responseJson.processed_count === 'number') {
          const totalAcknowledged = (responseJson.processed_count || 0) + (responseJson.duplicates_count || 0);
          if (totalAcknowledged >= 1 || currentBatch.length === 0) {
            // Mark batch as successfully sent
            const eventIds = currentBatch.map(b => b.event_id);
            this.queueRepo.markBatchSent(eventIds);
            this.lastSuccessfulSync = new Date().toISOString();
            this.lastSyncError = undefined;

            this.isSyncing = false;
            return {
              processed: currentBatch.length,
              succeeded: currentBatch.length,
              failed: 0,
              duration_ms: durationMs
            };
          }
        }

        // Endpoint returned HTTP 200 but application-level failure (e.g. { success: false, error: '...' })
        const errMsg = responseJson?.error || `Application error: ${JSON.stringify(responseJson).slice(0, 150)}`;
        const isAuthFailure = typeof errMsg === 'string' && (
          errMsg.toLowerCase().includes('hmac') ||
          errMsg.toLowerCase().includes('signature') ||
          errMsg.toLowerCase().includes('secret') ||
          errMsg.toLowerCase().includes('auth')
        );
        this.lastSyncError = errMsg;
        this.handleBatchFailure(currentBatch, errMsg, isAuthFailure);

        this.isSyncing = false;
        return {
          processed: currentBatch.length,
          succeeded: 0,
          failed: currentBatch.length,
          duration_ms: durationMs,
          error: errMsg
        };
      } else {
        // HTTP Error (e.g. 401 Unauthorized, 400 Bad Request, 500 Server Error)
        const errMsg = `HTTP ${response.statusCode}: ${response.body.slice(0, 200)}`;
        this.lastSyncError = errMsg;
        this.handleBatchFailure(currentBatch, errMsg, response.statusCode === 401 || response.statusCode === 403);

        this.isSyncing = false;
        return {
          processed: currentBatch.length,
          succeeded: 0,
          failed: currentBatch.length,
          duration_ms: durationMs,
          error: errMsg
        };
      }
    } catch (netErr: any) {
      // Network/outage error
      const durationMs = Date.now() - startMs;
      const errMsg = netErr?.message || 'Network unreachable';
      this.lastSyncError = errMsg;
      this.lastSyncDurationMs = durationMs;

      // Reset claimed batch back to PENDING with exponential backoff
      if (currentBatch.length > 0) {
        this.handleBatchFailure(currentBatch, errMsg, false);
      }

      this.isSyncing = false;
      return {
        processed: currentBatch.length,
        succeeded: 0,
        failed: currentBatch.length,
        duration_ms: durationMs,
        error: errMsg
      };
    } finally {
      this.isSyncing = false;
    }
  }

  /**
   * Handles failed batch with exponential backoff calculation.
   * Max retry interval: 1 hour (3,600,000 ms).
   */
  private handleBatchFailure(batch: TelemetryQueueRecord[], errorMessage: string, isAuthFailure: boolean): void {
    const eventIds = batch.map(b => b.event_id);

    for (const item of batch) {
      const attempts = (item.attempt_count || 0) + 1;

      // Exponential backoff: base 1s, capped at 1 hour (3600s)
      // If auth failure, wait full hour before retrying
      const backoffSeconds = isAuthFailure
        ? 3600
        : Math.min(3600, Math.pow(2, Math.min(attempts, 12)));

      const nextAttemptAt = new Date(Date.now() + backoffSeconds * 1000).toISOString();
      this.queueRepo.markBatchFailed([item.event_id], errorMessage, nextAttemptAt);
    }
  }

  /**
   * Internal HTTP/HTTPS request sender with timeout and Google Apps Script redirect handling
   */
  private sendHttpRequest(
    urlStr: string,
    body: string,
    headers: Record<string, string>,
    timeoutMs: number = 15000,
    maxRedirects: number = 5
  ): Promise<{ statusCode: number; body: string }> {
    return new Promise((resolve, reject) => {
      const url = new URL(urlStr);
      const isHttps = url.protocol === 'https:';
      const client = isHttps ? https : http;

      const req = client.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: (url.pathname || '/') + (url.search || ''),
          method: 'POST',
          headers: {
            ...headers,
            'Content-Length': Buffer.byteLength(body, 'utf8')
          },
          timeout: timeoutMs
        },
        res => {
          let resBody = '';
          res.setEncoding('utf8');
          res.on('data', chunk => {
            resBody += chunk;
          });
          res.on('end', () => {
            // Handle HTTP 301/302/303/307/308 redirects (Google Apps Script standard)
            if (
              res.statusCode &&
              res.statusCode >= 300 &&
              res.statusCode < 400 &&
              res.headers.location &&
              maxRedirects > 0
            ) {
              const redirectUrl = new URL(res.headers.location, urlStr).toString();
              const isRedirHttps = redirectUrl.startsWith('https:');
              const redirClient = isRedirHttps ? https : http;

              const redirReq = redirClient.get(redirectUrl, { timeout: timeoutMs }, redirRes => {
                let redirBody = '';
                redirRes.setEncoding('utf8');
                redirRes.on('data', c => {
                  redirBody += c;
                });
                redirRes.on('end', () => {
                  resolve({
                    statusCode: redirRes.statusCode || 200,
                    body: redirBody
                  });
                });
              });

              redirReq.on('timeout', () => {
                redirReq.destroy(new Error(`Telemetry sync redirect timed out after ${timeoutMs}ms`));
              });
              redirReq.on('error', err => {
                reject(err);
              });
              return;
            }

            resolve({
              statusCode: res.statusCode || 500,
              body: resBody
            });
          });
        }
      );

      req.on('timeout', () => {
        req.destroy(new Error(`Telemetry sync timed out after ${timeoutMs}ms`));
      });

      req.on('error', err => {
        reject(err);
      });

      req.write(body);
      req.end();
    });
  }

  /**
   * Gets telemetry health summary
   */
  public getHealthStats(): TelemetryHealthStats {
    const stats = this.queueRepo.getHealthStats();
    return {
      ...stats,
      last_successful_sync: this.lastSuccessfulSync,
      last_sync_error: this.lastSyncError,
      sync_duration_ms: this.lastSyncDurationMs
    };
  }
}
