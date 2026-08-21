/**
 * FILE-SENTINEL — Phase T1.5: Local SQLite Telemetry Queue Manager
 *
 * Guarantees:
 * - Deterministic priority-based eviction (LOW -> NORMAL -> HIGH, never CRITICAL)
 * - Size validation & sanitization prior to insertion
 * - Stuck 'SENDING' event recovery (reset to PENDING if locked > 5 min)
 * - Safe local retention purging (SENT items older than retention threshold)
 * - Zero impact on scan/audit/security tables
 */

import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  TelemetryQueueRecord,
  TelemetryPriority,
  TelemetryQueueStatus,
  CURRENT_TELEMETRY_SCHEMA_VERSION,
  TelemetryHealthStats
} from './telemetryTypes.js';
import {
  filterAndSanitizeEvent,
  getEventPriority,
  MAX_QUEUE_CAPACITY,
  MAX_EVENT_SIZE_BYTES,
  DEFAULT_LOCAL_RETENTION_DAYS
} from './telemetryPrivacy.js';

export class TelemetryQueueRepository {
  private db: DatabaseSync;
  private maxCapacity: number;

  constructor(db: DatabaseSync, maxCapacity: number = MAX_QUEUE_CAPACITY) {
    this.db = db;
    this.maxCapacity = maxCapacity;
  }

  /**
   * Enqueues an event into the SQLite telemetry queue after full allowlist filtering and sanitization.
   * Applies deterministic capacity eviction if the queue is full.
   */
  public enqueue(
    rawPayload: Record<string, any>,
    explicitPriority?: TelemetryPriority
  ): { success: boolean; event_id?: string; queue_id?: string; error?: string } {
    try {
      // 1. Allowlist filtering, sanitization, envelope validation, and size capping
      const sanitized = filterAndSanitizeEvent(rawPayload);
      if (!sanitized) {
        return {
          success: false,
          error: 'Event rejected by privacy allowlist or exceeded size limits (max 64KB)'
        };
      }

      const eventId = sanitized.event_id;
      const eventType = sanitized.event_type;
      const schemaVersion = sanitized.schema_version || CURRENT_TELEMETRY_SCHEMA_VERSION;
      const priority: TelemetryPriority = explicitPriority || getEventPriority(eventType);
      const payloadJson = JSON.stringify(sanitized);

      if (Buffer.byteLength(payloadJson, 'utf8') > MAX_EVENT_SIZE_BYTES) {
        return {
          success: false,
          error: `Event size (${Buffer.byteLength(payloadJson, 'utf8')} bytes) exceeds limit (${MAX_EVENT_SIZE_BYTES} bytes)`
        };
      }

      // 2. Check if event_id already exists in queue (Idempotency)
      const existing = this.db.prepare('SELECT id, status FROM telemetry_queue WHERE event_id = ?').get(eventId) as any;
      if (existing) {
        return {
          success: true,
          event_id: eventId,
          queue_id: existing.id
        };
      }

      // 3. Enforce queue capacity bounds via deterministic eviction
      this.enforceCapacity();

      // 4. Insert into queue
      const queueId = `TQ-${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      const stmt = this.db.prepare(`
        INSERT INTO telemetry_queue (
          id, event_id, event_type, schema_version, priority, payload_json,
          created_at, attempt_count, next_attempt_at, status, locked_at, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'PENDING', NULL, NULL)
      `);

      stmt.run(
        queueId,
        eventId,
        eventType,
        schemaVersion,
        priority,
        payloadJson,
        now,
        now
      );

      return {
        success: true,
        event_id: eventId,
        queue_id: queueId
      };
    } catch (err: any) {
      return {
        success: false,
        error: err.message || 'Failed to enqueue telemetry event'
      };
    }
  }

  /**
   * Enforces max capacity by evicting lowest priority events:
   * Eviction order: LOW -> NORMAL -> HIGH. Never evicts CRITICAL.
   */
  public enforceCapacity(): number {
    const countRow = this.db.prepare("SELECT COUNT(*) as count FROM telemetry_queue WHERE status != 'SENT'").get() as { count: number };
    const currentCount = countRow?.count || 0;

    if (currentCount < this.maxCapacity) {
      return 0;
    }

    const excess = currentCount - this.maxCapacity + 1;
    let evicted = 0;

    // 1. Try evicting LOW priority first (oldest first)
    const evictLow = this.db.prepare(`
      DELETE FROM telemetry_queue
      WHERE id IN (
        SELECT id FROM telemetry_queue
        WHERE priority = 'LOW' AND status != 'SENT'
        ORDER BY created_at ASC
        LIMIT ?
      )
    `).run(excess);
    evicted += (evictLow as any).changes || 0;

    // 2. If still over capacity, evict NORMAL priority
    if (evicted < excess) {
      const remaining = excess - evicted;
      const evictNormal = this.db.prepare(`
        DELETE FROM telemetry_queue
        WHERE id IN (
          SELECT id FROM telemetry_queue
          WHERE priority = 'NORMAL' AND status != 'SENT'
          ORDER BY created_at ASC
          LIMIT ?
        )
      `).run(remaining);
      evicted += (evictNormal as any).changes || 0;
    }

    // 3. If still over capacity, evict HIGH priority
    if (evicted < excess) {
      const remaining = excess - evicted;
      const evictHigh = this.db.prepare(`
        DELETE FROM telemetry_queue
        WHERE id IN (
          SELECT id FROM telemetry_queue
          WHERE priority = 'HIGH' AND status != 'SENT'
          ORDER BY created_at ASC
          LIMIT ?
        )
      `).run(remaining);
      evicted += (evictHigh as any).changes || 0;
    }

    // Note: CRITICAL events are NEVER evicted.
    return evicted;
  }

  /**
   * Recover any events stuck in 'SENDING' state with locked_at older than 5 minutes.
   */
  public recoverStuckSending(timeoutMinutes: number = 5): number {
    const thresholdMs = Date.now() - timeoutMinutes * 60 * 1000;
    const thresholdIso = new Date(thresholdMs).toISOString();

    const result = this.db.prepare(`
      UPDATE telemetry_queue
      SET status = 'PENDING',
          locked_at = NULL,
          last_error = 'Recovered from stuck SENDING state'
      WHERE status = 'SENDING' AND (locked_at IS NULL OR locked_at < ?)
    `).run(thresholdIso);

    return (result as any).changes || 0;
  }

  /**
   * Purges successfully SENT telemetry records older than retention threshold.
   * Never touches audit logs, scan evidence, or licensing records.
   */
  public purgeOldSent(retentionDays: number = DEFAULT_LOCAL_RETENTION_DAYS): number {
    const thresholdMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    const thresholdIso = new Date(thresholdMs).toISOString();

    const result = this.db.prepare(`
      DELETE FROM telemetry_queue
      WHERE status = 'SENT' AND created_at < ?
    `).run(thresholdIso);

    return (result as any).changes || 0;
  }

  /**
   * Claims a batch of pending events for dispatch, locking them with status 'SENDING'.
   */
  public claimBatch(maxEvents: number = 50): TelemetryQueueRecord[] {
    const now = new Date().toISOString();

    const pending = this.db.prepare(`
      SELECT * FROM telemetry_queue
      WHERE status = 'PENDING' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
      ORDER BY
        CASE priority
          WHEN 'CRITICAL' THEN 1
          WHEN 'HIGH' THEN 2
          WHEN 'NORMAL' THEN 3
          WHEN 'LOW' THEN 4
          ELSE 5
        END ASC,
        created_at ASC
      LIMIT ?
    `).all(now, maxEvents) as any[];

    if (pending.length === 0) {
      return [];
    }

    const ids = pending.map(p => p.id);
    const placeholders = ids.map(() => '?').join(',');

    this.db.prepare(`
      UPDATE telemetry_queue
      SET status = 'SENDING', locked_at = ?
      WHERE id IN (${placeholders})
    `).run(now, ...ids);

    return pending.map(p => ({
      id: p.id,
      event_id: p.event_id || p.id,
      event_type: p.event_type,
      schema_version: p.schema_version || 1,
      priority: p.priority || 'NORMAL',
      payload_json: p.payload_json,
      created_at: p.created_at,
      attempt_count: p.attempt_count || 0,
      next_attempt_at: p.next_attempt_at,
      status: 'SENDING',
      locked_at: now,
      last_error: p.last_error
    }));
  }

  /**
   * Marks events as successfully SENT.
   */
  public markBatchSent(eventIds: string[]): void {
    if (!eventIds || eventIds.length === 0) return;
    const placeholders = eventIds.map(() => '?').join(',');
    this.db.prepare(`
      UPDATE telemetry_queue
      SET status = 'SENT', locked_at = NULL, last_error = NULL
      WHERE event_id IN (${placeholders}) OR id IN (${placeholders})
    `).run(...eventIds, ...eventIds);
  }

  /**
   * Marks events as FAILED and schedules next attempt with backoff.
   */
  public markBatchFailed(eventIds: string[], errorMessage: string, nextAttemptIso: string): void {
    if (!eventIds || eventIds.length === 0) return;
    const placeholders = eventIds.map(() => '?').join(',');
    this.db.prepare(`
      UPDATE telemetry_queue
      SET status = 'PENDING',
          attempt_count = attempt_count + 1,
          next_attempt_at = ?,
          locked_at = NULL,
          last_error = ?
      WHERE event_id IN (${placeholders}) OR id IN (${placeholders})
    `).run(nextAttemptIso, errorMessage, ...eventIds, ...eventIds);
  }

  /**
   * Gets telemetry health statistics.
   */
  public getHealthStats(): TelemetryHealthStats {
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
}
