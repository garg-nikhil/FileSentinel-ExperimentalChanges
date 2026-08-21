import 'dotenv/config';
import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { createApiRouter } from './backend/routes.js';
import { securityHeaders, corsMiddleware, enforceContentType, rateLimiter, csrfProtection, safeErrorHandler, apiCacheControl } from './backend/securityMiddleware.js';
import { FileIntegrityMonitor } from './backend/fimService.js';
import { getDatabase } from './backend/db.js';
import { TelemetrySyncService } from './backend/telemetry/telemetrySyncService.js';

async function startServer() {
  const fimResult = FileIntegrityMonitor.verifyIntegrity();
  if (!fimResult.valid) {
    console.warn('[FIM Warning] File integrity check flagged files:', fimResult.modifiedFiles);
  } else {
    console.log('[FIM] File integrity check passed successfully.');
  }

  const app = express();
  const PORT = Number(process.env.PORT || 3000);
  const db = getDatabase();

  // Security Hardening #10: Never trust proxy headers for authentication or host determination
  app.set('trust proxy', false);

  // Security Middleware
  app.use(securityHeaders);
  app.use(corsMiddleware);
  app.use(express.json({ limit: '100kb' }));
  app.use(enforceContentType);
  app.use(csrfProtection);
  // Security Hardening #14: Prevent caching of API responses
  app.use('/api', apiCacheControl);

  // Rate limiters for sensitive endpoints
  const authRateLimiter = rateLimiter({ windowMs: 60000, max: process.env.NODE_ENV === 'production' ? 30 : 120 });
  const apiRateLimiter = rateLimiter({ windowMs: 60000, max: process.env.NODE_ENV === 'production' ? 300 : 1000 });
  const webhookRateLimiter = rateLimiter({ windowMs: 60000, max: 200 });

  app.use('/api/auth/login', authRateLimiter);
  app.use('/api/webhooks', webhookRateLimiter);
  app.use('/api', apiRateLimiter);

  // Mount API Router
  app.use('/api', createApiRouter(db));

  // Global Safe Error Handler
  app.use('/api', safeErrorHandler);

  // Mount Vite middleware in development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Security Hardening #3: Default to loopback for local-first security; require explicit HOST env var for network binding
  const HOST = process.env.HOST || '127.0.0.1';

  const server = app.listen(PORT, HOST, () => {
    console.log(`[FileSentinel] Local-First Security Server running on http://${HOST}:${PORT}`);
  });

  server.headersTimeout = 60000;
  server.requestTimeout = 120000;
  server.keepAliveTimeout = 65000;

  // Background Telemetry Synchronization Lifecycle
  let syncService: TelemetrySyncService | null = null;
  const isTelemetryEnabled = process.env.TELEMETRY_ENABLED === 'true' || process.env.TELEMETRY_ENABLED === '1';

  if (isTelemetryEnabled) {
    const ingestionUrl = process.env.TELEMETRY_INGESTION_URL?.trim();
    const ingestionSecret = process.env.TELEMETRY_INGESTION_SECRET?.trim();

    if (!ingestionUrl) {
      console.warn('[Telemetry] Safe Warning: TELEMETRY_ENABLED is true, but TELEMETRY_INGESTION_URL is missing. Background synchronization disabled.');
    } else if (!ingestionSecret) {
      console.warn('[Telemetry] Safe Warning: TELEMETRY_ENABLED is true, but TELEMETRY_INGESTION_SECRET is missing. Background synchronization disabled.');
    } else {
      const syncIntervalSec = parseInt(process.env.TELEMETRY_SYNC_INTERVAL_SEC || '60', 10) || 60;
      syncService = new TelemetrySyncService(db, {
        enabled: true,
        ingestionUrl,
        ingestionSecret,
        environment: (process.env.TELEMETRY_ENVIRONMENT as any) || (process.env.NODE_ENV === 'production' ? 'production' : 'development'),
        maxEventsPerBatch: parseInt(process.env.TELEMETRY_MAX_BATCH_SIZE || '50', 10) || 50
      });

      syncService.start(syncIntervalSec * 1000);
      console.log(`[Telemetry] Background synchronization service active (Interval: ${syncIntervalSec}s)`);
    }
  }

  // Graceful server shutdown
  const handleShutdown = (signal: string) => {
    console.log(`[FileSentinel] Received ${signal}. Shutting down gracefully...`);
    if (syncService) {
      syncService.stop();
      syncService = null;
    }
    server.close(() => {
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
  process.on('SIGINT', () => handleShutdown('SIGINT'));
}

startServer().catch(err => {
  console.error('Failed to start FileSentinel server:', err);
});
