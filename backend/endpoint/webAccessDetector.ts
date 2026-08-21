/**
 * FILE-SENTINEL — Phase A: Endpoint Compliance Detection Engine
 * Web Access Compliance Detector with Conservative Deterministic Classification & Bounded Retries
 *
 * STRICTLY DETECTION ONLY:
 * - NO network blocking
 * - NO firewall rule modifications
 * - NO proxy configuration changes
 * - NO browser history, cookies, credentials, or personal data inspection
 *
 * LOCAL AGENT ARCHITECTURE:
 * - Executes on the host endpoint machine running the FileSentinel backend or local agent daemon.
 * - Read-only HTTPS / DNS probes are conducted strictly for compliance verification.
 */

import https from 'node:https';
import http from 'node:http';
import dns from 'node:dns/promises';
import { URL } from 'node:url';
import {
  WebAccessTarget,
  WebTargetResult,
  WebAccessCategory,
  WebAccessStatus,
  ConfidenceLevel,
  DetectionMethod
} from './endpointTypes.js';

/**
 * Validates whether a hostname belongs to the approved domain registry.
 * Uses exact match or suffix-dot matching to prevent lookalike domains (e.g. evil-facebook.com or facebook.com.attacker.com).
 */
export function isDomainAllowed(hostname: string, allowedDomains: string[]): boolean {
  if (!hostname || !allowedDomains || allowedDomains.length === 0) {
    return false;
  }
  const cleanHost = hostname.toLowerCase().trim();
  return allowedDomains.some((allowed) => {
    const cleanAllowed = allowed.toLowerCase().trim();
    return cleanHost === cleanAllowed || cleanHost.endsWith('.' + cleanAllowed);
  });
}

/**
 * Validates and sanitizes a custom web access target if configured by an authorized tenant admin.
 * Blocks localhost, private IP ranges, loopback, and metadata-service addresses.
 */
export function validateAndSanitizeTarget(target: Partial<WebAccessTarget>): WebAccessTarget {
  if (!target || typeof target !== 'object') {
    throw new Error('Target definition must be a valid object');
  }

  if (!target.id || typeof target.id !== 'string') {
    throw new Error('Target id is required and must be a string');
  }

  const validCategories: WebAccessCategory[] = ['SOCIAL_MEDIA', 'PERSONAL_EMAIL', 'MESSAGING', 'CLOUD_STORAGE'];
  if (!target.category || !validCategories.includes(target.category)) {
    throw new Error(`Target category must be one of: ${validCategories.join(', ')}`);
  }

  if (!target.service_name || typeof target.service_name !== 'string' || target.service_name.trim().length === 0) {
    throw new Error('Target service_name is required');
  }

  if (!target.probe_url || typeof target.probe_url !== 'string') {
    throw new Error('Target probe_url is required');
  }

  let parsed: URL;
  try {
    parsed = new URL(target.probe_url);
  } catch (err: any) {
    throw new Error(`Invalid probe_url: ${err?.message || 'Malformed URL'}`);
  }

  // Strictly enforce HTTPS protocol
  if (parsed.protocol !== 'https:') {
    throw new Error(`Probe URL protocol must be HTTPS (received ${parsed.protocol})`);
  }

  const host = parsed.hostname.toLowerCase();

  // Prevent probing loopback, localhost, and metadata IP ranges
  const forbiddenHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254'];
  if (forbiddenHosts.includes(host) || host.startsWith('127.') || host.startsWith('169.254.')) {
    throw new Error(`Probe URL host '${host}' is forbidden (localhost/metadata prohibited)`);
  }

  // Prevent private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  if (/^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)) {
    throw new Error(`Probe URL host '${host}' is forbidden (private network address prohibited)`);
  }

  const primaryDomain = target.primary_domain?.toLowerCase().trim() || host;
  const expectedIdentifiers = Array.isArray(target.expected_identifiers) && target.expected_identifiers.length > 0
    ? target.expected_identifiers.map(s => String(s).trim())
    : [primaryDomain];

  const allowedDomains = Array.isArray(target.allowed_domains) && target.allowed_domains.length > 0
    ? target.allowed_domains.map(d => String(d).toLowerCase().trim())
    : [primaryDomain];

  return {
    id: target.id.trim(),
    category: target.category,
    service_name: target.service_name.trim(),
    primary_domain: primaryDomain,
    probe_url: target.probe_url.trim(),
    expected_identifiers: expectedIdentifiers,
    allowed_domains: allowedDomains
  };
}

/**
 * Server-controlled default targets with hardened allowed domain registries
 */
export const DEFAULT_WEB_TARGETS: WebAccessTarget[] = [
  // --- SOCIAL MEDIA ---
  {
    id: 'soc-fb',
    category: 'SOCIAL_MEDIA',
    service_name: 'Facebook',
    primary_domain: 'facebook.com',
    probe_url: 'https://www.facebook.com',
    expected_identifiers: ['facebook', 'fb', 'meta', 'fbcdn'],
    allowed_domains: ['facebook.com', 'fb.com', 'meta.com', 'fbcdn.net', 'facebook.net']
  },
  {
    id: 'soc-ig',
    category: 'SOCIAL_MEDIA',
    service_name: 'Instagram',
    primary_domain: 'instagram.com',
    probe_url: 'https://www.instagram.com',
    expected_identifiers: ['instagram', 'cdninstagram', 'meta', 'facebook'],
    allowed_domains: ['instagram.com', 'cdninstagram.com', 'facebook.com', 'fb.com', 'meta.com', 'fbcdn.net']
  },
  {
    id: 'soc-x',
    category: 'SOCIAL_MEDIA',
    service_name: 'X',
    primary_domain: 'x.com',
    probe_url: 'https://x.com',
    expected_identifiers: ['x.com', 'twitter', 'twimg', 't.co'],
    allowed_domains: ['x.com', 'twitter.com', 'twimg.com', 't.co']
  },
  {
    id: 'soc-li',
    category: 'SOCIAL_MEDIA',
    service_name: 'LinkedIn',
    primary_domain: 'linkedin.com',
    probe_url: 'https://www.linkedin.com',
    expected_identifiers: ['linkedin', 'licdn'],
    allowed_domains: ['linkedin.com', 'licdn.com']
  },
  {
    id: 'soc-rd',
    category: 'SOCIAL_MEDIA',
    service_name: 'Reddit',
    primary_domain: 'reddit.com',
    probe_url: 'https://www.reddit.com',
    expected_identifiers: ['reddit', 'redditmedia', 'redd.it'],
    allowed_domains: ['reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com']
  },
  {
    id: 'soc-tt',
    category: 'SOCIAL_MEDIA',
    service_name: 'TikTok',
    primary_domain: 'tiktok.com',
    probe_url: 'https://www.tiktok.com',
    expected_identifiers: ['tiktok', 'tiktokcdn', 'bytedance'],
    allowed_domains: ['tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'bytedance.com', 'byteoversea.com', 'ibytedtos.com']
  },

  // --- PERSONAL EMAIL ---
  {
    id: 'eml-gm',
    category: 'PERSONAL_EMAIL',
    service_name: 'Gmail',
    primary_domain: 'mail.google.com',
    probe_url: 'https://mail.google.com',
    expected_identifiers: ['google', 'gmail', 'accounts.google', 'service=mail'],
    allowed_domains: ['google.com', 'googleusercontent.com', 'gstatic.com', 'accounts.google.com', 'google.co.in', '1e100.net']
  },
  {
    id: 'eml-yh',
    category: 'PERSONAL_EMAIL',
    service_name: 'Yahoo Mail',
    primary_domain: 'mail.yahoo.com',
    probe_url: 'https://mail.yahoo.com',
    expected_identifiers: ['yahoo', 'login.yahoo', 'yimg'],
    allowed_domains: ['yahoo.com', 'yimg.com']
  },
  {
    id: 'eml-ol',
    category: 'PERSONAL_EMAIL',
    service_name: 'Outlook.com',
    primary_domain: 'outlook.live.com',
    probe_url: 'https://login.live.com',
    expected_identifiers: ['outlook', 'live.com', 'microsoft', 'msft', 'login'],
    allowed_domains: ['live.com', 'microsoft.com', 'office.com', 'outlook.com', 'microsoftonline.com', 'login.live.com', 'login.microsoftonline.com', 'msftauth.net', 'msauth.net']
  },
  {
    id: 'eml-pr',
    category: 'PERSONAL_EMAIL',
    service_name: 'Proton Mail',
    primary_domain: 'mail.proton.me',
    probe_url: 'https://mail.proton.me',
    expected_identifiers: ['proton', 'protonmail', 'proton.me'],
    allowed_domains: ['proton.me', 'protonmail.com']
  },
  {
    id: 'eml-ic',
    category: 'PERSONAL_EMAIL',
    service_name: 'iCloud Mail',
    primary_domain: 'www.icloud.com',
    probe_url: 'https://www.icloud.com/mail',
    expected_identifiers: ['icloud', 'apple'],
    allowed_domains: ['icloud.com', 'apple.com', 'apple-cloudkit.com', 'mzstatic.com']
  },

  // --- MESSAGING ---
  {
    id: 'msg-wa',
    category: 'MESSAGING',
    service_name: 'WhatsApp Web',
    primary_domain: 'web.whatsapp.com',
    probe_url: 'https://web.whatsapp.com',
    expected_identifiers: ['whatsapp', 'meta', 'fbcdn'],
    allowed_domains: ['whatsapp.com', 'whatsapp.net', 'fbcdn.net', 'facebook.com', 'meta.com']
  },
  {
    id: 'msg-tg',
    category: 'MESSAGING',
    service_name: 'Telegram Web',
    primary_domain: 'web.telegram.org',
    probe_url: 'https://web.telegram.org',
    expected_identifiers: ['telegram', 't.me'],
    allowed_domains: ['telegram.org', 't.me']
  },
  {
    id: 'msg-ms',
    category: 'MESSAGING',
    service_name: 'Messenger',
    primary_domain: 'www.messenger.com',
    probe_url: 'https://www.messenger.com',
    expected_identifiers: ['messenger', 'facebook', 'meta', 'msgr', 'fbcdn'],
    allowed_domains: ['messenger.com', 'facebook.com', 'fb.com', 'meta.com', 'fbcdn.net', 'facebook.net']
  },
  {
    id: 'msg-dc',
    category: 'MESSAGING',
    service_name: 'Discord',
    primary_domain: 'discord.com',
    probe_url: 'https://discord.com',
    expected_identifiers: ['discord', 'discordapp'],
    allowed_domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discord.media']
  },
  {
    id: 'msg-sg',
    category: 'MESSAGING',
    service_name: 'Signal',
    primary_domain: 'signal.org',
    probe_url: 'https://signal.org',
    expected_identifiers: ['signal', 'whispersystems'],
    allowed_domains: ['signal.org', 'whispersystems.org']
  },

  // --- CLOUD STORAGE ---
  {
    id: 'cld-gd',
    category: 'CLOUD_STORAGE',
    service_name: 'Google Drive',
    primary_domain: 'drive.google.com',
    probe_url: 'https://drive.google.com',
    expected_identifiers: ['google', 'drive', 'accounts.google', 'service=wise'],
    allowed_domains: ['google.com', 'googleusercontent.com', 'gstatic.com', 'accounts.google.com', 'google.co.in', '1e100.net']
  },
  {
    id: 'cld-db',
    category: 'CLOUD_STORAGE',
    service_name: 'Dropbox',
    primary_domain: 'www.dropbox.com',
    probe_url: 'https://www.dropbox.com',
    expected_identifiers: ['dropbox', 'dropboxstatic'],
    allowed_domains: ['dropbox.com', 'dropboxstatic.com', 'dropboxusercontent.com', 'dropbox-dns.com', 'db.tt']
  },
  {
    id: 'cld-od',
    category: 'CLOUD_STORAGE',
    service_name: 'OneDrive',
    primary_domain: 'onedrive.live.com',
    probe_url: 'https://onedrive.live.com',
    expected_identifiers: ['onedrive', 'live.com', 'microsoft', 'sharepoint', '1drv', 'login', 'office', 'live'],
    allowed_domains: ['live.com', 'microsoft.com', 'office.com', 'sharepoint.com', 'microsoftonline.com', 'onedrive.live.com', 'onedrive.com', '1drv.ms', 'live.net', 'azureedge.net', 'login.live.com', 'login.microsoftonline.com', 'msftauth.net', 'msauth.net']
  },
  {
    id: 'cld-bx',
    category: 'CLOUD_STORAGE',
    service_name: 'Box',
    primary_domain: 'www.box.com',
    probe_url: 'https://www.box.com',
    expected_identifiers: ['box.com', 'box', 'boxcdn'],
    allowed_domains: ['box.com', 'boxcdn.net', 'account.box.com', 'boxcloud.com']
  },
  {
    id: 'cld-ic',
    category: 'CLOUD_STORAGE',
    service_name: 'iCloud Drive',
    primary_domain: 'www.icloud.com',
    probe_url: 'https://www.icloud.com',
    expected_identifiers: ['icloud', 'apple'],
    allowed_domains: ['icloud.com', 'apple.com', 'apple-cloudkit.com', 'mzstatic.com']
  }
];

export interface WebAccessDetectorOptions {
  targets?: WebAccessTarget[];
  dnsTimeoutMs?: number;
  connectionTimeoutMs?: number;
  requestTimeoutMs?: number;
  maxResponseSizeBytes?: number;
  maxRedirects?: number;
  concurrencyLimit?: number;
  maxRetries?: number;
  mockProbeHandler?: (target: WebAccessTarget) => Promise<WebTargetResult>;
}

export class WebAccessDetector {
  private targets: WebAccessTarget[];
  private dnsTimeoutMs: number;
  private connectionTimeoutMs: number;
  private requestTimeoutMs: number;
  private maxResponseSizeBytes: number;
  private maxRedirects: number;
  private concurrencyLimit: number;
  private maxRetries: number;
  private mockProbeHandler?: (target: WebAccessTarget) => Promise<WebTargetResult>;

  constructor(options: WebAccessDetectorOptions = {}) {
    this.targets = options.targets || DEFAULT_WEB_TARGETS;
    this.dnsTimeoutMs = options.dnsTimeoutMs || 3000;
    this.connectionTimeoutMs = options.connectionTimeoutMs || 5000;
    this.requestTimeoutMs = options.requestTimeoutMs || 7000;
    this.maxResponseSizeBytes = options.maxResponseSizeBytes || 65536; // 64 KB cap
    this.maxRedirects = options.maxRedirects || 5;
    this.concurrencyLimit = options.concurrencyLimit || 6;
    this.maxRetries = options.maxRetries || 2; // Up to 2 attempts total
    this.mockProbeHandler = options.mockProbeHandler;
  }

  public getTargets(): WebAccessTarget[] {
    return this.targets;
  }

  /**
   * Run full bounded web accessibility detection across all configured targets
   */
  public async detectAll(): Promise<WebTargetResult[]> {
    const results: WebTargetResult[] = [];
    const queue = [...this.targets];
    const executing: Promise<void>[] = [];

    const runWorker = async () => {
      while (queue.length > 0) {
        const target = queue.shift();
        if (!target) break;
        const result = await this.probeTarget(target);
        results.push(result);
      }
    };

    const workerCount = Math.min(this.concurrencyLimit, this.targets.length);
    for (let i = 0; i < workerCount; i++) {
      executing.push(runWorker());
    }

    await Promise.all(executing);
    return results;
  }

  /**
   * Run detection for a specific category
   */
  public async detectCategory(category: WebAccessCategory): Promise<WebTargetResult[]> {
    const categoryTargets = this.targets.filter(t => t.category === category);
    const results: WebTargetResult[] = [];
    for (const target of categoryTargets) {
      results.push(await this.probeTarget(target));
    }
    return results;
  }

  /**
   * Perform bounded probe on a single target with multi-stage verification and bounded retries.
   */
  public async probeTarget(target: WebAccessTarget): Promise<WebTargetResult> {
    const timestamp = new Date().toISOString();

    let lastResult: WebTargetResult | undefined;
    const maxAttempts = Math.max(1, this.maxRetries);

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      if (this.mockProbeHandler) {
        const mockRes = await this.mockProbeHandler(target);
        const resultWithAttempt = {
          ...mockRes,
          probeAttempts: mockRes.probeAttempts ?? attempt
        };
        if (resultWithAttempt.status === 'ACCESSIBLE' || resultWithAttempt.status === 'BLOCKED') {
          return resultWithAttempt;
        }
        lastResult = resultWithAttempt;
        if (resultWithAttempt.status === 'UNREACHABLE' && attempt < maxAttempts) {
          continue;
        }
        return lastResult;
      }

      const startTime = Date.now();
      try {
        const parsedUrl = new URL(target.probe_url);

        // Enforce strict HTTPS requirement
        if (parsedUrl.protocol !== 'https:') {
          return {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'INDETERMINATE',
            confidence: 'LOW',
            detectionMethod: 'HTTPS_PROBE',
            networkReachable: false,
            policyBlockDetected: false,
            serviceIdentityConfirmed: false,
            probeAttempts: attempt,
            reason: `Insecure probe URL protocol '${parsedUrl.protocol}' rejected. Only deterministic HTTPS signals are allowed.`,
            responseTimeMs: Date.now() - startTime,
            timestamp
          };
        }

        // Stage 1: DNS Resolution Check & Sinkhole Detection
        let dnsAddresses: string[] = [];
        try {
          let timerId: NodeJS.Timeout | undefined;
          const lookupPromise = dns.lookup(parsedUrl.hostname, { all: true });
          const timerPromise = new Promise<never>((_, reject) => {
            timerId = setTimeout(() => reject(new Error('DNS resolution timed out')), this.dnsTimeoutMs);
          });
          const lookupResult = await Promise.race([lookupPromise, timerPromise]);
          if (timerId) clearTimeout(timerId);
          dnsAddresses = lookupResult.map(r => r.address);
        } catch (dnsErr: any) {
          const code = dnsErr?.code;
          const msg = dnsErr?.message || '';

          if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
            // NXDOMAIN is INDETERMINATE unless confirmed sinkhole
            lastResult = {
              category: target.category,
              service: target.service_name,
              target_domain: target.primary_domain,
              status: 'INDETERMINATE',
              confidence: 'LOW',
              detectionMethod: 'DNS_TCP_PROBE',
              networkReachable: false,
              policyBlockDetected: false,
              serviceIdentityConfirmed: false,
              probeAttempts: attempt,
              reason: `DNS lookup failed (NXDOMAIN / unresolvable): ${dnsErr?.message || 'Unknown DNS error'}`,
              responseTimeMs: Date.now() - startTime,
              timestamp
            };
            // Retry if attempts remain
            if (attempt < maxAttempts) {
              await new Promise(r => setTimeout(r, 150));
              continue;
            }
            return lastResult;
          }

          if (msg.includes('timed out') || code === 'ETIMEDOUT') {
            lastResult = {
              category: target.category,
              service: target.service_name,
              target_domain: target.primary_domain,
              status: 'UNREACHABLE',
              confidence: 'MEDIUM',
              detectionMethod: 'DNS_TCP_PROBE',
              networkReachable: false,
              policyBlockDetected: false,
              serviceIdentityConfirmed: false,
              probeAttempts: attempt,
              reason: 'DNS resolution timed out',
              responseTimeMs: Date.now() - startTime,
              timestamp
            };
            if (attempt < maxAttempts) {
              await new Promise(r => setTimeout(r, 150));
              continue;
            }
            return lastResult;
          }

          lastResult = {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'INDETERMINATE',
            confidence: 'LOW',
            detectionMethod: 'DNS_TCP_PROBE',
            networkReachable: false,
            policyBlockDetected: false,
            serviceIdentityConfirmed: false,
            probeAttempts: attempt,
            reason: `DNS lookup failed: ${dnsErr?.message || 'Unknown DNS error'}`,
            responseTimeMs: Date.now() - startTime,
            timestamp
          };
          if (attempt < maxAttempts) {
            await new Promise(r => setTimeout(r, 150));
            continue;
          }
          return lastResult;
        }

        // Check for local DNS Sinkholes (127.0.0.1, 0.0.0.0, etc.)
        const isSinkhole = dnsAddresses.some(addr =>
          addr === '127.0.0.1' ||
          addr === '0.0.0.0' ||
          addr === '::1' ||
          addr === '10.0.0.0' ||
          addr.startsWith('127.')
        );

        if (isSinkhole) {
          return {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'BLOCKED',
            confidence: 'HIGH',
            detectionMethod: 'DNS_TCP_PROBE',
            networkReachable: true,
            policyBlockDetected: true,
            serviceIdentityConfirmed: false,
            probeAttempts: attempt,
            reason: `DNS resolved to loopback sinkhole address: ${dnsAddresses.join(', ')}`,
            responseTimeMs: Date.now() - startTime,
            timestamp
          };
        }

        // Stage 2 & 3: HTTPS Request, TLS Handshake, and Content Inspection
        const httpResult = await this.performBoundedRequest(target.probe_url, target, 0);
        const elapsed = Date.now() - startTime;

        const completeResult: WebTargetResult = {
          ...httpResult,
          probeAttempts: attempt,
          responseTimeMs: elapsed,
          timestamp
        };

        // If target is accessible or explicitly blocked by policy, return immediately (no retry needed)
        if (completeResult.status === 'ACCESSIBLE' || completeResult.status === 'BLOCKED') {
          return completeResult;
        }

        // For UNREACHABLE or transient errors, attempt retry if available
        lastResult = completeResult;
        if (completeResult.status === 'UNREACHABLE' && attempt < maxAttempts) {
          await new Promise(r => setTimeout(r, 150));
          continue;
        }

        return completeResult;
      } catch (err: any) {
        const elapsed = Date.now() - startTime;
        const errMsg = err?.message || '';

        // TLS Enterprise Interception Check
        if (/fortiguard|zscaler|paloalto|bluecoat|cisco\s*umbrella|enterprise\s*ca/i.test(errMsg)) {
          return {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'BLOCKED',
            confidence: 'HIGH',
            detectionMethod: 'HTTPS_PROBE',
            networkReachable: true,
            policyBlockDetected: true,
            serviceIdentityConfirmed: false,
            probeAttempts: attempt,
            reason: `Enterprise TLS interception policy detected: ${errMsg}`,
            responseTimeMs: elapsed,
            timestamp
          };
        }

        // Generic TLS / Certificate issues without policy signatures -> INDETERMINATE
        if (/certificate|self-signed|DEPTH_ZERO_SELF_SIGNED_CERT|CERT_AUTHORITY_INVALID|SSL/i.test(errMsg)) {
          return {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'INDETERMINATE',
            confidence: 'LOW',
            detectionMethod: 'HTTPS_PROBE',
            networkReachable: true,
            policyBlockDetected: false,
            serviceIdentityConfirmed: false,
            probeAttempts: attempt,
            reason: `TLS certificate / handshake error without policy signatures: ${errMsg}`,
            responseTimeMs: elapsed,
            timestamp
          };
        }

        // Connection refused / reset / timeout -> UNREACHABLE with retry
        if (/ECONNREFUSED|ECONNRESET|ETIMEDOUT|timeout/i.test(errMsg)) {
          lastResult = {
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'UNREACHABLE',
            confidence: 'MEDIUM',
            detectionMethod: 'HTTPS_PROBE',
            networkReachable: false,
            policyBlockDetected: false,
            serviceIdentityConfirmed: false,
            probeAttempts: attempt,
            reason: `Connection rejected or timed out: ${errMsg}`,
            responseTimeMs: elapsed,
            timestamp
          };
          if (attempt < maxAttempts) {
            await new Promise(r => setTimeout(r, 150));
            continue;
          }
          return lastResult;
        }

        lastResult = {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: false,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          probeAttempts: attempt,
          reason: `Probe error: ${errMsg}`,
          responseTimeMs: elapsed,
          timestamp
        };
        if (attempt < maxAttempts) {
          await new Promise(r => setTimeout(r, 150));
          continue;
        }
        return lastResult;
      }
    }

    return lastResult || {
      category: target.category,
      service: target.service_name,
      target_domain: target.primary_domain,
      status: 'INDETERMINATE',
      confidence: 'LOW',
      detectionMethod: 'HTTPS_PROBE',
      networkReachable: false,
      policyBlockDetected: false,
      serviceIdentityConfirmed: false,
      probeAttempts: maxAttempts,
      reason: 'Probe attempts exhausted without conclusive signal',
      timestamp
    };
  }

  /**
   * Internal bounded HTTPS client with strict redirects, domain validation, timeout, size limits, and false-positive defense
   */
  private performBoundedRequest(
    targetUrl: string,
    target: WebAccessTarget,
    redirectCount: number
  ): Promise<Omit<WebTargetResult, 'responseTimeMs' | 'timestamp' | 'probeAttempts'>> {
    return new Promise((resolve) => {
      if (redirectCount > this.maxRedirects) {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: true,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          reason: `Excessive redirects encountered during probe (${redirectCount} > ${this.maxRedirects})`
        });
      }

      let parsed: URL;
      try {
        parsed = new URL(targetUrl);
      } catch (err: any) {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: false,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          reason: `Malformed probe URL: ${err?.message}`
        });
      }

      // Enforce strict HTTPS requirement
      if (parsed.protocol !== 'https:') {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: false,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          reason: `Insecure probe URL protocol '${parsed.protocol}' rejected. Only deterministic HTTPS probes are permitted.`
        });
      }

      // Validate that the request domain is allowed for this target service
      const allowedDomains = target.allowed_domains && target.allowed_domains.length > 0
        ? target.allowed_domains
        : [target.primary_domain];

      if (!isDomainAllowed(parsed.hostname, allowedDomains)) {
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: true,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          reason: `Probe domain '${parsed.hostname}' does not match allowed domain set for ${target.service_name}`
        });
      }

      const client = https;
      let settled = false;

      const reqPath = (parsed.pathname || '/') + (parsed.search || '');

      const req = client.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || 443,
          path: reqPath,
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'close'
          },
          timeout: this.requestTimeoutMs
        },
        (res) => {
          const statusCode = res.statusCode || 0;
          const headers = res.headers;
          const location = headers.location;

          // 1. Handle Redirects (301, 302, 303, 307, 308)
          if ([301, 302, 303, 307, 308].includes(statusCode) && location) {
            res.resume(); // Drain stream to release underlying socket

            if (redirectCount >= this.maxRedirects) {
              settled = true;
              return resolve({
                category: target.category,
                service: target.service_name,
                target_domain: target.primary_domain,
                status: 'ACCESSIBLE',
                confidence: 'MEDIUM',
                detectionMethod: 'HTTPS_PROBE',
                httpStatusCode: statusCode,
                networkReachable: true,
                policyBlockDetected: false,
                serviceIdentityConfirmed: true,
                reason: `Target accessible with HTTP ${statusCode} redirect (max redirects reached)`
              });
            }

            let nextUrl: string;
            let nextParsed: URL;
            try {
              nextUrl = new URL(location, targetUrl).toString();
              nextParsed = new URL(nextUrl);
            } catch {
              nextUrl = location;
              nextParsed = parsed;
            }

            // Check for corporate proxy block redirect (e.g., block.corporate.com, fortiguard, zscaler)
            if (/block|deny|firewall|fortinet|paloalto|zscaler|umbrella|barracuda/i.test(nextUrl)) {
              settled = true;
              return resolve({
                category: target.category,
                service: target.service_name,
                target_domain: target.primary_domain,
                status: 'BLOCKED',
                confidence: 'HIGH',
                detectionMethod: 'HTTPS_PROBE',
                httpStatusCode: statusCode,
                networkReachable: true,
                policyBlockDetected: true,
                serviceIdentityConfirmed: false,
                reason: `Redirected to corporate firewall block portal: ${nextUrl}`
              });
            }

            // Check for captive portal redirect (exclude legitimate target auth / SSO endpoints)
            const isTargetAuth = /accounts\.google\.com|login\.live\.com|login\.microsoftonline\.com|appleid\.apple\.com|auth\.proton\.me|login\.yahoo\.com|account\.box\.com|auth0|oauth/i.test(nextUrl);
            if (!isTargetAuth && /(captive|hotspot-login|wifilogin|portal\/login|radius-login)/i.test(nextUrl)) {
              settled = true;
              return resolve({
                category: target.category,
                service: target.service_name,
                target_domain: target.primary_domain,
                status: 'BLOCKED',
                confidence: 'HIGH',
                detectionMethod: 'HTTPS_PROBE',
                httpStatusCode: statusCode,
                networkReachable: true,
                policyBlockDetected: true,
                serviceIdentityConfirmed: false,
                reason: `Redirected to captive / network login portal: ${nextUrl}`
              });
            }

            // Validate that redirect hostname stays within the approved domain set
            if (!isDomainAllowed(nextParsed.hostname, allowedDomains)) {
              settled = true;
              return resolve({
                category: target.category,
                service: target.service_name,
                target_domain: target.primary_domain,
                status: 'INDETERMINATE',
                confidence: 'MEDIUM',
                detectionMethod: 'HTTPS_PROBE',
                httpStatusCode: statusCode,
                networkReachable: true,
                policyBlockDetected: false,
                serviceIdentityConfirmed: false,
                reason: `Redirect target '${nextParsed.hostname}' left approved domain set for ${target.service_name}`
              });
            }

            // Valid target service redirect within approved domain set
            settled = true;
            return this.performBoundedRequest(nextUrl, target, redirectCount + 1).then(resolve);
          }

          // Collect bounded body snippet for verification (up to maxResponseSizeBytes)
          let bodyBuffer = '';
          res.setEncoding('utf8');

          res.on('data', (chunk) => {
            if (bodyBuffer.length < this.maxResponseSizeBytes) {
              bodyBuffer += chunk;
            } else {
              res.resume(); // Discard remaining chunks
            }
          });

          const finishResponse = () => {
            if (settled) return;
            settled = true;
            try {
              req.destroy();
            } catch {}
            const classification = this.classifyResponse(statusCode, headers, bodyBuffer, target);
            return resolve(classification);
          };

          res.on('end', finishResponse);
          res.on('close', finishResponse);
          res.on('error', finishResponse);
        }
      );

      req.setTimeout(this.requestTimeoutMs, () => {
        if (settled) return;
        settled = true;
        req.destroy();
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'UNREACHABLE',
          confidence: 'MEDIUM',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: false,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          reason: 'Network request timed out'
        });
      });

      req.on('timeout', () => {
        if (settled) return;
        settled = true;
        req.destroy();
        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'UNREACHABLE',
          confidence: 'MEDIUM',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: false,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          reason: 'Network request timed out'
        });
      });

      req.on('error', (err: any) => {
        if (settled) return;
        settled = true;

        if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN/i.test(err?.code || '')) {
          return resolve({
            category: target.category,
            service: target.service_name,
            target_domain: target.primary_domain,
            status: 'UNREACHABLE',
            confidence: 'MEDIUM',
            detectionMethod: 'HTTPS_PROBE',
            networkReachable: false,
            policyBlockDetected: false,
            serviceIdentityConfirmed: false,
            reason: `Connection refused / unresolvable: ${err?.message}`
          });
        }

        return resolve({
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'INDETERMINATE',
          confidence: 'LOW',
          detectionMethod: 'HTTPS_PROBE',
          networkReachable: false,
          policyBlockDetected: false,
          serviceIdentityConfirmed: false,
          reason: `Network probe error: ${err?.message}`
        });
      });

      req.end();
    });
  }

  /**
   * Conservative deterministic classification.
   *
   * ACCESSIBLE: Valid HTTPS response (200..399, or 400/405 from validated domain) without policy-block evidence.
   * BLOCKED: ONLY when explicit corporate policy/firewall block page or filtering evidence exists.
   * UNREACHABLE: Handled at transport layer when connection fails after retries.
   * INDETERMINATE: 401/403 without policy signatures, 451 without policy signatures, 500-504, or ambiguous responses.
   */
  public classifyResponse(
    statusCode: number,
    headers: http.IncomingHttpHeaders,
    body: string,
    target: WebAccessTarget
  ): Omit<WebTargetResult, 'responseTimeMs' | 'timestamp' | 'probeAttempts'> {
    const lowerBody = body.toLowerCase();
    const serverHeader = String(headers['server'] || '').toLowerCase();
    const setCookieHeader = String(headers['set-cookie'] || '').toLowerCase();
    const cspHeader = String(headers['content-security-policy'] || '').toLowerCase();
    const locationHeader = String(headers['location'] || '').toLowerCase();
    const allHeaders = `${serverHeader} ${setCookieHeader} ${cspHeader} ${locationHeader}`.toLowerCase();

    // 1. Corporate Firewall / Proxy Policy Block Signature Detection
    const blockPageSignatures = [
      'access denied',
      'access is denied',
      'url block',
      'website blocked',
      'category blocked',
      'policy violation',
      'content filter',
      'fortiguard',
      'palo alto networks',
      'zscaler',
      'cisco umbrella',
      'sonicwall',
      'sophos',
      'blue coat',
      'squid/proxy',
      'squid error',
      'the following error was encountered',
      'websense',
      'barracuda',
      'access to this web page is restricted',
      'blocked by administrator',
      'restricted by organization',
      'firewall block',
      'web filter'
    ];

    const hasBlockSignature = blockPageSignatures.some(sig => lowerBody.includes(sig) || allHeaders.includes(sig));

    if (hasBlockSignature) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'BLOCKED',
        confidence: 'HIGH',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        networkReachable: true,
        policyBlockDetected: true,
        serviceIdentityConfirmed: false,
        reason: 'Corporate firewall / security gateway policy block page detected'
      };
    }

    // 2. Captive Portal Detection in Body
    if (lowerBody.includes('captive portal') || lowerBody.includes('wifi authentication') || lowerBody.includes('hotspot login')) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'BLOCKED',
        confidence: 'HIGH',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        networkReachable: true,
        policyBlockDetected: true,
        serviceIdentityConfirmed: false,
        reason: 'Network intercepted by captive portal login screen'
      };
    }

    // 3. HTTP 451: Unavailable for Legal / Policy Reasons
    if (statusCode === 451) {
      if (hasBlockSignature || /legal|policy|restricted|court order|censorship|copyright/i.test(lowerBody)) {
        return {
          category: target.category,
          service: target.service_name,
          target_domain: target.primary_domain,
          status: 'BLOCKED',
          confidence: 'HIGH',
          detectionMethod: 'HTTPS_PROBE',
          httpStatusCode: 451,
          networkReachable: true,
          policyBlockDetected: true,
          serviceIdentityConfirmed: false,
          reason: 'HTTP 451: Unavailable for Legal/Policy Reasons (explicit policy block evidence confirmed)'
        };
      }

      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'INDETERMINATE',
        confidence: 'MEDIUM',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: 451,
        networkReachable: true,
        policyBlockDetected: false,
        serviceIdentityConfirmed: true,
        reason: 'HTTP 451: Service returned 451 without explicit enterprise policy block evidence'
      };
    }

    // 4. HTTP 401 / 403: Forbidden or Unauthorized
    // CRITICAL: 403 MUST NOT automatically mean BLOCKED.
    // Without explicit corporate/policy block evidence, anti-bot/CDN/auth 403 is INDETERMINATE.
    if (statusCode === 401 || statusCode === 403) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'INDETERMINATE',
        confidence: 'MEDIUM',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        networkReachable: true,
        policyBlockDetected: false,
        serviceIdentityConfirmed: true,
        reason: `HTTP ${statusCode}: Target service returned access/authentication challenge without enterprise policy block signatures`
      };
    }

    // 5. Temporary Service Outage or Server Error (HTTP 500..504)
    if (statusCode >= 500 && statusCode <= 504) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'INDETERMINATE',
        confidence: 'LOW',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        networkReachable: true,
        policyBlockDetected: false,
        serviceIdentityConfirmed: false,
        reason: `Target server error HTTP ${statusCode} (possible temporary outage or upstream failure)`
      };
    }

    // 6. Valid Response from Target (HTTP 200..399 or 400/405 without policy block)
    if ((statusCode >= 200 && statusCode < 400) || statusCode === 400 || statusCode === 405) {
      return {
        category: target.category,
        service: target.service_name,
        target_domain: target.primary_domain,
        status: 'ACCESSIBLE',
        confidence: 'HIGH',
        detectionMethod: 'HTTPS_PROBE',
        httpStatusCode: statusCode,
        networkReachable: true,
        policyBlockDetected: false,
        serviceIdentityConfirmed: true,
        reason: `Target accessible with verified HTTPS response from ${target.primary_domain} (HTTP ${statusCode})`
      };
    }

    // 7. Generic or unhandled HTTP status -> INDETERMINATE
    return {
      category: target.category,
      service: target.service_name,
      target_domain: target.primary_domain,
      status: 'INDETERMINATE',
      confidence: 'LOW',
      detectionMethod: 'HTTPS_PROBE',
      httpStatusCode: statusCode,
      networkReachable: true,
      policyBlockDetected: false,
      serviceIdentityConfirmed: false,
      reason: `Ambiguous HTTP ${statusCode} response without definitive accessibility confirmation`
    };
  }
}
