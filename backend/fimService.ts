import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export class FileIntegrityMonitor {
  private static criticalFiles = [
    'backend/auth.ts',
    'backend/licensing.ts',
    'backend/db.ts',
    'backend/routes.ts',
    'backend/securityMiddleware.ts',
    'backend/audit/verifiableReportService.ts'
  ];

  private static baselineHashes: Record<string, string> = {
    'backend/auth.ts': 'BASELINE_ANCHOR',
    'backend/licensing.ts': 'BASELINE_ANCHOR',
    'backend/db.ts': 'BASELINE_ANCHOR',
    'backend/routes.ts': 'BASELINE_ANCHOR',
    'backend/securityMiddleware.ts': 'BASELINE_ANCHOR',
    'backend/audit/verifiableReportService.ts': 'BASELINE_ANCHOR'
  };

  // Security Hardening #11: Track whether baselines were pre-computed (from manifest) or runtime-computed
  private static baselinesFromManifest = false;

  public static initializeBaseline(): void {
    const baseDir = process.cwd();

    // Attempt to load pre-computed baseline manifest (shipped from CI/CD)
    const manifestPath = path.join(baseDir, '.fim-baseline.json');
    if (fs.existsSync(manifestPath)) {
      try {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        if (manifest && typeof manifest === 'object') {
          let loaded = 0;
          for (const relPath of this.criticalFiles) {
            if (manifest[relPath] && typeof manifest[relPath] === 'string' && /^[0-9a-f]{64}$/.test(manifest[relPath])) {
              this.baselineHashes[relPath] = manifest[relPath];
              loaded++;
            }
          }
          if (loaded > 0) {
            this.baselinesFromManifest = true;
            console.log(`[FIM] Loaded ${loaded} pre-computed baseline hashes from manifest.`);
            return;
          }
        }
      } catch (e) {
        console.warn('[FIM] Failed to parse baseline manifest:', e);
      }
    }

    // Fallback: compute baselines at runtime (less secure, first-run scenario)
    console.warn('[FIM] WARNING: No pre-computed baseline manifest found. Computing baselines at runtime. This means the first run always passes even if files are already tampered.');
    console.warn('[FIM] To fix: Generate .fim-baseline.json from CI/CD using `FileIntegrityMonitor.generateManifest()`');

    for (const relPath of this.criticalFiles) {
      const fullPath = path.join(baseDir, relPath);
      if (fs.existsSync(fullPath)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const hash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
          this.baselineHashes[relPath] = hash;
        } catch (e) {
          // ignore
        }
      }
    }
  }

  public static verifyIntegrity(): { valid: boolean; modifiedFiles: string[]; baselinesFromManifest: boolean } {
    const modifiedFiles: string[] = [];
    const baseDir = process.cwd();

    for (const relPath of this.criticalFiles) {
      const fullPath = path.join(baseDir, relPath);
      if (!fs.existsSync(fullPath)) {
        continue;
      }
      try {
        const content = fs.readFileSync(fullPath, 'utf8');
        const hash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
        const baseline = this.baselineHashes[relPath];
        if (baseline && baseline !== 'BASELINE_ANCHOR' && baseline !== hash) {
          modifiedFiles.push(relPath);
        }
      } catch (err) {
        modifiedFiles.push(relPath);
      }
    }

    return {
      valid: modifiedFiles.length === 0,
      modifiedFiles,
      baselinesFromManifest: this.baselinesFromManifest
    };
  }

  /**
   * Generate a baseline manifest JSON for CI/CD to ship with the build.
   * Run this during your build pipeline and save the output to .fim-baseline.json
   */
  public static generateManifest(): Record<string, string> {
    const baseDir = process.cwd();
    const manifest: Record<string, string> = {};

    for (const relPath of this.criticalFiles) {
      const fullPath = path.join(baseDir, relPath);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, 'utf8');
        manifest[relPath] = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
      }
    }

    return manifest;
  }
}

// Initialize baseline on load
FileIntegrityMonitor.initializeBaseline();

