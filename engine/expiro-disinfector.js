/**
 * engine/expiro-disinfector.js
 *
 * Expiro remediation for GSM Shield AV.
 *
 * POLICY (v3, 2026-10-22)
 * -----------------------
 * Expiro hides the original bytes it overwrites (a patched CALL in the code
 * section and the relocation table) inside an encrypted, compressed body
 * (Quick Heal / Seqrite 2023; McAfee notes some variants also shrink and
 * encrypt the relocation table to break naive repair). Undoing that requires
 * decrypting the virus body, which this product does not implement.
 *
 * The previous "surgical" repair cleared section flags, moved the entry point
 * to an arbitrary .text offset and truncated overlays, then "verified" the
 * result with the same heuristics that already scored real Expiro at 0. On a
 * real infection that leaves the virus reachable and can break the host, and
 * truncating overlays destroys legitimate installers. It has been removed.
 *
 * Remediation is now, in order:
 *   1. Protected Windows paths: never touched; return SFC/DISM guidance.
 *   2. Restore a VERIFIED clean copy: same build (COFF timestamp, entry point,
 *      section layout) AND structurally clean, from a caller-supplied trusted
 *      directory (e.g. a freshly extracted vendor package).
 *   3. Otherwise quarantine (the quarantine module stores files neutralized,
 *      so they cannot be executed) and tell the user to reinstall.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { analyzeExpiroStructure, buildIdentity, isSameBuild } = require('./expiro-structural');

const DEFAULT_THREAT = 'Virus:Win32/Expiro';

class ExpiroDisinfector {
  /**
   * @param {object} quarantineModule - must expose quarantineFile(path, threatName)
   * @param {object} [options]
   * @param {string[]} [options.trustedSourceDirs] - directories holding known-clean vendor copies
   */
  constructor(quarantineModule, options = {}) {
    this.quarantineModule = quarantineModule;
    this.trustedSourceDirs = Array.isArray(options.trustedSourceDirs) ? options.trustedSourceDirs : [];
    this.disinfectionLog = [];
  }

  /**
   * Determine whether a path is a protected Windows component.
   * @param {string} filePath
   * @returns {{isCritical: boolean, requiresBackup: boolean, canAutoRemove: boolean, reason: string}}
   */
  assessFileCriticality(filePath) {
    const normalizedPath = String(filePath).toLowerCase().replace(/\//g, '\\');
    const criticalPaths = [
      'c:\\windows\\system32',
      'c:\\windows\\syswow64',
      'c:\\program files\\windows defender',
      'c:\\windows\\winsxs',
      'c:\\windows\\servicing',
      'c:\\windows\\assembly',
      'c:\\windows\\microsoft.net',
    ];
    const isCritical = criticalPaths.some((p) => normalizedPath.startsWith(p));
    const criticalProcesses = ['explorer.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe', 'services.exe', 'smss.exe'];
    const isCriticalProcess = criticalProcesses.includes(path.basename(String(filePath)).toLowerCase());
    return {
      isCritical: isCritical || isCriticalProcess,
      requiresBackup: true,
      canAutoRemove: !isCritical && !isCriticalProcess,
      reason: isCritical ? 'System directory' : isCriticalProcess ? 'Critical process' : 'User application',
    };
  }

  /**
   * Quarantine an infected file (the quarantine module neutralizes it).
   * @returns {Promise<object>}
   */
  async quarantineInfectedFile(filePath, threatName) {
    try {
      const assessment = this.assessFileCriticality(filePath);
      const fileHash = await this.calculateFileHash(filePath);
      const q = await this.quarantineModule.quarantineFile(filePath, threatName);
      const result = {
        success: true,
        action: 'quarantined',
        filePath,
        threatName,
        fileHash,
        criticality: assessment,
        quarantinePath: q && q.quarantinePath,
        timestamp: new Date().toISOString(),
        canRestore: true,
      };
      this.disinfectionLog.push(result);
      return result;
    } catch (error) {
      console.error(`[expiro-disinfector] Quarantine failed: ${error.message}`);
      return { success: false, action: 'failed', filePath, error: error.message, timestamp: new Date().toISOString() };
    }
  }

  /**
   * Find candidate clean copies by file name in the caller-supplied trusted dirs.
   * Candidates are only proposals; restoreFromCleanSource() verifies them.
   * @param {string} filePath
   * @returns {string[]}
   */
  findCleanSources(filePath) {
    const name = path.basename(String(filePath)).toLowerCase();
    const out = [];
    for (const dir of this.trustedSourceDirs) {
      try {
        const candidate = path.join(dir, path.basename(filePath));
        if (fs.existsSync(candidate)) { out.push(candidate); continue; }
        for (const entry of fs.readdirSync(dir)) {
          if (entry.toLowerCase() === name) out.push(path.join(dir, entry));
        }
      } catch (_) { /* unreadable dir: skip */ }
    }
    return out;
  }

  /**
   * Check that a candidate is safe to put in place of `infectedPath`.
   * @returns {{ok: boolean, reason: string}}
   */
  verifyCleanCandidate(candidate, infectedPath) {
    const s = analyzeExpiroStructure(candidate);
    if (!s.isPE) return { ok: false, reason: 'candidate is not a PE file' };
    if (s.verdict !== 'clean') return { ok: false, reason: `candidate is not structurally clean (${s.verdict})` };
    const want = buildIdentity(infectedPath);
    const have = buildIdentity(candidate);
    if (!isSameBuild(want, have)) return { ok: false, reason: 'candidate is a different build (timestamp/entry point/section layout differ)' };
    return { ok: true, reason: 'same build and structurally clean' };
  }

  /**
   * Replace an infected file with a verified clean copy from a trusted dir.
   * @returns {Promise<object>}
   */
  async restoreFromCleanSource(infectedPath, threatName = DEFAULT_THREAT) {
    const candidates = this.findCleanSources(infectedPath);
    if (candidates.length === 0) {
      return { success: false, action: 'no_clean_source', message: 'No trusted clean copy supplied' };
    }
    const rejected = [];
    for (const candidate of candidates) {
      const check = this.verifyCleanCandidate(candidate, infectedPath);
      if (!check.ok) { rejected.push(`${candidate}: ${check.reason}`); continue; }
      const q = await this.quarantineInfectedFile(infectedPath, threatName);
      if (!q.success) return { success: false, action: 'restore_failed', error: `could not quarantine infected file: ${q.error}` };
      try {
        fs.copyFileSync(candidate, infectedPath);
      } catch (err) {
        return { success: false, action: 'restore_failed', error: err.message, quarantinePath: q.quarantinePath,
          recommendation: 'The infected file is in quarantine; reinstall the application from the vendor.' };
      }
      const after = analyzeExpiroStructure(infectedPath);
      return {
        success: after.verdict === 'clean',
        action: 'restored',
        filePath: infectedPath,
        sourceFile: candidate,
        previousFile: q.quarantinePath,
        verification: after.verdict,
        timestamp: new Date().toISOString(),
      };
    }
    return { success: false, action: 'no_clean_source', message: 'No candidate passed verification', rejected };
  }

  calculateFileHash(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      stream.on('data', (d) => hash.update(d));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  /**
   * Main remediation workflow (see policy in the header).
   * @param {string} filePath
   * @param {object} detectionResult - result from expiro-detector
   * @returns {Promise<object>}
   */
  async disinfectFile(filePath, detectionResult = {}) {
    const threatName = detectionResult.threatName || DEFAULT_THREAT;
    const assessment = this.assessFileCriticality(filePath);

    if (assessment.isCritical) {
      const r = {
        success: false,
        action: 'system_protected',
        filePath,
        isCritical: true,
        error: 'Protected Windows component cannot be modified by GSM Shield.',
        recommendation: 'From an elevated prompt run "DISM /Online /Cleanup-Image /RestoreHealth" and then "sfc /scannow". ' +
          'If the component store copy is also infected, use a repair install from verified Microsoft media. See research/DISINFECTION_PROCEDURE.md.',
        timestamp: new Date().toISOString(),
      };
      this.disinfectionLog.push(r);
      return r;
    }

    const restore = await this.restoreFromCleanSource(filePath, threatName);
    if (restore.success) {
      this.disinfectionLog.push(restore);
      return restore;
    }

    const q = await this.quarantineInfectedFile(filePath, threatName);
    if (q.success) {
      q.recommendation = 'Reinstall this application from the vendor. The infected file is quarantined in neutralized form and cannot be executed.';
      if (restore.rejected) q.rejectedCandidates = restore.rejected;
    }
    return q;
  }

  /**
   * Batch remediation; non-critical files first.
   */
  async disinfectBatch(detections, onProgress) {
    const results = { total: detections.length, successful: 0, failed: 0, disinfected: 0, quarantined: 0, restored: 0, details: [] };
    const sorted = [...detections].sort((a, b) =>
      Number(this.assessFileCriticality(a.filePath).isCritical) - Number(this.assessFileCriticality(b.filePath).isCritical));
    for (let i = 0; i < sorted.length; i++) {
      const detection = sorted[i];
      if (onProgress) onProgress({ current: i + 1, total: sorted.length, file: detection.filePath });
      const result = await this.disinfectFile(detection.filePath, detection);
      results.details.push(result);
      if (result.success) {
        results.successful++;
        if (result.action === 'quarantined') results.quarantined++;
        if (result.action === 'restored') { results.restored++; results.disinfected++; }
      } else {
        results.failed++;
      }
      await new Promise((resolve) => setImmediate(resolve));
    }
    return results;
  }

  getLog() {
    return this.disinfectionLog;
  }

  generateReport() {
    const report = [];
    report.push('='.repeat(70));
    report.push('EXPIRO DISINFECTION REPORT');
    report.push('='.repeat(70));
    report.push('');
    report.push(`Total Files Processed: ${this.disinfectionLog.length}`);
    report.push(`Successful: ${this.disinfectionLog.filter((r) => r.success).length}`);
    report.push(`Failed: ${this.disinfectionLog.filter((r) => !r.success).length}`);
    report.push('');
    for (const entry of this.disinfectionLog) {
      report.push(`File: ${entry.filePath}`);
      report.push(`Action: ${entry.action}`);
      report.push(`Status: ${entry.success ? 'SUCCESS' : 'FAILED'}`);
      if (entry.recommendation) report.push(`Recommendation: ${entry.recommendation}`);
      report.push('');
    }
    report.push('='.repeat(70));
    return report.join('\n');
  }
}

module.exports = ExpiroDisinfector;
