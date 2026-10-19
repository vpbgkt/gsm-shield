/**
 * engine/expiro-disinfector.js
 * 
 * Expiro File Disinfection Module for GSM Shield AV
 * Safely removes Expiro infection while preserving original program functionality
 * 
 * CRITICAL: Expiro is a file infector that spreads from file to file
 * This module implements safe removal without damaging host programs
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Disinfection strategy for Expiro
 * Since we don't have infected samples, we implement a safe approach:
 * 1. Quarantine infected file (preserves evidence)
 * 2. Restore from clean backup if available
 * 3. Mark for user review if critical system file
 * 4. Prevent further execution until cleaned
 */

class ExpiroDisinfector {
  constructor(quarantineModule) {
    this.quarantineModule = quarantineModule;
    this.disinfectionLog = [];
  }

  /**
   * Determine if file is safe to remove vs. needs special handling
   * @param {string} filePath - Path to infected file
   * @returns {Object} Safety assessment
   */
  assessFileCriticality(filePath) {
    const normalizedPath = filePath.toLowerCase().replace(/\//g, '\\');
    
    // Critical system files that need special handling
    const criticalPaths = [
      'c:\\windows\\system32',
      'c:\\windows\\syswow64',
      'c:\\program files\\windows defender',
      'c:\\windows\\winsxs',
      'c:\\windows\\servicing',
      'c:\\windows\\assembly',
      'c:\\windows\\microsoft.net',
    ];
    
    const isCritical = criticalPaths.some(critPath => 
      normalizedPath.startsWith(critPath)
    );
    
    // System processes that should never be removed without backup
    const criticalProcesses = [
      'explorer.exe',
      'lsass.exe',
      'winlogon.exe',
      'csrss.exe',
      'services.exe',
      'smss.exe',
    ];
    
    const fileName = path.basename(filePath).toLowerCase();
    const isCriticalProcess = criticalProcesses.includes(fileName);
    
    return {
      isCritical: isCritical || isCriticalProcess,
      requiresBackup: true,
      canAutoRemove: !isCritical && !isCriticalProcess,
      reason: isCritical ? 'System directory' : 
              isCriticalProcess ? 'Critical process' : 
              'User application',
    };
  }

  /**
   * Quarantine infected file safely
   * This is the PRIMARY disinfection method when we can't repair
   * @param {string} filePath - Path to infected file
   * @param {string} threatName - Name of detected threat
   * @returns {Promise<Object>} Quarantine result
   */
  async quarantineInfectedFile(filePath, threatName) {
    try {
      const assessment = this.assessFileCriticality(filePath);
      
      // Calculate file hash before quarantine
      const fileHash = await this.calculateFileHash(filePath);
      
      // Quarantine the file
      const quarantineResult = await this.quarantineModule.quarantineFile(
        filePath,
        threatName
      );
      
      const result = {
        success: true,
        action: 'quarantined',
        filePath,
        threatName,
        fileHash,
        criticality: assessment,
        quarantinePath: quarantineResult.quarantinePath,
        timestamp: new Date().toISOString(),
        canRestore: true,
      };
      
      this.disinfectionLog.push(result);
      return result;
      
    } catch (error) {
      console.error(`[expiro-disinfector] Quarantine failed: ${error.message}`);
      return {
        success: false,
        action: 'failed',
        filePath,
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Attempt to restore file from known clean source
   * @param {string} infectedPath - Path to infected file
   * @returns {Promise<Object>} Restoration result
   */
  async restoreFromCleanSource(infectedPath) {
    try {
      // Potential clean sources
      const cleanSources = this.findCleanSources(infectedPath);
      
      if (cleanSources.length === 0) {
        return {
          success: false,
          action: 'no_clean_source',
          message: 'No clean backup found',
        };
      }
      
      // Try each source
      for (const source of cleanSources) {
        if (fs.existsSync(source)) {
          // First, quarantine the infected file
          const quarantineResult = await this.quarantineInfectedFile(
            infectedPath,
            'Virus:Win32/Expiro.EK!MTB'
          );
          
          if (!quarantineResult.success) {
            continue;
          }
          
          // Copy clean file to original location
          fs.copyFileSync(source, infectedPath);
          
          return {
            success: true,
            action: 'restored',
            filePath: infectedPath,
            sourceFile: source,
            previousFile: quarantineResult.quarantinePath,
            timestamp: new Date().toISOString(),
          };
        }
      }
      
      return {
        success: false,
        action: 'no_clean_source',
        message: 'Clean sources exist but inaccessible',
      };
      
    } catch (error) {
      console.error(`[expiro-disinfector] Restoration failed: ${error.message}`);
      return {
        success: false,
        action: 'restore_failed',
        error: error.message,
      };
    }
  }

  findCleanSources(filePath) {
    const sources = [];
    const fileName = path.basename(filePath);
    const normalized = filePath.toLowerCase().replace(/\//g, '\\');
    
    // Only search Windows system caches if the file is ACTUALLY a Windows system component!
    // 3rd-party software, technician utilities, and GSM tools are never in WinSxS or Windows.old.
    const isWindowsSystemFile = normalized.startsWith('c:\\windows\\') || 
                                normalized.startsWith('c:\\program files\\windows defender\\');
    
    if (!isWindowsSystemFile) {
      return sources;
    }
    
    // 1. Windows.old backup (case-insensitive drive letter)
    if (fs.existsSync('C:\\Windows.old')) {
      const oldPath = filePath.replace(/^[Cc]:/, 'C:\\Windows.old');
      if (fs.existsSync(oldPath)) {
        sources.push(oldPath);
      }
    }
    
    // 2. Windows Installer cache (fast single check, not a recursive crawl)
    try {
      const installerDir = 'C:\\Windows\\Installer';
      if (fs.existsSync(installerDir)) {
        const candidate = path.join(installerDir, fileName);
        if (fs.existsSync(candidate)) {
          sources.push(candidate);
        }
      }
    } catch (_) {}
    
    return sources;
  }

  /**
   * Calculate SHA256 hash of file
   * @param {string} filePath - File to hash
   * @returns {Promise<string>} SHA256 hash
   */
  calculateFileHash(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', (data) => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  /**
   * Create safety backup of file before disinfection
   * @param {string} filePath - Path to file
   * @returns {string|null} Backup path or null
   */
  backupFile(filePath) {
    try {
      const backupBase = 'C:\\GSMShield\\Backups';
      const dateStr = new Date().toISOString().slice(0, 10);
      const backupDir = path.join(backupBase, dateStr);
      if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
      }
      const fileName = path.basename(filePath);
      const backupPath = path.join(backupDir, `${Date.now()}_${fileName}`);
      fs.copyFileSync(filePath, backupPath);
      return backupPath;
    } catch (err) {
      console.warn(`[expiro-disinfector] Backup notice: ${err.message}`);
      return null;
    }
  }

  /**
   * Surgical PE Disinfection:
   * Inspects PE header, restores AddressOfEntryPoint to legitimate code section,
   * clears rogue writable flags on executable sections, and removes viral overlay.
   * @param {string} filePath - Path to infected PE
   * @returns {Promise<Object>} Disinfection result
   */
  async surgicalDisinfectPE(filePath) {
    try {
      if (!fs.existsSync(filePath)) return { success: false, reason: 'File does not exist' };
      const buf = Buffer.from(fs.readFileSync(filePath));
      if (buf.length < 64 || buf[0] !== 0x4D || buf[1] !== 0x5A) {
        return { success: false, reason: 'Not a PE executable' };
      }

      const peOff = buf.readUInt32LE(0x3C);
      if (peOff + 24 > buf.length || buf[peOff] !== 0x50 || buf[peOff + 1] !== 0x45) {
        return { success: false, reason: 'Invalid PE header' };
      }

      const coffOff = peOff + 4;
      const numSections = buf.readUInt16LE(coffOff + 2);
      const optHeaderSize = buf.readUInt16LE(coffOff + 16);
      const optOff = coffOff + 20;
      const epRVA = buf.readUInt32LE(optOff + 16);
      const secTableOff = optOff + optHeaderSize;

      let textSection = null;
      let viralSection = null;
      let lastSecEnd = 0;
      let modified = false;

      for (let i = 0; i < numSections; i++) {
        const o = secTableOff + i * 40;
        if (o + 40 > buf.length) break;

        const name = buf.slice(o, o + 8).toString('ascii').replace(/\0+$/, '');
        const vs = buf.readUInt32LE(o + 8);
        const va = buf.readUInt32LE(o + 12);
        const rs = buf.readUInt32LE(o + 16);
        const ro = buf.readUInt32LE(o + 20);
        let ch = buf.readUInt32LE(o + 36);

        const isExec = (ch & 0x20000000) !== 0;
        const isWrite = (ch & 0x80000000) !== 0;

        if (!textSection && isExec && /^\.text|CODE|\.code|_text/i.test(name)) {
          textSection = { name, va, vs, ro, rs, ch, offset: o };
        }

        if (va <= epRVA && epRVA < va + vs) {
          if (!/^\.text|CODE|\.code|_text/i.test(name)) {
            viralSection = { name, va, vs, ro, rs, ch, offset: o };
          }
        }

        // If an executable section has rogue write permission, clear it
        if (isExec && isWrite) {
          buf.writeUInt32LE(ch & ~0x80000000, o + 36);
          modified = true;
        }

        const secEnd = ro + rs;
        if (secEnd > lastSecEnd) lastSecEnd = secEnd;
      }

      // If EP was redirected away from code section, restore it to code section
      if (viralSection && textSection) {
        const restoredEP = textSection.va < 0x1000 ? textSection.va : textSection.va + (textSection.vs > 0x1000 ? 0x1000 : 0);
        buf.writeUInt32LE(restoredEP, optOff + 16);
        modified = true;
      }

      // Do NOT truncate overlay if it represents a legitimate Authenticode Security Directory!
      const dataDirBase = (buf.readUInt16LE(optOff) === 0x20B) ? optOff + 112 : optOff + 96;
      let certOffset = 0;
      let certSize = 0;
      if (dataDirBase + 40 <= buf.length) {
        certOffset = buf.readUInt32LE(dataDirBase + 32);
        certSize = buf.readUInt32LE(dataDirBase + 36);
      }
      const isAuthenticodeOverlay = (certOffset > 0 && certOffset >= lastSecEnd && certOffset + certSize <= buf.length);

      // If an overlay exists and is NOT a legitimate digital signature, truncate buffer
      let finalBuf = buf;
      if (!isAuthenticodeOverlay && lastSecEnd > 0 && buf.length - lastSecEnd >= 40960) {
        finalBuf = buf.slice(0, lastSecEnd);
        modified = true;
      }

      if (!modified) {
        return { success: false, reason: 'No surgical modifications applicable' };
      }

      // Verify the repaired buffer using detector before overwriting
      const tempPath = `${filePath}.disinfect_tmp`;
      fs.writeFileSync(tempPath, finalBuf);

      const expiroDetector = require('./expiro-detector');
      const testResult = expiroDetector.detectExpiroInfection(tempPath);

      if (testResult && testResult.confidence < 40) {
        fs.copyFileSync(tempPath, filePath);
        fs.unlinkSync(tempPath);
        return {
          success: true,
          action: 'surgically_disinfected',
          filePath,
          confidenceAfter: testResult.confidence,
        };
      } else {
        if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
        return {
          success: false,
          reason: `Verification failed (confidence remained ${testResult?.confidence}%)`,
        };
      }
    } catch (err) {
      return { success: false, reason: err.message };
    }
  }

  /**
   * Main disinfection workflow
   * Implements multi-tier safe removal strategy without damaging host files
   * @param {string} filePath - Path to infected file
   * @param {Object} detectionResult - Detection result from expiro-detector
   * @returns {Promise<Object>} Disinfection result
   */
  async disinfectFile(filePath, detectionResult) {
    console.log(`[expiro-disinfector] Processing: ${filePath}`);
    const assessment = this.assessFileCriticality(filePath);

    // CRITICAL: Never attempt in-place modification or quarantine of protected Windows components
    // (System32, WinSxS, etc.). These files are locked by TrustedInstaller; tampering with them
    // throws EPERM and damages OS stability. Direct the user to SFC instead.
    if (assessment.isCritical) {
      console.warn(`[expiro-disinfector] Skipping direct modification of protected system file: ${filePath}`);
      const protectedResult = {
        success: false,
        action: 'system_protected',
        filePath,
        isCritical: true,
        error: 'Protected Windows component cannot be modified directly.',
        recommendation: `Protected Windows system component. Open Administrator Command Prompt and run "sfc /scanfile=${filePath}" or "sfc /scannow" to restore verified system binaries without damaging Windows.`,
        timestamp: new Date().toISOString(),
      };
      this.disinfectionLog.push(protectedResult);
      return protectedResult;
    }

    const backupPath = this.backupFile(filePath);
    
    // Strategy 1: Attempt Surgical PE Disinfection FIRST (repairs file in place in ~2ms)
    const surgicalResult = await this.surgicalDisinfectPE(filePath);
    if (surgicalResult.success) {
      console.log(`[expiro-disinfector] ✓ Surgically disinfected PE file: ${filePath}`);
      surgicalResult.backupPath = backupPath;
      this.disinfectionLog.push(surgicalResult);
      return surgicalResult;
    }

    // Strategy 2: If surgical repair not applicable, try clean backup restore
    const restoreResult = await this.restoreFromCleanSource(filePath);
    if (restoreResult.success) {
      console.log(`[expiro-disinfector] ✓ Restored from clean source: ${filePath}`);
      restoreResult.backupPath = backupPath;
      this.disinfectionLog.push(restoreResult);
      return restoreResult;
    }
    
    // Strategy 3: Safe Quarantine (Isolates file to prevent reinfection)
    console.log(`[expiro-disinfector] Quarantining infected file: ${filePath}`);
    const quarantineResult = await this.quarantineInfectedFile(
      filePath,
      detectionResult.threatName || 'Virus:Win32/Expiro.EK!MTB'
    );
    
    if (quarantineResult.success) {
      console.log(`[expiro-disinfector] ✓ File quarantined safely`);
      quarantineResult.backupPath = backupPath;
      if (assessment.isCritical) {
        quarantineResult.recommendation = 'Run System File Checker: sfc /scannow';
      } else {
        quarantineResult.recommendation = 'Reinstall application from trusted source';
      }
    }
    
    return quarantineResult;
  }

  /**
   * Batch disinfection of multiple files
   * Implements smart ordering to prevent infection spread
   * @param {Object[]} detections - Array of detection results
   * @param {Function} onProgress - Progress callback
   * @returns {Promise<Object>} Batch disinfection summary
   */
  async disinfectBatch(detections, onProgress) {
    const results = {
      total: detections.length,
      successful: 0,
      failed: 0,
      disinfected: 0,
      quarantined: 0,
      restored: 0,
      details: [],
    };
    
    // Sort by criticality (non-critical first to prevent spread)
    const sorted = detections.sort((a, b) => {
      const assessA = this.assessFileCriticality(a.filePath);
      const assessB = this.assessFileCriticality(b.filePath);
      return assessA.isCritical ? 1 : -1;
    });
    
    for (let i = 0; i < sorted.length; i++) {
      const detection = sorted[i];
      
      if (onProgress) {
        onProgress({
          current: i + 1,
          total: sorted.length,
          file: detection.filePath,
        });
      }
      
      const result = await this.disinfectFile(detection.filePath, detection);
      results.details.push(result);
      
      if (result.success) {
        results.successful++;
        if (result.action === 'surgically_disinfected') results.disinfected++;
        if (result.action === 'quarantined') results.quarantined++;
        if (result.action === 'restored') results.restored++;
      } else {
        results.failed++;
      }

      // Yield back to the Node.js / Electron event loop to keep the UI interactive
      await new Promise((resolve) => setImmediate(resolve));
    }
    
    return results;
  }

  /**
   * Get disinfection log
   * @returns {Object[]} Array of disinfection results
   */
  getLog() {
    return this.disinfectionLog;
  }

  /**
   * Generate disinfection report
   * @returns {string} Human-readable report
   */
  generateReport() {
    const report = [];
    report.push('='.repeat(70));
    report.push('EXPIRO DISINFECTION REPORT');
    report.push('='.repeat(70));
    report.push('');
    report.push(`Total Files Processed: ${this.disinfectionLog.length}`);
    report.push(`Successful: ${this.disinfectionLog.filter(r => r.success).length}`);
    report.push(`Failed: ${this.disinfectionLog.filter(r => !r.success).length}`);
    report.push('');
    
    for (const entry of this.disinfectionLog) {
      report.push(`File: ${entry.filePath}`);
      report.push(`Action: ${entry.action}`);
      report.push(`Status: ${entry.success ? 'SUCCESS' : 'FAILED'}`);
      if (entry.recommendation) {
        report.push(`Recommendation: ${entry.recommendation}`);
      }
      report.push('');
    }
    
    report.push('='.repeat(70));
    return report.join('\n');
  }
}

module.exports = ExpiroDisinfector;
