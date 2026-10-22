/**
 * monitor/expiro-monitor.js
 * 
 * Expiro-Specific Real-Time Monitoring Integration
 * Integrates with chokidar file watcher to prevent Expiro spread
 * 
 * PREVENTS INFECTION CHAIN:
 * - Scans files immediately after creation/modification
 * - Blocks execution of infected files
 * - Auto-quarantines threats
 * - Stops propagation across system
 */

'use strict';

const chokidar = require('chokidar');
const path = require('path');
const ExpiroPrevention = require('../engine/expiro-prevention');
const ExpiroDisinfector = require('../engine/expiro-disinfector');

/** PE-capable extensions watched in real time (Expiro targets .exe; others are cheap to check). */
const WATCHED_EXTENSIONS = ['.exe', '.dll', '.scr', '.com', '.cpl', '.tmp'];

class ExpiroMonitor {
  constructor(quarantineModule, mainWindow) {
    this.quarantineModule = quarantineModule;
    this.mainWindow = mainWindow;
    this.prevention = new ExpiroPrevention(quarantineModule);
    this.disinfector = new ExpiroDisinfector(quarantineModule);
    this.watcher = null;
    this.watchedPaths = [];
    
    // Setup event handlers
    this.setupEventHandlers();
  }

  /**
   * Setup event handlers for prevention module
   */
  setupEventHandlers() {
    // When threat is blocked, notify UI
    this.prevention.on('threat-blocked', (event) => {
      console.error(`[expiro-monitor] 🛑 THREAT BLOCKED: ${event.filePath}`);
      
      if (this.mainWindow && !this.mainWindow.isDestroyed()) {
        this.mainWindow.webContents.send('expiro:blocked', {
          filePath: event.filePath,
          threatName: event.threatName,
          confidence: event.confidence,
          action: 'blocked',
          timestamp: event.timestamp,
        });
        
        // Show Windows notification
        this.showNotification(
          'Expiro Infection Blocked!',
          `File: ${path.basename(event.filePath)}\nAction: Quarantined`
        );
      }
    });
    
    // When threat is detected after file modification
    this.prevention.on('threat-detected', (event) => {
      console.warn(`[expiro-monitor] 🦠 THREAT DETECTED: ${event.filePath}`);
      
      if (this.mainWindow && !this.mainWindow.isDestroyed()) {
        this.mainWindow.webContents.send('expiro:detected', {
          filePath: event.filePath,
          threatName: event.threatName,
          confidence: event.confidence,
          action: 'quarantined',
          timestamp: event.timestamp,
        });
        
        this.showNotification(
          'Expiro Infection Detected!',
          `File: ${path.basename(event.filePath)}\nStatus: Quarantined`
        );
      }
    });
  }

  /**
   * Show Windows notification
   * @param {string} title - Notification title
   * @param {string} body - Notification body
   */
  showNotification(title, body) {
    try {
      const { Notification } = require('electron');
      new Notification({ title, body, urgency: 'critical' }).show();
    } catch (error) {
      console.error(`[expiro-monitor] Notification error: ${error.message}`);
    }
  }

  /**
   * Start monitoring directories for Expiro activity
   * @param {string[]} paths - Directories to monitor
   * @returns {Promise<void>}
   */
  async start(paths) {
    if (this.watcher) {
      console.warn('[expiro-monitor] Already running, stopping first...');
      await this.stop();
    }
    
    this.watchedPaths = paths.filter(p => typeof p === 'string' && p.length > 0);
    
    if (this.watchedPaths.length === 0) {
      console.warn('[expiro-monitor] No paths to monitor');
      return;
    }
    
    console.log(`[expiro-monitor] Starting Expiro protection for ${this.watchedPaths.length} path(s)`);
    
    // Start prevention module
    this.prevention.start();
    
    // Setup file watcher
    this.watcher = chokidar.watch(this.watchedPaths, {
      persistent: true,
      ignoreInitial: true,  // Don't scan existing files on startup
      depth: 6,
      awaitWriteFinish: {
        stabilityThreshold: 2000,  // Wait 2s after write completes
        pollInterval: 100,
      },
      // Exclude heavy system directories, build caches, and non-PE files.
      // NOTE: %LOCALAPPDATA%\Temp is deliberately NOT excluded any more: browser
      // downloads (Edge uses Temp\MicrosoftEdgeDownloads), installer payloads and
      // uninstaller copies land there, and infected files were found there in the
      // 2026-10-22 incident. The structural check reads only headers, so it is cheap.
      ignored: (filePath, stats) => {
        const lower = filePath.toLowerCase();
        if (lower.includes('$recycle.bin') ||
            lower.includes('system volume information') ||
            lower.includes('\\winsxs') ||
            lower.includes('\\servicing') ||
            lower.includes('\\node_modules') ||
            lower.includes('\\.git') ||
            lower.includes('\\inetcache') ||
            lower.includes('\\gsmshield\\quarantine') ||
            lower.includes('\\gsmshieldav\\quarantine') ||
            lower.includes('\\gsmshield\\backups')) {
          return true;
        }
        // Always allow eligible directories so chokidar can descend into them
        if (!stats || stats.isDirectory()) return false;
        // For files, only watch PE-capable extensions
        const ext = path.extname(filePath).toLowerCase();
        return !WATCHED_EXTENSIONS.includes(ext);
      },
    });
    
    // Monitor new files (potential infection vectors)
    this.watcher.on('add', async (filePath) => {
      console.log(`[expiro-monitor] New file: ${path.basename(filePath)}`);
      await this.prevention.scanAfterModification(filePath);
    });
    
    // Monitor modified files (infection in progress)
    this.watcher.on('change', async (filePath) => {
      console.log(`[expiro-monitor] Modified: ${path.basename(filePath)}`);
      await this.prevention.scanAfterModification(filePath);
    });
    
    // Monitor for errors
    this.watcher.on('error', (error) => {
      console.error(`[expiro-monitor] Watcher error: ${error.message}`);
      
      if (this.mainWindow && !this.mainWindow.isDestroyed()) {
        this.mainWindow.webContents.send('expiro:error', {
          message: error.message,
          timestamp: new Date().toISOString(),
        });
      }
    });
    
    console.log('[expiro-monitor] ✓ Expiro protection ACTIVE');
  }

  /**
   * Stop monitoring
   * @returns {Promise<void>}
   */
  async stop() {
    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
    
    this.prevention.stop();
    this.watchedPaths = [];
    
    console.log('[expiro-monitor] ✗ Expiro protection STOPPED');
  }

  /**
   * Update watched paths (hot-reload)
   * @param {string[]} newPaths - New paths to watch
   * @returns {Promise<void>}
   */
  async updatePaths(newPaths) {
    const filtered = newPaths.filter(p => typeof p === 'string' && p.length > 0);
    
    if (this.watcher && filtered.length > 0) {
      // Remove old paths
      for (const oldPath of this.watchedPaths) {
        if (!filtered.includes(oldPath)) {
          this.watcher.unwatch(oldPath);
        }
      }
      
      // Add new paths
      for (const newPath of filtered) {
        if (!this.watchedPaths.includes(newPath)) {
          this.watcher.add(newPath);
        }
      }
      
      this.watchedPaths = filtered;
      console.log(`[expiro-monitor] Paths updated: ${filtered.length} path(s)`);
    } else if (filtered.length > 0) {
      // Not running, start fresh
      await this.start(filtered);
    }
  }

  /**
   * Scan file on-demand before execution
   * Used by system to check files before allowing execution
   * @param {string} filePath - File to scan
   * @returns {Promise<Object>} Scan result with block decision
   */
  async scanBeforeExecution(filePath) {
    return await this.prevention.scanBeforeExecution(filePath);
  }

  /**
   * Disinfect a detected infection
   * @param {string} filePath - Infected file path
   * @param {Object} detectionResult - Detection result
   * @returns {Promise<Object>} Disinfection result
   */
  async disinfectFile(filePath, detectionResult) {
    return await this.disinfector.disinfectFile(filePath, detectionResult);
  }

  /**
   * Get current statistics
   * @returns {Object} Combined stats
   */
  getStats() {
    return {
      prevention: this.prevention.getStats(),
      watchedPaths: this.watchedPaths.length,
      isActive: this.watcher !== null,
    };
  }

  /**
   * Generate activity report
   * @returns {string} Report
   */
  generateReport() {
    const stats = this.getStats();
    
    const report = [];
    report.push('='.repeat(70));
    report.push('EXPIRO REAL-TIME PROTECTION REPORT');
    report.push('='.repeat(70));
    report.push('');
    report.push(`Status: ${stats.isActive ? 'ACTIVE ✓' : 'INACTIVE ✗'}`);
    report.push(`Monitored Directories: ${stats.watchedPaths}`);
    report.push('');
    report.push('Prevention Statistics:');
    report.push(`  Uptime: ${stats.prevention.uptimeHours} hours`);
    report.push(`  Files Scanned: ${stats.prevention.filesScanned}`);
    report.push(`  Infections Blocked: ${stats.prevention.infectionsBlocked}`);
    report.push('');
    
    if (this.watchedPaths.length > 0) {
      report.push('Monitored Paths:');
      for (const p of this.watchedPaths) {
        report.push(`  - ${p}`);
      }
    }
    
    report.push('');
    report.push('='.repeat(70));
    
    return report.join('\n');
  }
}

module.exports = ExpiroMonitor;
