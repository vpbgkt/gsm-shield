/**
 * engine/expiro-prevention.js
 * 
 * Real-Time Expiro Infection Prevention Module
 * Stops Expiro from spreading to other files
 * 
 * CRITICAL FUNCTIONALITY:
 * - Monitors file creation/modification events
 * - Scans files before they execute
 * - Blocks infected files from running
 * - Prevents infection chain propagation
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const expiroDetector = require('./expiro-detector');

class ExpiroPrevention extends EventEmitter {
  constructor(quarantineModule) {
    super();
    this.quarantineModule = quarantineModule;
    this.isActive = false;
    this.scanQueue = [];
    this.scanning = false;
    this.stats = {
      filesScanned: 0,
      infectionsBlocked: 0,
      startTime: null,
    };
  }

  /**
   * Start real-time prevention
   */
  start() {
    if (this.isActive) {
      console.warn('[expiro-prevention] Already active');
      return;
    }
    
    this.isActive = true;
    this.stats.startTime = Date.now();
    
    console.log('[expiro-prevention] ✓ Real-time prevention activated');
    this.emit('started');
  }

  /**
   * Stop real-time prevention
   */
  stop() {
    this.isActive = false;
    this.scanQueue = [];
    
    console.log('[expiro-prevention] ✗ Real-time prevention stopped');
    this.emit('stopped');
  }

  /**
   * Scan file before execution (pre-execution hook)
   * This is the KEY method to prevent infection spread
   * @param {string} filePath - File about to be executed
   * @returns {Promise<Object>} Scan result with action
   */
  async scanBeforeExecution(filePath) {
    if (!this.isActive) {
      return { allowed: true, reason: 'Prevention not active' };
    }
    
    try {
      // Only scan PE-capable files (same set the detector's structural layer handles)
      const ext = path.extname(filePath).toLowerCase();
      if (!expiroDetector.STRUCTURAL_EXTENSIONS.includes(ext)) {
        return { allowed: true, reason: 'Not executable' };
      }
      
      console.log(`[expiro-prevention] Pre-execution scan: ${path.basename(filePath)}`);
      
      // Scan for Expiro infection
      const detection = await expiroDetector.scanFile(filePath);
      this.stats.filesScanned++;
      
      if (detection.isInfected) {
        this.stats.infectionsBlocked++;
        
        console.error(`[expiro-prevention] 🛑 BLOCKED: ${filePath}`);
        console.error(`[expiro-prevention] Confidence: ${detection.confidence}%`);
        
        // Emit threat detected event
        this.emit('threat-blocked', {
          filePath,
          threatName: detection.threatName,
          confidence: detection.confidence,
          reasons: detection.reasons,
          timestamp: new Date().toISOString(),
        });
        
        // Auto-quarantine to prevent spread
        try {
          await this.quarantineModule.quarantineFile(
            filePath,
            detection.threatName
          );
          
          console.log(`[expiro-prevention] ✓ File quarantined automatically`);
        } catch (qErr) {
          console.error(`[expiro-prevention] Quarantine failed: ${qErr.message}`);
        }
        
        return {
          allowed: false,
          blocked: true,
          reason: 'Expiro infection detected',
          threatName: detection.threatName,
          confidence: detection.confidence,
          action: 'quarantined',
        };
      }
      
      return {
        allowed: true,
        reason: 'Clean',
      };
      
    } catch (error) {
      console.error(`[expiro-prevention] Scan error: ${error.message}`);
      
      // Fail-safe: block on error for critical files
      const assessment = this.assessFileCriticality(filePath);
      if (assessment.isCritical) {
        return {
          allowed: false,
          blocked: true,
          reason: 'Scan error on critical file',
          error: error.message,
        };
      }
      
      // Allow non-critical files on scan error
      return {
        allowed: true,
        reason: 'Scan error (non-critical file)',
      };
    }
  }

  /**
   * Scan newly created/modified file (post-write hook)
   * Detects infection after file modification
   * @param {string} filePath - File that was modified
   * @returns {Promise<Object>} Scan result
   */
  async scanAfterModification(filePath) {
    if (!this.isActive) {
      return { scanned: false, reason: 'Prevention not active' };
    }
    
    // Add to queue and process asynchronously
    this.scanQueue.push(filePath);
    
    if (!this.scanning) {
      this.processQueue();
    }
    
    return { scanned: true, queued: true };
  }

  /**
   * Process scan queue asynchronously
   */
  async processQueue() {
    if (this.scanning || this.scanQueue.length === 0) return;
    
    this.scanning = true;
    
    while (this.scanQueue.length > 0) {
      const filePath = this.scanQueue.shift();
      
      try {
        const detection = await expiroDetector.scanFile(filePath);
        this.stats.filesScanned++;
        
        if (detection.isInfected) {
          this.stats.infectionsBlocked++;
          
          console.error(`[expiro-prevention] 🦠 INFECTED: ${filePath}`);
          
          this.emit('threat-detected', {
            filePath,
            threatName: detection.threatName,
            confidence: detection.confidence,
            reasons: detection.reasons,
            timestamp: new Date().toISOString(),
          });
          
          // Auto-quarantine
          try {
            await this.quarantineModule.quarantineFile(
              filePath,
              detection.threatName
            );
            console.log(`[expiro-prevention] ✓ Quarantined: ${path.basename(filePath)}`);
          } catch (qErr) {
            console.error(`[expiro-prevention] Quarantine failed: ${qErr.message}`);
          }
        }
        
      } catch (error) {
        console.error(`[expiro-prevention] Queue scan error: ${error.message}`);
      }
    }
    
    this.scanning = false;
  }

  /**
   * Check if file is in critical location
   * @param {string} filePath - File path to check
   * @returns {Object} Criticality assessment
   */
  assessFileCriticality(filePath) {
    const normalizedPath = filePath.toLowerCase();
    
    const criticalPaths = [
      'c:\\windows\\system32',
      'c:\\windows\\syswow64',
    ];
    
    const isCritical = criticalPaths.some(critPath => 
      normalizedPath.startsWith(critPath)
    );
    
    return { isCritical };
  }

  /**
   * Get prevention statistics
   * @returns {Object} Current stats
   */
  getStats() {
    const uptime = this.stats.startTime 
      ? Date.now() - this.stats.startTime 
      : 0;
    
    return {
      ...this.stats,
      uptime,
      uptimeHours: (uptime / (1000 * 60 * 60)).toFixed(2),
      isActive: this.isActive,
    };
  }

  /**
   * Generate prevention report
   * @returns {string} Human-readable report
   */
  generateReport() {
    const stats = this.getStats();
    
    const report = [];
    report.push('='.repeat(70));
    report.push('EXPIRO REAL-TIME PREVENTION REPORT');
    report.push('='.repeat(70));
    report.push('');
    report.push(`Status: ${stats.isActive ? 'ACTIVE' : 'INACTIVE'}`);
    report.push(`Uptime: ${stats.uptimeHours} hours`);
    report.push(`Files Scanned: ${stats.filesScanned}`);
    report.push(`Infections Blocked: ${stats.infectionsBlocked}`);
    report.push('');
    
    if (stats.filesScanned > 0) {
      const blockRate = (stats.infectionsBlocked / stats.filesScanned * 100).toFixed(2);
      report.push(`Block Rate: ${blockRate}%`);
    }
    
    report.push('='.repeat(70));
    
    return report.join('\n');
  }
}

module.exports = ExpiroPrevention;
