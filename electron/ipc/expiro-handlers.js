/**
 * electron/ipc/expiro-handlers.js
 * 
 * IPC Handlers for Expiro-Specific Functionality
 * Provides UI control over Expiro detection and disinfection
 */

'use strict';

const fs = require('fs');
const path = require('path');
const expiroDetector = require('../../engine/expiro-detector');
const ExpiroDisinfector = require('../../engine/expiro-disinfector');

/**
 * Register all Expiro-related IPC handlers
 * @param {Electron.IpcMain} ipcMain
 * @param {Object} deps - Dependencies
 */
function register(ipcMain, { getQuarantine, getMainWindow }) {
  
  /**
   * Scan single file for Expiro infection
   */
  ipcMain.handle('expiro:scan-file', async (event, { filePath }) => {
    try {
      const result = await expiroDetector.scanFile(filePath);
      
      return {
        success: true,
        result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Scan multiple files
   */
  ipcMain.handle('expiro:scan-files', async (event, { filePaths }) => {
    try {
      const results = await expiroDetector.scanFiles(
        filePaths,
        (progress) => {
          // Send progress updates to renderer
          const win = getMainWindow();
          if (win && !win.isDestroyed()) {
            win.webContents.send('expiro:scan-progress', progress);
          }
        }
      );
      
      return {
        success: true,
        results,
        summary: {
          total: results.length,
          infected: results.filter(r => r.isInfected).length,
          clean: results.filter(r => !r.isInfected).length,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Disinfect infected file
   */
  ipcMain.handle('expiro:disinfect-file', async (event, { filePath, detection }) => {
    try {
      const quarantine = getQuarantine();
      const disinfector = new ExpiroDisinfector(quarantine);
      
      const result = await disinfector.disinfectFile(filePath, detection);
      
      return {
        success: true,
        result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Batch disinfect multiple files
   */
  ipcMain.handle('expiro:disinfect-batch', async (event, { detections }) => {
    try {
      const quarantine = getQuarantine();
      const disinfector = new ExpiroDisinfector(quarantine);
      
      const result = await disinfector.disinfectBatch(
        detections,
        (progress) => {
          // Send progress updates
          const win = getMainWindow();
          if (win && !win.isDestroyed()) {
            win.webContents.send('expiro:disinfect-progress', progress);
          }
        }
      );
      
      return {
        success: true,
        result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Get Expiro protection statistics
   */
  ipcMain.handle('expiro:get-stats', async () => {
    try {
      const expiroMonitor = global.expiroMonitor;
      
      if (!expiroMonitor) {
        return {
          success: true,
          stats: {
            isActive: false,
            message: 'Expiro protection not initialized',
          },
        };
      }
      
      const stats = expiroMonitor.getStats();
      
      return {
        success: true,
        stats,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Generate Expiro protection report
   */
  ipcMain.handle('expiro:generate-report', async () => {
    try {
      const expiroMonitor = global.expiroMonitor;
      
      if (!expiroMonitor) {
        return {
          success: false,
          error: 'Expiro protection not initialized',
        };
      }
      
      const report = expiroMonitor.generateReport();
      
      return {
        success: true,
        report,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Manually trigger scan before file execution
   * Used by system hooks or user-initiated scans
   */
  ipcMain.handle('expiro:scan-before-execution', async (event, { filePath }) => {
    try {
      const expiroMonitor = global.expiroMonitor;
      
      if (!expiroMonitor) {
        return {
          success: true,
          allowed: true,
          reason: 'Expiro protection not active',
        };
      }
      
      const result = await expiroMonitor.scanBeforeExecution(filePath);
      
      return {
        success: true,
        ...result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Update monitored paths for Expiro protection
   */
  ipcMain.handle('expiro:update-paths', async (event, { paths }) => {
    try {
      const expiroMonitor = global.expiroMonitor;
      
      if (!expiroMonitor) {
        return {
          success: false,
          error: 'Expiro protection not initialized',
        };
      }
      
      await expiroMonitor.updatePaths(paths);
      
      return {
        success: true,
        message: `Updated to monitor ${paths.length} path(s)`,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  });

  /**
   * Recursively scan a folder for PE executables using Expiro heuristics
   */
  ipcMain.handle('expiro:scan-directory', async (event, { dirPath, maxDepth = 4 }) => {
    try {
      if (!fs.existsSync(dirPath)) {
        return { success: false, error: 'Directory does not exist' };
      }

      const peFiles = [];
      // Only user-mode PE executables and libraries (Expiro does not infect kernel .sys drivers)
      const peExts = new Set(['.exe', '.dll', '.scr']);

      // Directories that should always be excluded from heuristic traversal:
      // - Quarantine & backup repositories (never re-scan already-isolated files)
      // - System volume, trash, and recovery folders
      // - Developer build caches
      const skipNames = new Set([
        '$recycle.bin',
        'system volume information',
        'recovery',
        'node_modules',
        '.git',
        'winsxs',
        'servicing',
        'assembly',
        'microsoft.net',
        'installer',
        '$windows.~bt',
        '$windows.~ws',
      ]);

      function walk(currentDir, currentDepth) {
        if (currentDepth > maxDepth) return;
        try {
          const entries = fs.readdirSync(currentDir, { withFileTypes: true });
          for (const entry of entries) {
            const lowerName = entry.name.toLowerCase();
            if (skipNames.has(lowerName)) continue;

            const fullPath = path.join(currentDir, entry.name);
            const lowerPath = fullPath.toLowerCase();

            // Skip quarantine & backup directories
            if (lowerPath.includes('\\gsmshield\\quarantine') ||
                lowerPath.includes('\\gsmshieldav\\quarantine') ||
                lowerPath.includes('\\gsmshield\\backups')) {
              continue;
            }

            if (entry.isDirectory()) {
              // Avoid following junctions/symlinks which cause infinite loops
              try {
                if (fs.lstatSync(fullPath).isSymbolicLink()) continue;
              } catch (_) {}

              walk(fullPath, currentDepth + 1);
            } else if (entry.isFile()) {
              const ext = path.extname(fullPath).toLowerCase();
              if (peExts.has(ext)) {
                peFiles.push(fullPath);
              }
            }
          }
        } catch (_) {}
      }

      walk(dirPath, 0);

      const win = getMainWindow();
      const scanRes = await expiroDetector.scanFiles(
        peFiles,
        (progress) => {
          if (win && !win.isDestroyed()) {
            win.webContents.send('expiro:scan-progress', progress);
          }
        },
        { onlyInfected: true }
      );

      const detections = scanRes.detections || [];
      const totalScanned = scanRes.scannedCount || peFiles.length;
      const infectedCount = scanRes.infectedCount || detections.length;

      return {
        success: true,
        totalFiles: totalScanned,
        results: detections, // Return only infected files to prevent IPC serialization overflow
        summary: {
          total: totalScanned,
          infected: infectedCount,
          clean: totalScanned - infectedCount,
        },
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  /**
   * Get current Expiro heuristic detection configuration
   */
  ipcMain.handle('expiro:get-config', async () => {
    return {
      success: true,
      detectionThreshold: expiroDetector.EXPIRO_SIGNATURES.detectionThreshold,
      certaintyThreshold: expiroDetector.EXPIRO_SIGNATURES.certaintyThreshold,
      highEntropyThreshold: expiroDetector.EXPIRO_SIGNATURES.highEntropyThreshold,
    };
  });

  /**
   * Set Expiro detection sensitivity threshold
   */
  ipcMain.handle('expiro:set-threshold', async (event, { threshold }) => {
    const val = Number(threshold);
    if (!isNaN(val) && val >= 30 && val <= 95) {
      expiroDetector.EXPIRO_SIGNATURES.detectionThreshold = val;
      return { success: true, threshold: val };
    }
    return { success: false, error: 'Threshold must be between 30 and 95' };
  });
}

module.exports = { register };
