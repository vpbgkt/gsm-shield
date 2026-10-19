/**
 * electron/ipc/expiro-handlers.js
 * 
 * IPC Handlers for Expiro-Specific Functionality
 * Provides UI control over Expiro detection and disinfection
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');
const expiroDetector = require('../../engine/expiro-detector');
const ExpiroDisinfector = require('../../engine/expiro-disinfector');

let activeWorker = null;

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
   * Scan multiple files via Worker thread to keep UI completely responsive
   */
  ipcMain.handle('expiro:scan-files', async (event, { filePaths }) => {
    try {
      if (!Array.isArray(filePaths) || filePaths.length === 0) {
        return {
          success: true,
          results: [],
          summary: { total: 0, infected: 0, clean: 0 },
        };
      }

      if (activeWorker) {
        try {
          await activeWorker.terminate();
        } catch (_) {}
        activeWorker = null;
      }

      const win = getMainWindow();
      const workerPath = path.join(__dirname, '../../engine/expiro-scanner-worker.js');

      return await new Promise((resolve) => {
        let resolved = false;
        const worker = new Worker(workerPath, {
          workerData: {
            filePaths,
            threshold: expiroDetector.EXPIRO_SIGNATURES.detectionThreshold,
          },
        });
        activeWorker = worker;

        worker.on('message', (msg) => {
          if (!msg) return;
          if (msg.type === 'progress') {
            if (win && !win.isDestroyed()) {
              win.webContents.send('expiro:scan-progress', msg);
            }
          } else if (msg.type === 'complete') {
            if (!resolved) {
              resolved = true;
              activeWorker = null;
              resolve({
                success: true,
                results: msg.results || [],
                summary: msg.summary || {
                  total: msg.totalFiles,
                  infected: (msg.results || []).length,
                  clean: msg.totalFiles - (msg.results || []).length,
                },
                cancelled: Boolean(msg.cancelled),
              });
            }
          } else if (msg.type === 'error') {
            if (!resolved) {
              resolved = true;
              activeWorker = null;
              resolve({ success: false, error: msg.error });
            }
          }
        });

        worker.on('error', (err) => {
          if (!resolved) {
            resolved = true;
            activeWorker = null;
            resolve({ success: false, error: err.message });
          }
        });

        worker.on('exit', (code) => {
          if (activeWorker === worker) {
            activeWorker = null;
          }
          if (!resolved) {
            resolved = true;
            resolve({ success: false, error: `Worker exited with code ${code}` });
          }
        });
      });
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
   * Executed via Worker Thread so Electron main process remains 100% responsive
   */
  ipcMain.handle('expiro:scan-directory', async (event, { dirPath, maxDepth = 4 }) => {
    try {
      if (!fs.existsSync(dirPath)) {
        return { success: false, error: 'Directory does not exist' };
      }

      if (activeWorker) {
        try {
          await activeWorker.terminate();
        } catch (_) {}
        activeWorker = null;
      }

      const win = getMainWindow();
      const workerPath = path.join(__dirname, '../../engine/expiro-scanner-worker.js');

      return await new Promise((resolve) => {
        let resolved = false;
        const worker = new Worker(workerPath, {
          workerData: {
            dirPath,
            maxDepth,
            threshold: expiroDetector.EXPIRO_SIGNATURES.detectionThreshold,
          },
        });
        activeWorker = worker;

        worker.on('message', (msg) => {
          if (!msg) return;
          if (msg.type === 'progress') {
            if (win && !win.isDestroyed()) {
              win.webContents.send('expiro:scan-progress', msg);
            }
          } else if (msg.type === 'complete') {
            if (!resolved) {
              resolved = true;
              activeWorker = null;
              resolve({
                success: true,
                totalFiles: msg.totalFiles,
                results: msg.results || [],
                summary: msg.summary || {
                  total: msg.totalFiles,
                  infected: (msg.results || []).length,
                  clean: msg.totalFiles - (msg.results || []).length,
                },
                cancelled: Boolean(msg.cancelled),
              });
            }
          } else if (msg.type === 'error') {
            if (!resolved) {
              resolved = true;
              activeWorker = null;
              resolve({ success: false, error: msg.error });
            }
          }
        });

        worker.on('error', (err) => {
          if (!resolved) {
            resolved = true;
            activeWorker = null;
            resolve({ success: false, error: err.message });
          }
        });

        worker.on('exit', (code) => {
          if (activeWorker === worker) {
            activeWorker = null;
          }
          if (!resolved) {
            resolved = true;
            resolve({ success: false, error: `Worker exited with code ${code}` });
          }
        });
      });
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  /**
   * Cancel an ongoing Expiro scan worker
   */
  ipcMain.handle('expiro:cancel-scan', async () => {
    if (activeWorker) {
      try {
        activeWorker.postMessage({ type: 'cancel' });
        setTimeout(() => {
          if (activeWorker) {
            activeWorker.terminate().catch(() => {});
            activeWorker = null;
          }
        }, 500);
      } catch (_) {}
      return { success: true, message: 'Scan cancellation requested' };
    }
    return { success: true, message: 'No active scan worker' };
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
