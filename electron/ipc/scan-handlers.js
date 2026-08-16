'use strict';

/**
 * electron/ipc/scan-handlers.js
 *
 * IPC handlers for the scan subsystem:
 *   - scan:start   { mode, targetPath? } -> { scanId }
 *   - scan:cancel  { scanId? }           -> { success }
 *   - scan:history { limit? }            -> ScanRecord[]
 *
 * Pushes to renderer during a running scan:
 *   - scan:progress { scanId, currentFile, filesScanned }
 *   - scan:threat   { scanId, filePath, threatName }
 *   - scan:complete { scanId, result }
 *
 * Requirements: 14.1, 15.1, 15.2, 15.3, 15.4
 */

const path = require('path');
const os = require('os');
const crypto = require('crypto');

/** Generate a unique scan ID. */
function generateScanId() {
  return crypto.randomBytes(16).toString('hex');
}

// ---- State ---------------------------------------------------------------

/** Currently active scan (only one at a time). */
let activeScan = null;

// ---- Path helpers --------------------------------------------------------

/**
 * Quick-scan target paths: common Windows threat locations.
 */
function getQuickScanPaths() {
  const home = os.homedir();
  return [
    path.join(home, 'Downloads'),
    path.join(home, 'Desktop'),
    path.join(home, 'Documents'),
    path.join(home, 'AppData', 'Local', 'Temp'),
  ].filter((p) => {
    try { require('fs').accessSync(p); return true; } catch { return false; }
  });
}

/**
 * Full-scan target: the system drive root (usually C:\).
 */
function getFullScanPath() {
  return process.env.SystemDrive || 'C:';
}

// ---- Register ------------------------------------------------------------

/**
 * @param {Electron.IpcMain} ipcMain
 * @param {Object} deps
 * @param {Function} deps.getMainWindow
 * @param {Function} deps.getDb
 */
function register(ipcMain, { getMainWindow, getDb }) {

  // ══════════════════════════════════════════════════════════════════════════
  // scan:start
  // ══════════════════════════════════════════════════════════════════════════
  ipcMain.handle('scan:start', async (_event, { mode, targetPath } = {}) => {
    if (activeScan) {
      return { scanId: activeScan.id, error: 'A scan is already running' };
    }

    const scanId = generateScanId();
    const win = getMainWindow();
    const scanner = require('../../engine/scanner');

    // Determine target path based on mode
    let scanTarget;
    switch (mode) {
      case 'quick':
        // Quick scan: scan multiple common directories sequentially
        scanTarget = null; // handled specially below
        break;
      case 'full':
        scanTarget = getFullScanPath();
        break;
      case 'folder':
      case 'file':
        if (!targetPath) {
          // Open a dialog to pick the target
          try {
            const { dialog } = require('electron');
            const result = await dialog.showOpenDialog(win, {
              properties: mode === 'folder' ? ['openDirectory'] : ['openFile'],
              title: mode === 'folder' ? 'Select folder to scan' : 'Select file to scan',
            });
            if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
              return { scanId: null, cancelled: true };
            }
            scanTarget = result.filePaths[0];
          } catch (err) {
            return { scanId: null, error: err.message };
          }
        } else {
          scanTarget = targetPath;
        }
        break;
      default:
        scanTarget = getFullScanPath();
    }

    // Create scan history record in DB
    const startedAt = new Date().toISOString();
    let dbRecordId = null;
    try {
      const db = getDb();
      const result = db.prepare(
        'INSERT INTO scan_history (mode, target_path, started_at, status) VALUES (?, ?, ?, ?)'
      ).run(mode || 'quick', scanTarget || 'multiple', startedAt, 'running');
      dbRecordId = result.lastInsertRowid;
    } catch (err) {
      console.error('[scan-handlers] DB insert failed:', err.message);
    }

    // AbortController for cancellation
    const controller = new AbortController();

    activeScan = { id: scanId, controller, dbRecordId, startedAt, mode };

    // Push helper
    function push(channel, payload) {
      if (win && !win.isDestroyed()) {
        win.webContents.send(channel, payload);
      }
    }

    // Run the scan asynchronously
    (async () => {
      let totalFilesScanned = 0;
      let totalThreatsFound = 0;

      try {
        const targets = mode === 'quick' ? getQuickScanPaths() : [scanTarget];

        for (const target of targets) {
          if (controller.signal.aborted) break;

          const result = await scanner.scan(target, {
            signal: controller.signal,
            onProgress({ filesScanned }) {
              totalFilesScanned = filesScanned;
              push('scan:progress', {
                scanId,
                currentFile: target,
                filesScanned: totalFilesScanned,
              });
            },
            onThreat({ filePath, threatName }) {
              totalThreatsFound++;
              push('scan:threat', { scanId, filePath, threatName });

              // Auto-quarantine (best effort)
              try {
                const quarantine = require('../../engine/quarantine');
                quarantine.quarantineFile(filePath, threatName).catch(() => {});
              } catch (_) {}
            },
          });

          if (result) {
            totalFilesScanned += result.filesScanned || 0;
            totalThreatsFound += result.threatsFound || 0;
          }
        }
      } catch (err) {
        console.error('[scan-handlers] Scan error:', err.message);
      }

      // Update DB record
      const endedAt = new Date().toISOString();
      const status = controller.signal.aborted ? 'cancelled' : 'complete';
      try {
        const db = getDb();
        if (dbRecordId) {
          db.prepare(
            'UPDATE scan_history SET ended_at = ?, files_scanned = ?, threats_found = ?, status = ? WHERE id = ?'
          ).run(endedAt, totalFilesScanned, totalThreatsFound, status, dbRecordId);
        }
      } catch (err) {
        console.error('[scan-handlers] DB update failed:', err.message);
      }

      // Push complete
      push('scan:complete', {
        scanId,
        result: {
          filesScanned: totalFilesScanned,
          threatsFound: totalThreatsFound,
          cancelled: controller.signal.aborted,
          duration: Date.now() - new Date(startedAt).getTime(),
        },
      });

      activeScan = null;
    })();

    return { scanId };
  });

  // ══════════════════════════════════════════════════════════════════════════
  // scan:cancel
  // ══════════════════════════════════════════════════════════════════════════
  ipcMain.handle('scan:cancel', async () => {
    if (activeScan) {
      activeScan.controller.abort();
      return { success: true };
    }
    return { success: false, reason: 'No active scan' };
  });

  // ══════════════════════════════════════════════════════════════════════════
  // scan:history
  // ══════════════════════════════════════════════════════════════════════════
  ipcMain.handle('scan:history', async (_event, { limit } = {}) => {
    try {
      const db = getDb();
      const rows = db.prepare(
        'SELECT * FROM scan_history ORDER BY started_at DESC LIMIT ?'
      ).all(limit || 50);
      return rows;
    } catch (err) {
      console.error('[scan-handlers] History query failed:', err.message);
      return [];
    }
  });
}

module.exports = { register };
