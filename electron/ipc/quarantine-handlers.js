'use strict';

/**
 * electron/ipc/quarantine-handlers.js
 *
 * Registers all quarantine-related IPC channels:
 *   quarantine:list       — SELECT * FROM quarantine ORDER BY detected_at DESC
 *   quarantine:restore    — restore file to original path; on OriginalPathMissingError return { needsPath: true }
 *   quarantine:restore-to — fs.rename to user-chosen destination, then delete DB record
 *   quarantine:delete     — permanently delete file from disk and remove DB record
 *
 * Note: QUARANTINE_DIR exclusion from monitor watch paths is enforced by the
 * monitor module (monitor/monitor.js, task 7.1). The monitor filters out the
 * QUARANTINE_DIR from all watch paths before passing them to Chokidar to ensure
 * quarantined files are never re-scanned (Requirement 9.2, 10.6).
 *
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.6
 */

const fs = require('fs');
const path = require('path');

// ─── Main registration function ───────────────────────────────────────────────

/**
 * Register all quarantine IPC handlers.
 *
 * @param {Electron.IpcMain} ipcMain
 * @param {Object} deps
 * @param {() => import('better-sqlite3').Database} deps.getDb
 * @param {() => object} deps.getQuarantine - engine/quarantine.js module
 */
function register(ipcMain, { getDb, getQuarantine }) {
  // ── quarantine:list ──────────────────────────────────────────────────────────
  // Returns all quarantine entries ordered by detection date (newest first).
  // Requirement 9.1: display all quarantine entries in the Quarantine page.
  ipcMain.handle('quarantine:list', () => {
    try {
      const db = getDb();
      const stmt = db.prepare(`
        SELECT * FROM quarantine 
        ORDER BY detected_at DESC
      `);
      const entries = stmt.all();
      return entries;
    } catch (err) {
      console.error('[quarantine-handlers] quarantine:list failed:', err.message);
      return [];
    }
  });

  // ── quarantine:restore ───────────────────────────────────────────────────────
  // Attempts to restore a quarantined file to its original path.
  // If the original directory no longer exists, returns { success: false, needsPath: true }.
  // Requirements: 9.3, 9.6
  ipcMain.handle('quarantine:restore', async (_event, { id }) => {
    try {
      const quarantine = getQuarantine();
      await quarantine.restoreFile(id);
      
      return {
        success: true,
        message: 'File restored to original location.',
      };
    } catch (err) {
      // Check if this is the OriginalPathMissingError
      if (err.name === 'OriginalPathMissingError') {
        // Requirement 9.6: prompt user to choose alternative destination
        return {
          success: false,
          needsPath: true,
          message: err.message,
        };
      }

      console.error('[quarantine-handlers] quarantine:restore failed:', err.message);
      return {
        success: false,
        error: `Failed to restore file: ${err.message}`,
      };
    }
  });

  // ── quarantine:restore-to ────────────────────────────────────────────────────
  // Restores a quarantined file to a user-chosen destination path.
  // Uses fs.rename to move the file, then deletes the DB record.
  // Requirement 9.6: allow user to choose alternative restore destination.
  ipcMain.handle('quarantine:restore-to', async (_event, { id, destPath }) => {
    try {
      const db = getDb();

      // 1. Look up the quarantine record
      const stmt = db.prepare(`
        SELECT quarantine_path, original_path
        FROM quarantine
        WHERE id = ?
      `);
      const record = stmt.get(id);

      if (!record) {
        return {
          success: false,
          error: 'Quarantine entry not found.',
        };
      }

      const { quarantine_path } = record;

      // 2. Verify the quarantine file still exists
      if (!fs.existsSync(quarantine_path)) {
        return {
          success: false,
          error: 'Quarantined file no longer exists on disk.',
        };
      }

      // 3. Ensure destination directory exists
      const destDir = path.dirname(destPath);
      if (!fs.existsSync(destDir)) {
        return {
          success: false,
          error: `Destination directory does not exist: ${destDir}`,
        };
      }

      // 4. Move the file to the new destination (atomic rename)
      fs.renameSync(quarantine_path, destPath);

      // 5. Delete the quarantine record
      const deleteStmt = db.prepare('DELETE FROM quarantine WHERE id = ?');
      deleteStmt.run(id);

      return {
        success: true,
        message: `File restored to ${destPath}`,
      };
    } catch (err) {
      console.error('[quarantine-handlers] quarantine:restore-to failed:', err.message);
      return {
        success: false,
        error: `Failed to restore file: ${err.message}`,
      };
    }
  });

  // ── quarantine:delete ────────────────────────────────────────────────────────
  // Permanently deletes a quarantined file from disk and removes its DB record.
  // Requirement 9.4: securely delete file and remove quarantine entry.
  ipcMain.handle('quarantine:delete', async (_event, { id }) => {
    try {
      const quarantine = getQuarantine();
      await quarantine.deleteFile(id);

      return {
        success: true,
        message: 'File permanently deleted.',
      };
    } catch (err) {
      console.error('[quarantine-handlers] quarantine:delete failed:', err.message);
      return {
        success: false,
        error: `Failed to delete file: ${err.message}`,
      };
    }
  });
}

module.exports = { register };
