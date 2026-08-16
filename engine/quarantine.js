'use strict';

/**
 * engine/quarantine.js
 *
 * Quarantine operations: move infected files to a secure directory, restore
 * them to their original location, and permanently delete them.
 *
 * Works both inside Electron (uses app.getPath('appData')) and in plain
 * Node.js / Jest tests (falls back to os.homedir() + AppData/Roaming).
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { getDb } = require('../database/init');
const { hashFile } = require('../whitelist/hasher');

/**
 * Custom error thrown when the original directory of a quarantined file
 * no longer exists at restore time.
 */
class OriginalPathMissingError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OriginalPathMissingError';
  }
}

/**
 * Resolve the quarantine directory path.
 * Electron provides app.getPath('appData'); outside Electron we derive it
 * from the OS home directory the same way Electron would on Windows.
 *
 * @returns {string} Absolute path to the quarantine directory
 */
function resolveQuarantineDir() {
  try {
    // Running inside Electron main process
    const { app } = require('electron');
    if (app && typeof app.getPath === 'function') {
      return path.join(app.getPath('appData'), 'GSMShieldAV', 'quarantine');
    }
  } catch (_) {
    // Not running in Electron — fall through to OS-based fallback
  }

  // Fallback: %APPDATA% env var (Windows) or homedir + AppData/Roaming
  const appData =
    process.env.APPDATA ||
    path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(appData, 'GSMShieldAV', 'quarantine');
}

/** The quarantine directory path. */
const QUARANTINE_DIR = resolveQuarantineDir();

/**
 * Ensure the quarantine directory exists, creating it if necessary.
 */
function ensureQuarantineDir() {
  fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
}

/**
 * Quarantine an infected file: move it to the quarantine directory with a
 * unique name, compute its hash, and record metadata in the database.
 *
 * @param {string} filePath - Absolute path to the file to quarantine
 * @param {string} threatName - Name/identifier of the threat detected
 * @returns {Promise<void>}
 */
async function quarantineFile(filePath, threatName) {
  ensureQuarantineDir();

  // 1. Compute SHA-256 hash of the file before moving
  const fileHash = await hashFile(filePath);

  // 2. Get file size
  const stats = fs.statSync(filePath);
  const fileSize = stats.size;

  // 3. Generate unique quarantine filename: <uuid>_<basename>
  const uuid = crypto.randomUUID();
  const basename = path.basename(filePath);
  const quarantineName = `${uuid}_${basename}`;
  const quarantinePath = path.join(QUARANTINE_DIR, quarantineName);

  // 4. Move file to quarantine directory.
  // fs.renameSync throws EXDEV when the source and destination are on
  // different volumes/drive letters (e.g. infected file on D:\, quarantine
  // dir on C:\AppData) — rename cannot cross a filesystem boundary. Fall
  // back to copy-then-delete in that case so quarantine still succeeds.
  try {
    fs.renameSync(filePath, quarantinePath);
  } catch (err) {
    if (err.code === 'EXDEV') {
      fs.copyFileSync(filePath, quarantinePath);
      fs.unlinkSync(filePath);
    } else {
      throw err;
    }
  }

  // 5. Insert record into quarantine table
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO quarantine (original_path, quarantine_path, threat_name, file_hash, file_size)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(filePath, quarantinePath, threatName, fileHash, fileSize);
}

/**
 * Restore a quarantined file to its original location.
 *
 * If the original directory no longer exists, throws OriginalPathMissingError.
 * On success, removes the quarantine database record.
 *
 * @param {number} id - Quarantine entry ID
 * @returns {Promise<void>}
 * @throws {OriginalPathMissingError} When the original directory doesn't exist
 * @throws {Error} When the quarantine entry is not found
 */
async function restoreFile(id) {
  const db = getDb();

  // Look up quarantine record
  const stmt = db.prepare(`
    SELECT original_path, quarantine_path
    FROM quarantine
    WHERE id = ?
  `);
  const record = stmt.get(id);

  if (!record) {
    throw new Error(`Quarantine entry not found: ${id}`);
  }

  const { original_path, quarantine_path } = record;

  // Check if original directory exists
  const originalDir = path.dirname(original_path);
  if (!fs.existsSync(originalDir)) {
    throw new OriginalPathMissingError(
      `Original directory no longer exists: ${originalDir}`
    );
  }

  // Restore file to original location (atomic rename)
  fs.renameSync(quarantine_path, original_path);

  // Delete quarantine record
  const deleteStmt = db.prepare('DELETE FROM quarantine WHERE id = ?');
  deleteStmt.run(id);
}

/**
 * Permanently delete a quarantined file from disk and remove its database record.
 *
 * @param {number} id - Quarantine entry ID
 * @returns {Promise<void>}
 * @throws {Error} When the quarantine entry is not found
 */
async function deleteFile(id) {
  const db = getDb();

  // Look up quarantine record
  const stmt = db.prepare('SELECT quarantine_path FROM quarantine WHERE id = ?');
  const record = stmt.get(id);

  if (!record) {
    throw new Error(`Quarantine entry not found: ${id}`);
  }

  const { quarantine_path } = record;

  // Delete file from disk
  if (fs.existsSync(quarantine_path)) {
    fs.unlinkSync(quarantine_path);
  }

  // Delete quarantine record
  const deleteStmt = db.prepare('DELETE FROM quarantine WHERE id = ?');
  deleteStmt.run(id);
}

module.exports = {
  QUARANTINE_DIR,
  quarantineFile,
  restoreFile,
  deleteFile,
  OriginalPathMissingError,
};
