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
 * Neutralized storage format (v1).
 *
 * Quarantined files used to be stored as "<uuid>_<name>.exe": still a valid,
 * runnable program sitting in a user-writable folder. For a file infector such
 * as Expiro that means one accidental double-click re-infects the machine, and
 * the copy can be re-infected or re-detected by other scanners.
 *
 * Files are now stored as "<uuid>_<name>.gsmq": an 8-byte header followed by
 * the content XOR-ed with a constant. The stored file has no "MZ" header and a
 * non-executable extension, so Windows cannot run it even if renamed.
 * restoreFile() decodes it and still accepts legacy raw entries.
 */
const QUARANTINE_EXT = '.gsmq';
const QUARANTINE_MAGIC = Buffer.from('GSMQ\x01\x00\x00\x00', 'latin1');
const QUARANTINE_XOR = 0xa5;

/**
 * Ensure the quarantine directory exists, creating it if necessary.
 */
function ensureQuarantineDir() {
  fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
}

/** XOR a buffer in place with the quarantine key. */
function xorInPlace(buf) {
  for (let i = 0; i < buf.length; i++) buf[i] ^= QUARANTINE_XOR;
  return buf;
}

/** Copy `src` to `dst` applying the XOR transform, optionally writing/skipping the header. */
function transcode(src, dst, { writeHeader, skipHeader }) {
  const inFd = fs.openSync(src, 'r');
  let outFd = null;
  try {
    outFd = fs.openSync(dst, 'wx');
    if (writeHeader) fs.writeSync(outFd, QUARANTINE_MAGIC);
    const chunk = Buffer.alloc(1024 * 1024);
    let pos = skipHeader ? QUARANTINE_MAGIC.length : 0;
    for (;;) {
      const n = fs.readSync(inFd, chunk, 0, chunk.length, pos);
      if (n <= 0) break;
      fs.writeSync(outFd, xorInPlace(chunk.subarray(0, n)));
      pos += n;
    }
  } catch (err) {
    if (outFd !== null) { try { fs.closeSync(outFd); } catch (_) { /* ignore */ } outFd = null; }
    try { fs.unlinkSync(dst); } catch (_) { /* ignore */ }
    throw err;
  } finally {
    if (outFd !== null) fs.closeSync(outFd);
    fs.closeSync(inFd);
  }
}

/** True when the stored file uses the neutralized format. */
function isNeutralized(quarantinePath) {
  let fd = null;
  try {
    fd = fs.openSync(quarantinePath, 'r');
    const head = Buffer.alloc(QUARANTINE_MAGIC.length);
    const n = fs.readSync(fd, head, 0, head.length, 0);
    return n === head.length && head.equals(QUARANTINE_MAGIC);
  } catch (_) {
    return false;
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

/**
 * Quarantine an infected file: store a neutralized copy in the quarantine
 * directory under a unique name, remove the original, compute its hash, and
 * record metadata in the database.
 *
 * @param {string} filePath - Absolute path to the file to quarantine
 * @param {string} threatName - Name/identifier of the threat detected
 * @returns {Promise<{quarantinePath: string, fileHash: string, fileSize: number}>}
 */
async function quarantineFile(filePath, threatName) {
  ensureQuarantineDir();

  // 1. Compute SHA-256 hash of the original file
  const fileHash = await hashFile(filePath);

  // 2. Get file size
  const stats = fs.statSync(filePath);
  const fileSize = stats.size;

  // 3. Unique, non-executable quarantine filename: <uuid>_<basename>.gsmq
  const uuid = crypto.randomUUID();
  const basename = path.basename(filePath);
  const quarantineName = `${uuid}_${basename}${QUARANTINE_EXT}`;
  const quarantinePath = path.join(QUARANTINE_DIR, quarantineName);

  // 4. Write the neutralized copy, then remove the original. Copy+delete also
  // works across volumes (no EXDEV special case needed). If the original
  // cannot be deleted (locked/running), roll back so nothing is half-done.
  transcode(filePath, quarantinePath, { writeHeader: true, skipHeader: false });
  try {
    fs.unlinkSync(filePath);
  } catch (err) {
    try { fs.unlinkSync(quarantinePath); } catch (_) { /* ignore */ }
    throw err;
  }

  // 5. Insert record into quarantine table
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO quarantine (original_path, quarantine_path, threat_name, file_hash, file_size)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(filePath, quarantinePath, threatName, fileHash, fileSize);

  // 6. Return quarantine metadata for callers (disinfector etc.)
  return { quarantinePath, fileHash, fileSize };
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

  // Restore file to original location.
  if (isNeutralized(quarantine_path)) {
    // Neutralized entry: decode to the original path, then remove the stored copy.
    if (fs.existsSync(original_path)) fs.unlinkSync(original_path);
    transcode(quarantine_path, original_path, { writeHeader: false, skipHeader: true });
    fs.unlinkSync(quarantine_path);
  } else {
    // Legacy raw entry (created before the neutralized format).
    // Handle EXDEV (cross-volume): fall back to copy-then-delete.
    try {
      fs.renameSync(quarantine_path, original_path);
    } catch (err) {
      if (err.code === 'EXDEV') {
        fs.copyFileSync(quarantine_path, original_path);
        fs.unlinkSync(quarantine_path);
      } else {
        throw err;
      }
    }
  }

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
  QUARANTINE_EXT,
  QUARANTINE_MAGIC,
  quarantineFile,
  restoreFile,
  deleteFile,
  isNeutralized,
  OriginalPathMissingError,
};
