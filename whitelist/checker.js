'use strict';

/**
 * whitelist/checker.js
 *
 * Pre-scan whitelist gate: check if a file is whitelisted before invoking ClamAV.
 *
 * Exported function:
 *   isWhitelisted(filePath) → Promise<boolean>
 *
 * Returns true if the file's SHA-256 hash exists in the whitelist database.
 * Returns false on any file-read errors (ENOENT, EACCES, etc.) to allow the
 * scan to proceed — we never block a scan due to whitelist check failures.
 */

const { hashFile } = require('./hasher');
const { entryExists } = require('./db');

/**
 * Check whether a file is whitelisted.
 *
 * @param {string} filePath - Absolute or relative path to the file
 * @returns {Promise<boolean>} Resolves to true if hash exists in whitelist, false otherwise
 */
async function isWhitelisted(filePath) {
  try {
    const hash = await hashFile(filePath);
    return entryExists(hash);
  } catch (err) {
    // File-read errors (ENOENT, EACCES, etc.) should not block the scan
    // Return false to allow the scan to proceed normally
    return false;
  }
}

module.exports = { isWhitelisted };
