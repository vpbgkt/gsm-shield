'use strict';

/**
 * electron/ipc/whitelist-handlers.js
 *
 * Registers all whitelist-related IPC channels:
 *   whitelist:list    — return all whitelist entries (optionally filtered by query)
 *   whitelist:add     — hash file, check duplicate, check license cap, insert entry
 *   whitelist:remove  — delete user entry (forbidden for bundled/cloud)
 *   whitelist:submit  — validate hash, POST to backend /submissions
 *   whitelist:sync    — trigger cloud sync via sync.js
 *
 * Requirements: 3.1, 3.2, 3.3, 3.5, 5.1, 5.2, 5.3, 5.4
 */

const path = require('path');
const https = require('https');

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Maximum number of user-added whitelist entries allowed when license is inactive.
 * Requirement 3.5: cap user-added entries at 10 when license is inactive.
 */
const MAX_USER_ENTRIES_UNLICENSED = 10;

/**
 * Backend URL and API endpoint for submissions.
 * In production, this should be configured via environment variable.
 * Requirement 5.1: POST to backend /submissions endpoint.
 */
const BACKEND_URL = process.env.BACKEND_URL || 'https://gsm-shield-backend.example.com';
const SUBMISSIONS_ENDPOINT = '/submissions';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Validate that a string is a valid 64-character lowercase hexadecimal SHA-256 hash.
 * Requirement 5.4: validate 64-char hex before submitting.
 * Only lowercase hex characters [0-9a-f] are accepted.
 *
 * @param {string} hash - The string to validate
 * @returns {boolean} True if valid lowercase SHA-256 hex, false otherwise
 */
function isValidSHA256(hash) {
  if (typeof hash !== 'string') return false;
  if (hash.length !== 64) return false;
  return /^[0-9a-f]{64}$/.test(hash);
}

/**
 * Check if the license is currently active.
 * Returns false when license is inactive or in grace period with restrictions.
 * Requirement 3.5: check license status for whitelist cap enforcement.
 *
 * This is a placeholder — in a full implementation, this would query
 * the license module or store to get current license status.
 *
 * @param {Function} getLicense - Function that returns license status object
 * @returns {boolean} True if license is active
 */
function isLicenseActive(getLicense) {
  try {
    if (!getLicense) return false;
    const license = getLicense();
    if (!license) return false;
    return license.status === 'active';
  } catch (_) {
    return false;
  }
}

/**
 * POST submission data to the backend /submissions endpoint.
 * Requirement 5.1: send POST request to backend endpoint.
 * Requirement 5.3: return descriptive error on failure.
 *
 * @param {Object} submission - { hash, name, vendor }
 * @returns {Promise<{ success: boolean, error?: string }>}
 */
function submitToBackend(submission) {
  return new Promise((resolve) => {
    const postData = JSON.stringify(submission);
    const url = new URL(SUBMISSIONS_ENDPOINT, BACKEND_URL);

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData),
    };

    // Include Authorization header when API_KEY is configured
    // Requirement 5.1: POST to backend /submissions with Authorization header
    const apiKey = process.env.API_KEY;
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname,
      method: 'POST',
      headers,
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          // Success (2xx)
          resolve({ success: true });
        } else {
          // Backend returned error status
          resolve({
            success: false,
            error: `Backend returned ${res.statusCode}: ${body}`,
          });
        }
      });
    });

    req.on('error', (err) => {
      // Network error or connection failure
      resolve({
        success: false,
        error: `Network error: ${err.message}`,
      });
    });

    req.write(postData);
    req.end();
  });
}

// ─── Main registration function ───────────────────────────────────────────────

/**
 * Register all whitelist IPC handlers.
 *
 * @param {Electron.IpcMain} ipcMain
 * @param {Object} deps
 * @param {() => import('better-sqlite3').Database} deps.getDb
 * @param {() => object} deps.getHasher   - whitelist/hasher.js module
 * @param {() => object} deps.getWhitelistDb - whitelist/db.js module
 * @param {() => object} deps.getSync     - whitelist/sync.js module (for cloud sync)
 * @param {() => object} deps.getLicense  - license status getter (returns { status, ... })
 */
function register(ipcMain, { getDb, getHasher, getWhitelistDb, getSync, getLicense }) {
  // ── whitelist:list ───────────────────────────────────────────────────────────
  // Returns all whitelist entries, optionally filtered by query string.
  // Requirement 3.1: list all entries with optional search.
  ipcMain.handle('whitelist:list', (_event, { query } = {}) => {
    try {
      const whitelistDb = getWhitelistDb();
      return whitelistDb.listEntries(query);
    } catch (err) {
      console.error('[whitelist-handlers] whitelist:list failed:', err.message);
      return [];
    }
  });

  // ── whitelist:add ────────────────────────────────────────────────────────────
  // Hash file, check duplicate, check license cap (≤10 user entries when inactive),
  // insert entry with source='user' and verified=0.
  // Requirements: 3.1, 3.2, 3.5
  ipcMain.handle('whitelist:add', async (_event, { filePath }) => {
    try {
      const hasher = getHasher();
      const whitelistDb = getWhitelistDb();

      // 1. Hash the file
      // Requirement 3.1: compute SHA-256 hash of selected file
      let hash;
      try {
        hash = await hasher.hashFile(filePath);
      } catch (hashErr) {
        return {
          success: false,
          error: `Failed to hash file: ${hashErr.message}`,
        };
      }

      // 2. Check for duplicate
      // Requirement 3.2: notify user if file already trusted
      if (whitelistDb.entryExists(hash)) {
        return {
          success: false,
          duplicate: true,
          message: 'This file is already in the whitelist.',
        };
      }

      // 3. Check license cap for user entries
      // Requirement 3.5: cap at 10 user entries when license is inactive
      const licenseActive = isLicenseActive(getLicense);
      if (!licenseActive) {
        const userCount = whitelistDb.countUserEntries();
        if (userCount >= MAX_USER_ENTRIES_UNLICENSED) {
          return {
            success: false,
            capReached: true,
            message: `Whitelist cap reached (${MAX_USER_ENTRIES_UNLICENSED} entries). Activate a license to add more.`,
          };
        }
      }

      // 4. Insert the entry
      // Requirement 3.1: insert with source='user' and verified=0
      const fileName = path.basename(filePath);
      whitelistDb.insertEntry({
        hash,
        name: fileName,
        vendor: '', // User-added entries don't have vendor info by default
        source: 'user',
        verified: 0,
      });

      return {
        success: true,
        hash,
        message: 'File added to whitelist successfully.',
      };
    } catch (err) {
      console.error('[whitelist-handlers] whitelist:add failed:', err.message);
      return {
        success: false,
        error: `Failed to add file: ${err.message}`,
      };
    }
  });

  // ── whitelist:remove ─────────────────────────────────────────────────────────
  // Delete user entry only; returns forbidden if entry is bundled or cloud.
  // Requirement 3.3: only delete user-added entries, protect bundled/cloud entries.
  ipcMain.handle('whitelist:remove', (_event, { hash }) => {
    try {
      const whitelistDb = getWhitelistDb();
      const result = whitelistDb.deleteEntry(hash);

      if (!result.success && result.forbidden) {
        return {
          success: false,
          forbidden: true,
          message: 'Cannot remove pre-built or cloud-synced entries.',
        };
      }

      if (!result.success) {
        return {
          success: false,
          message: 'Entry not found.',
        };
      }

      return {
        success: true,
        message: 'Entry removed from whitelist.',
      };
    } catch (err) {
      console.error('[whitelist-handlers] whitelist:remove failed:', err.message);
      return {
        success: false,
        error: `Failed to remove entry: ${err.message}`,
      };
    }
  });

  // ── whitelist:submit ─────────────────────────────────────────────────────────
  // Validate 64-char lowercase hex hash, POST to backend /submissions endpoint.
  // Requirements: 5.1, 5.2, 5.3, 5.4, 25.4
  ipcMain.handle('whitelist:submit', async (_event, { hash, name, vendor }) => {
    // 1. Validate hash format — must be exactly 64 lowercase hex chars
    // Requirement 5.4: validate 64-char hex SHA-256 string; return 'invalid_hash' on failure
    if (!isValidSHA256(hash)) {
      return {
        success: false,
        error: 'invalid_hash',
      };
    }

    // 2. Validate required fields
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return {
        success: false,
        error: 'name_required',
      };
    }

    // 3. Submit to backend
    // Requirement 5.1: POST to backend /submissions endpoint with Authorization header
    const submission = {
      hash, // Already validated as lowercase
      name: name.trim(),
      vendor: vendor ? vendor.trim() : '',
    };

    // Wrap in try/catch to guarantee we never throw — Requirement 5.3
    try {
      const result = await submitToBackend(submission);

      if (result.success) {
        // Requirement 5.2: return success on 2xx
        return { success: true };
      } else {
        // Requirement 5.3: return descriptive error on non-2xx or network failure
        return {
          success: false,
          error: result.error || 'submission_failed',
        };
      }
    } catch (err) {
      // Should never reach here since submitToBackend never throws, but guard anyway
      console.error('[whitelist-handlers] whitelist:submit unexpected error:', err.message);
      return {
        success: false,
        error: `submission_failed: ${err.message}`,
      };
    }
  });

  // ── whitelist:sync ───────────────────────────────────────────────────────────
  // Trigger cloud sync via sync.js module.
  // Requirement 4.4: manual sync trigger from Whitelist page.
  ipcMain.handle('whitelist:sync', async () => {
    try {
      const sync = getSync();
      if (!sync || typeof sync.syncFromCloud !== 'function') {
        return {
          success: false,
          error: 'Cloud sync module not available.',
        };
      }

      // Delegate to sync.js syncFromCloud()
      const result = await sync.syncFromCloud();

      return {
        success: true,
        added: result.added || 0,
        updated: result.updated || 0,
        timestamp: result.timestamp || new Date().toISOString(),
      };
    } catch (err) {
      console.error('[whitelist-handlers] whitelist:sync failed:', err.message);
      return {
        success: false,
        error: `Sync failed: ${err.message}`,
      };
    }
  });
}

module.exports = { register, isValidSHA256 };
