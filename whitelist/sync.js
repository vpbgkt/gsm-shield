'use strict';

/**
 * whitelist/sync.js
 *
 * Cloud sync module for the whitelist.
 *
 * Public API:
 *   syncFromCloud()         → Promise<{ added, updated, timestamp }>
 *   scheduleSync()          → void   (sets up 24h interval, skips if license inactive)
 *   setMainWindow(win)      → void   (provides BrowserWindow reference for IPC push)
 *   setLicenseStatus(bool)  → void   (injects current license active state)
 *   isLicenseActive()       → boolean
 *
 * Requirements: 4.1, 4.2, 4.3, 4.5, 25.1
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const db = require('./db');

// ─── Module-level state ───────────────────────────────────────────────────────

/** @type {Electron.BrowserWindow | null} */
let _mainWindow = null;

/** @type {boolean} */
let _licenseActive = false;

/**
 * Consecutive failure tracking for the 72-hour "sync-error" escalation.
 * Resets to 0 on any successful sync.
 */
let _consecutiveFailureMs = 0;

/** The NodeJS timeout handle for the current back-off retry, if any. */
let _retryTimer = null;

/** The NodeJS interval handle for the 24h scheduler. */
let _scheduleInterval = null;

/**
 * Maximum back-off delay in milliseconds (8 hours).
 * @constant {number}
 */
const MAX_BACKOFF_MS = 8 * 60 * 60 * 1000; // 8h

/**
 * Threshold after which we push a 'whitelist:sync-error' IPC event (72 hours).
 * @constant {number}
 */
const ERROR_THRESHOLD_MS = 72 * 60 * 60 * 1000; // 72h

/**
 * Interval between scheduled syncs (24 hours).
 * @constant {number}
 */
const SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24h

// ─── Setters / getters ────────────────────────────────────────────────────────

/**
 * Provide the BrowserWindow reference so IPC push events can be sent.
 * Call this from main.js after the window is created.
 *
 * @param {Electron.BrowserWindow | null} win
 */
function setMainWindow(win) {
  _mainWindow = win;
}

/**
 * Inject the current license active state.
 * Call this whenever the license status changes (activation / deactivation).
 *
 * @param {boolean} active
 */
function setLicenseStatus(active) {
  _licenseActive = Boolean(active);
}

/**
 * Return whether the license is currently active.
 *
 * @returns {boolean}
 */
function isLicenseActive() {
  return _licenseActive;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolve the settings row helpers inline to avoid circular-dependency issues.
 * The database module may not be initialised at require-time in some test setups.
 */
function getDb() {
  return require('../database').getDb();
}

/**
 * Read a single setting value from the SQLite settings table.
 *
 * @param {string} key
 * @returns {string | null}
 */
function readSetting(key) {
  try {
    const row = getDb()
      .prepare('SELECT value FROM settings WHERE key = ?')
      .get(key);
    return row ? row.value : null;
  } catch (_) {
    return null;
  }
}

/**
 * Write a single setting value to the SQLite settings table.
 *
 * @param {string} key
 * @param {string} value
 */
function writeSetting(key, value) {
  try {
    getDb()
      .prepare('UPDATE settings SET value = ? WHERE key = ?')
      .run(value, key);
  } catch (err) {
    console.error('[sync] Failed to write setting:', key, err.message);
  }
}

/**
 * Push a one-way IPC event to the renderer window if available.
 *
 * @param {string} channel
 * @param {object} payload
 */
function pushIpc(channel, payload) {
  if (_mainWindow && !_mainWindow.isDestroyed()) {
    _mainWindow.webContents.send(channel, payload);
  }
}

/**
 * Perform an HTTPS (or HTTP) GET request and resolve with the parsed JSON body.
 * Rejects on connection error, non-200 status, or invalid JSON.
 *
 * @param {string} rawUrl   — Full URL, e.g. https://api.example.com/whitelist
 * @param {string} apiKey   — Value for the Authorization: Bearer header
 * @returns {Promise<Array>} Resolves to the parsed JSON array
 */
function fetchWhitelist(rawUrl, apiKey) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch (err) {
      return reject(new Error(`Invalid BACKEND_URL: ${rawUrl}`));
    }

    const transport = parsed.protocol === 'https:' ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + (parsed.search || ''),
      method: 'GET',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/json',
      },
    };

    const req = transport.request(options, (res) => {
      if (res.statusCode !== 200) {
        // Drain the response body before rejecting, to free the socket
        res.resume();
        return reject(
          new Error(`Server returned HTTP ${res.statusCode}`)
        );
      }

      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (!Array.isArray(parsed)) {
            return reject(new Error('Response body is not a JSON array'));
          }
          resolve(parsed);
        } catch (err) {
          reject(new Error(`JSON parse error: ${err.message}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(new Error(`Network error: ${err.message}`));
    });

    // 30-second timeout so a hung connection doesn't block the app
    req.setTimeout(30_000, () => {
      req.destroy(new Error('Request timed out after 30s'));
    });

    req.end();
  });
}

// ─── Back-off retry logic ──────────────────────────────────────────────────────

/**
 * Back-off delay sequence in milliseconds: 1h → 2h → 4h → 8h (capped).
 * @param {number} attempt  — zero-based attempt index (0 = first retry)
 * @returns {number} Milliseconds to wait before the next retry
 */
function backoffDelay(attempt) {
  const base = 60 * 60 * 1000; // 1h
  return Math.min(base * Math.pow(2, attempt), MAX_BACKOFF_MS);
}

/**
 * State for the ongoing back-off retry sequence.
 * Reset by a successful sync; incremented by each failure.
 */
let _retryAttempt = 0;

/**
 * Schedule one back-off retry of syncFromCloud().
 * Cancels any previously scheduled retry before setting the new one.
 */
function scheduleRetry() {
  if (_retryTimer) {
    clearTimeout(_retryTimer);
    _retryTimer = null;
  }

  const delay = backoffDelay(_retryAttempt);
  _retryAttempt += 1;

  console.log(
    `[sync] Scheduling retry #${_retryAttempt} in ${delay / 1000 / 60} min`
  );

  _retryTimer = setTimeout(async () => {
    _retryTimer = null;
    await syncFromCloud({ _isRetry: true });
  }, delay);
}

// ─── Core sync function ────────────────────────────────────────────────────────

/**
 * Pull the current whitelist from the cloud backend, upsert entries into the
 * local SQLite database, and update the `last_sync_at` setting.
 *
 * On any network / HTTP error:
 *   - Increments the consecutive-failure accumulator.
 *   - Schedules an exponential back-off retry (1h → 2h → 4h → 8h max).
 *   - If failures have persisted for > 72 consecutive hours, pushes the
 *     `whitelist:sync-error` IPC channel to the renderer.
 *
 * Never throws — always resolves with a structured result object.
 *
 * @param {object}  [_opts]
 * @param {boolean} [_opts._isRetry=false]  — internal flag; callers should not set this
 * @returns {Promise<{ added: number, updated: number, timestamp: string }>}
 */
async function syncFromCloud({ _isRetry = false } = {}) {
  const backendUrl = (process.env.BACKEND_URL || '').replace(/\/$/, '') + '/whitelist';
  const apiKey = process.env.API_KEY || '';

  if (!process.env.BACKEND_URL) {
    console.warn('[sync] BACKEND_URL is not set — skipping sync');
    return { added: 0, updated: 0, timestamp: new Date().toISOString() };
  }

  let entries;
  try {
    entries = await fetchWhitelist(backendUrl, apiKey);
  } catch (err) {
    // ── Failure path ──────────────────────────────────────────────────────────
    console.error('[sync] Fetch failed:', err.message);

    // Accumulate time for the 72-hour error threshold.
    // We add the delay that *just elapsed* (i.e. the back-off that brought us here)
    // plus, on the very first failure, treat it as 0 elapsed (retry not yet tried).
    if (_isRetry && _retryAttempt > 0) {
      _consecutiveFailureMs += backoffDelay(_retryAttempt - 1);
    }

    // Escalate to UI if failures have persisted beyond 72 hours
    if (_consecutiveFailureMs >= ERROR_THRESHOLD_MS) {
      console.error('[sync] Sync has been failing for >72 hours — pushing sync-error IPC');
      pushIpc('whitelist:sync-error', {
        message: `Whitelist cloud sync has been unavailable for more than 72 hours. Last error: ${err.message}`,
      });
    }

    // Schedule next back-off retry
    scheduleRetry();

    return { added: 0, updated: 0, timestamp: new Date().toISOString() };
  }

  // ── Success path ────────────────────────────────────────────────────────────

  // Reset failure state
  _consecutiveFailureMs = 0;
  _retryAttempt = 0;
  if (_retryTimer) {
    clearTimeout(_retryTimer);
    _retryTimer = null;
  }

  // Count entries before and after to derive added/updated counts
  let existingCount = 0;
  try {
    existingCount = getDb()
      .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'cloud'")
      .get().cnt;
  } catch (_) {
    // Non-fatal — counts are informational only
  }

  // Upsert all cloud entries, preserving user-source rows
  try {
    db.upsertCloudEntries(entries);
  } catch (err) {
    console.error('[sync] upsertCloudEntries failed:', err.message);
    // Still update last_sync_at so the UI shows the attempt was made
  }

  // Count after upsert
  let newCount = 0;
  try {
    newCount = getDb()
      .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'cloud'")
      .get().cnt;
  } catch (_) {
    // Non-fatal
  }

  const added = Math.max(0, newCount - existingCount);
  const updated = Math.max(0, entries.length - added);
  const timestamp = new Date().toISOString();

  // Persist last_sync_at
  writeSetting('last_sync_at', timestamp);

  console.log(`[sync] Sync complete — added: ${added}, updated: ${updated}`);

  return { added, updated, timestamp };
}

// ─── Scheduler ────────────────────────────────────────────────────────────────

/**
 * Set up a 24-hour repeating interval that calls syncFromCloud().
 * Skips the sync tick when the license is inactive.
 *
 * Safe to call multiple times — a second call clears the existing interval
 * before starting a new one.
 */
function scheduleSync() {
  if (_scheduleInterval) {
    clearInterval(_scheduleInterval);
    _scheduleInterval = null;
  }

  _scheduleInterval = setInterval(async () => {
    if (!isLicenseActive()) {
      console.log('[sync] Skipping scheduled sync — license inactive');
      return;
    }
    await module.exports.syncFromCloud();
  }, SYNC_INTERVAL_MS);

  // Allow Node.js / Electron to exit cleanly — the interval should not
  // prevent the process from shutting down.
  if (_scheduleInterval.unref) {
    _scheduleInterval.unref();
  }

  console.log('[sync] 24h sync scheduler started');
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  syncFromCloud,
  scheduleSync,
  setMainWindow,
  setLicenseStatus,
  isLicenseActive,

  // Exported for testing only — allows tests to inspect / reset internal state
  _resetState() {
    _consecutiveFailureMs = 0;
    _retryAttempt = 0;
    if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; }
    if (_scheduleInterval) { clearInterval(_scheduleInterval); _scheduleInterval = null; }
    _mainWindow = null;
    _licenseActive = false;
  },
  _getConsecutiveFailureMs() { return _consecutiveFailureMs; },
  _getRetryAttempt()        { return _retryAttempt; },
  _backoffDelay: backoffDelay,
};
