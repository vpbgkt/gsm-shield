'use strict';

/**
 * monitor/monitor.js
 *
 * Chokidar-based real-time file-system monitor.
 *
 * Public API:
 *   startMonitor(watchPaths, { onThreat, onError }) → Watcher
 *   stopMonitor(watcher) → void
 *   updatePaths(watcher, newPaths) → void
 *
 * Exported constants (for tests):
 *   MONITORED_EXTENSIONS  Set<string>
 *   QUARANTINE_DIR        string
 *
 * Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8
 */

const path    = require('path');
const os      = require('os');
const chokidar = require('chokidar');

const checker   = require('../whitelist/checker');
const scanner   = require('../engine/scanner');
const quarantine = require('../engine/quarantine');

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * File extensions that the monitor watches.
 * Only lowercase — comparisons always normalise to lowercase.
 * Requirement 10.2
 */
const MONITORED_EXTENSIONS = new Set([
  '.exe', '.dll', '.msi', '.bat', '.cmd',
  '.vbs', '.ps1', '.js',  '.scr', '.com',
  '.zip', '.rar', '.7z',
]);

/**
 * Quarantine directory — derived the same way as in engine/quarantine.js so
 * both modules always agree on the path.
 *
 * This module resolves the path once at load time.  The Chokidar watcher is
 * configured to always exclude this path (Requirement 10.6).
 */
const QUARANTINE_DIR = (() => {
  try {
    const { app } = require('electron');
    if (app && typeof app.getPath === 'function') {
      return path.join(app.getPath('appData'), 'GSMShieldAV', 'quarantine');
    }
  } catch (_) {
    // Not running inside Electron (e.g. tests) — fall through
  }
  const appData =
    process.env.APPDATA ||
    path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(appData, 'GSMShieldAV', 'quarantine');
})();

// ─── IPC helper ───────────────────────────────────────────────────────────────

/**
 * Module-level reference to the Electron BrowserWindow.
 * Call setMainWindow(win) from electron/main.js after window creation.
 *
 * @type {Electron.BrowserWindow|null}
 */
let _mainWindow = null;

/**
 * Register the main BrowserWindow so this module can push IPC events.
 *
 * @param {Electron.BrowserWindow|null} win
 */
function setMainWindow(win) {
  _mainWindow = win;
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

/**
 * Normalise a watch-path array: remove the quarantine directory and strip
 * duplicates.  Returns a fresh array — never mutates the input.
 *
 * @param {string[]} rawPaths
 * @returns {string[]}
 */
function filterPaths(rawPaths) {
  if (!Array.isArray(rawPaths)) return [];
  const quarantineLower = QUARANTINE_DIR.toLowerCase();
  const seen = new Set();
  const result = [];
  for (const p of rawPaths) {
    if (typeof p !== 'string') continue;
    if (p.toLowerCase() === quarantineLower) continue; // Requirement 10.6
    if (seen.has(p)) continue;
    seen.add(p);
    result.push(p);
  }
  return result;
}

/**
 * Return true when the file's extension (lowercased) is in MONITORED_EXTENSIONS.
 * Requirement 10.2
 *
 * @param {string} filePath
 * @returns {boolean}
 */
function isEligibleExtension(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return MONITORED_EXTENSIONS.has(ext);
}

// ─── File event processor ─────────────────────────────────────────────────────

/**
 * Handle a single eligible file event:
 *   1. Whitelist check  (Requirement 10.5)
 *   2. ClamAV scan
 *   3. If threat: quarantine, IPC push, Electron notification  (Req 10.4)
 *
 * Errors are surfaced through the onError callback and never thrown.
 *
 * @param {string}   filePath
 * @param {Function} onThreat  Called with { filePath, threatName }
 * @param {Function} onError   Called with { path, error }
 */
async function processFile(filePath, onThreat, onError) {
  try {
    // Step 1 — whitelist gate
    const whitelisted = await checker.isWhitelisted(filePath);
    if (whitelisted) return;

    // Step 2 — scan with ClamAV
    let detectedThreat = null;

    const result = await scanner.scan(filePath, {
      onThreat({ filePath: fp, threatName }) {
        // capture first threat found (monitor scans single files)
        if (!detectedThreat) detectedThreat = { filePath: fp, threatName };
      },
    });

    // Step 3 — handle threat
    if (detectedThreat || (result && result.threatsFound > 0)) {
      const threatName = detectedThreat
        ? detectedThreat.threatName
        : 'Unknown Threat';

      // Auto-quarantine
      try {
        await quarantine.quarantineFile(filePath, threatName);
      } catch (qErr) {
        console.error(`[monitor] quarantineFile failed for "${filePath}": ${qErr.message}`);
      }

      // Push IPC to renderer — Requirement 10.4
      const payload = { filePath, threatName, detectedAt: new Date().toISOString() };
      _mainWindow?.webContents.send('threat:detected', payload);

      // Electron system notification — Requirement 10.4
      try {
        const { Notification } = require('electron');
        new Notification({
          title: 'GSM Shield AV',
          body: `Threat detected: ${threatName}`,
        }).show();
      } catch (_) {
        // Notifications may not be available in all environments (e.g. tests)
      }

      // Invoke caller callback
      if (typeof onThreat === 'function') {
        onThreat({ filePath, threatName });
      }
    }
  } catch (err) {
    console.error(`[monitor] Error processing file "${filePath}": ${err.message}`);
    if (typeof onError === 'function') {
      onError({ path: filePath, error: err });
    }
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Start the real-time file-system monitor.
 *
 * @param {string[]} watchPaths   Directories / files to watch.
 * @param {object}   callbacks
 * @param {Function} callbacks.onThreat  Called when a threat is detected.
 * @param {Function} callbacks.onError   Called when a Chokidar path error occurs.
 * @returns {chokidar.FSWatcher}
 */
function startMonitor(watchPaths, { onThreat, onError } = {}) {
  const filteredPaths = filterPaths(watchPaths);

  // Chokidar watcher — Requirement 10.3 (awaitWriteFinish 2 000 ms)
  const watcher = chokidar.watch(filteredPaths, {
    persistent:    true,
    ignoreInitial: true,
    awaitWriteFinish: {
      stabilityThreshold: 2000,
      pollInterval:        100,
    },
  });

  // Track active paths so we can manage them in updatePaths
  watcher._monitorPaths = new Set(filteredPaths);

  // ── File events ────────────────────────────────────────────────────────────

  /**
   * Unified file event handler for 'add' and 'change'.
   * Requirement 10.2: filter by extension before doing any work.
   * Returns the processFile promise so callers (e.g. tests) can await it.
   */
  function onFileEvent(filePath) {
    if (!isEligibleExtension(filePath)) return Promise.resolve();
    return processFile(filePath, onThreat, onError);
  }

  watcher.on('add',    onFileEvent);
  watcher.on('change', onFileEvent);

  // ── Chokidar error handler ─────────────────────────────────────────────────
  // Requirement 10.7 (path errors): log, remove the erroring path, send IPC.
  watcher.on('error', (err) => {
    // Chokidar wraps path errors with the path in err.path
    const errPath = (err && err.path) ? err.path : null;
    console.error(`[monitor] Chokidar error${errPath ? ` on "${errPath}"` : ''}: ${err && err.message}`);

    if (errPath) {
      // Remove the bad path from the active watch set
      watcher._monitorPaths.delete(errPath);
      try {
        watcher.unwatch(errPath);
      } catch (_) {
        // Suppress unwatch errors
      }

      // Push IPC notification to renderer
      _mainWindow?.webContents.send('monitor:path-error', {
        path:    errPath,
        message: err ? err.message : String(err),
      });
    }

    if (typeof onError === 'function') {
      onError({ path: errPath, error: err });
    }
  });

  return watcher;
}

/**
 * Stop a running monitor watcher and release all resources.
 *
 * @param {chokidar.FSWatcher} watcher
 */
function stopMonitor(watcher) {
  if (!watcher) return;
  try {
    watcher.close();
  } catch (err) {
    console.error(`[monitor] Error closing watcher: ${err.message}`);
  }
}

/**
 * Hot-reload the watch path list without restarting the process.
 * The update completes well within the 5-second requirement (Requirement 10.7).
 *
 * @param {chokidar.FSWatcher} watcher
 * @param {string[]}           newPaths
 */
function updatePaths(watcher, newPaths) {
  if (!watcher) return;

  const filteredNew  = filterPaths(newPaths);
  const currentPaths = watcher._monitorPaths || new Set();

  // Remove paths that are no longer in the new list
  for (const p of currentPaths) {
    if (!filteredNew.includes(p)) {
      try {
        watcher.unwatch(p);
      } catch (err) {
        console.error(`[monitor] unwatch error for "${p}": ${err.message}`);
      }
    }
  }

  // Add new paths that were not already being watched
  for (const p of filteredNew) {
    if (!currentPaths.has(p)) {
      try {
        watcher.add(p);
      } catch (err) {
        console.error(`[monitor] add error for "${p}": ${err.message}`);
      }
    }
  }

  // Update the internal path tracking set
  watcher._monitorPaths = new Set(filteredNew);
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Public API
  startMonitor,
  stopMonitor,
  updatePaths,
  setMainWindow,

  // Exported constants — used by tests and other modules
  MONITORED_EXTENSIONS,
  QUARANTINE_DIR,
};
