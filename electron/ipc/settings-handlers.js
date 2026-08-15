'use strict';

/**
 * electron/ipc/settings-handlers.js
 *
 * Registers all settings-related IPC channels:
 *   settings:get              — return all settings as a key-value map
 *   settings:set              — update a single setting (validated key)
 *   settings:addPath          — append a path to monitored_paths (deduplicated)
 *   settings:removePath       — remove a path from monitored_paths
 *   settings:getDefinitionInfo— return { version, lastUpdate }
 *   definitions:update        — run FreshClam, stream progress/complete/error
 *
 * On module load (called once from main.js) also:
 *   - Reads pending threat events from threat-events.json and pushes them to
 *     the renderer, then clears the file (Requirements 11.3, 18.1–18.6).
 *   - Wires start_with_windows service registration via node-windows.
 *
 * Export: register(ipcMain, { getDb, getMainWindow, getMonitor, getUpdater })
 *
 * Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 11.1, 11.2, 11.3, 11.4,
 *               18.1, 18.2, 18.3, 18.4, 18.5, 18.6
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * The exhaustive list of keys that exist in the settings table.
 * settings:set rejects any key not in this list.
 */
const KNOWN_SETTINGS_KEYS = [
  'realtime_protection',
  'auto_quarantine',
  'start_with_windows',
  'telemetry_enabled',
  'last_sync_at',
  'first_run_complete',
  'monitored_paths',
  'definition_version',
  'last_definition_update',
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolve the AppData/GSMShieldAV directory.
 * Mirrors the logic in database/init.js so paths are consistent.
 */
function resolveAppDataDir() {
  try {
    const { app } = require('electron');
    if (app && typeof app.getPath === 'function') {
      return path.join(app.getPath('appData'), 'GSMShieldAV');
    }
  } catch (_) {
    // Not running inside Electron (e.g. unit tests)
  }
  const appData =
    process.env.APPDATA ||
    path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(appData, 'GSMShieldAV');
}

/**
 * Read all rows from the settings table and return them as a plain object
 * mapping key → value.
 *
 * @param {import('better-sqlite3').Database} db
 * @returns {Record<string, string>}
 */
function getAllSettings(db) {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const map = {};
  for (const row of rows) {
    map[row.key] = row.value;
  }
  return map;
}

/**
 * Write a single setting key/value pair.
 * Assumes the caller has already validated the key.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} key
 * @param {string} value
 */
function setSetting(db, key, value) {
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(value, key);
}

/**
 * Get a single setting value by key; returns null if not found.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} key
 * @returns {string|null}
 */
function getSetting(db, key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

// ─── Service management (node-windows) ────────────────────────────────────────

/**
 * Build the path where the service config JSON file should live.
 * @returns {string}
 */
function serviceConfigPath() {
  return path.join(resolveAppDataDir(), 'service-config.json');
}

/**
 * Write service-config.json and register the node-windows service.
 * Wrapped in try/catch because node-windows may not be installed.
 *
 * @param {import('better-sqlite3').Database} db
 */
function registerWindowsService(db) {
  try {
    // Write the config that service-wrapper.js reads on startup
    const monitoredPaths = JSON.parse(
      getSetting(db, 'monitored_paths') || '[]'
    );
    const config = {
      monitoredPaths,
      registeredAt: new Date().toISOString(),
    };
    fs.mkdirSync(resolveAppDataDir(), { recursive: true });
    fs.writeFileSync(serviceConfigPath(), JSON.stringify(config, null, 2), 'utf8');

    // Lazy require — node-windows may not be installed in dev environment
    const NodeWindows = require('node-windows'); // eslint-disable-line
    const Service = NodeWindows.Service;

    const svc = new Service({
      name: 'GSM Shield AV Monitor',
      description: 'GSM Shield AV real-time file-system protection service',
      script: path.join(__dirname, '..', '..', 'monitor', 'service-wrapper.js'),
    });

    svc.on('install', () => {
      svc.start();
    });

    svc.install();
  } catch (err) {
    console.error('[settings-handlers] Failed to register Windows service:', err.message);
  }
}

/**
 * Unregister (uninstall) the node-windows service.
 * Wrapped in try/catch because node-windows may not be installed.
 */
function unregisterWindowsService() {
  try {
    const NodeWindows = require('node-windows'); // eslint-disable-line
    const Service = NodeWindows.Service;

    const svc = new Service({
      name: 'GSM Shield AV Monitor',
      script: path.join(__dirname, '..', '..', 'monitor', 'service-wrapper.js'),
    });

    svc.on('uninstall', () => {
      console.log('[settings-handlers] Windows service uninstalled.');
    });

    svc.uninstall();
  } catch (err) {
    console.error('[settings-handlers] Failed to unregister Windows service:', err.message);
  }
}

// ─── Pending threat events (Requirement 11.3) ─────────────────────────────────

/**
 * Read threat events that the background service wrote to threat-events.json
 * while the app was closed, push them to the renderer, then clear the file.
 *
 * Called once during register() so events are delivered on every app open.
 *
 * @param {Function} getMainWindow — getter returning BrowserWindow | null
 */
function flushPendingThreatEvents(getMainWindow) {
  const eventsPath = path.join(resolveAppDataDir(), 'threat-events.json');

  let events = [];
  try {
    if (!fs.existsSync(eventsPath)) return;
    const raw = fs.readFileSync(eventsPath, 'utf8').trim();
    if (!raw) return;
    events = JSON.parse(raw);
    if (!Array.isArray(events) || events.length === 0) return;
  } catch (err) {
    console.error('[settings-handlers] Failed to read threat-events.json:', err.message);
    return;
  }

  // Push events to the renderer window (may not be ready yet — schedule for next tick)
  setImmediate(() => {
    const win = getMainWindow();
    if (win && !win.isDestroyed()) {
      for (const event of events) {
        win.webContents.send('threat:detected', event);
      }
    }
  });

  // Clear the file after reading
  try {
    fs.writeFileSync(eventsPath, '[]', 'utf8');
  } catch (err) {
    console.error('[settings-handlers] Failed to clear threat-events.json:', err.message);
  }
}

// ─── Main registration function ───────────────────────────────────────────────

/**
 * Register all settings and definitions IPC handlers.
 *
 * @param {Electron.IpcMain} ipcMain
 * @param {Object} deps
 * @param {() => import('better-sqlite3').Database} deps.getDb
 * @param {() => Electron.BrowserWindow | null}     deps.getMainWindow
 * @param {() => object | null}                     deps.getMonitor  — live Chokidar watcher instance
 * @param {() => object | null}                     deps.getUpdater  — engine/updater module (lazy)
 */
function register(ipcMain, { getDb, getMainWindow, getMonitor, getUpdater }) {
  // ── Flush any pending threat events written by the background service ────────
  flushPendingThreatEvents(getMainWindow);

  // ── settings:get ─────────────────────────────────────────────────────────────
  // Returns all settings rows as a flat key-value map.
  // Requirement 18.1–18.6: renderer needs all settings to populate the page.
  ipcMain.handle('settings:get', () => {
    const db = getDb();
    return getAllSettings(db);
  });

  // ── settings:set ─────────────────────────────────────────────────────────────
  // Validates key, updates the row, and handles side-effects.
  // Requirement 18.1 (realtime_protection), 18.2 (auto_quarantine),
  // 18.3 (start_with_windows), 18.6 (telemetry_enabled).
  ipcMain.handle('settings:set', (_event, { key, value }) => {
    if (!KNOWN_SETTINGS_KEYS.includes(key)) {
      return { success: false, error: `Unknown settings key: ${key}` };
    }

    const db = getDb();
    setSetting(db, key, value);

    // Side-effect: start_with_windows service registration (Requirement 11.1, 11.2)
    if (key === 'start_with_windows') {
      if (value === '1') {
        registerWindowsService(db);
      } else if (value === '0') {
        unregisterWindowsService();
      }
    }

    return { success: true };
  });

  // ── settings:addPath ─────────────────────────────────────────────────────────
  // Appends a path to the monitored_paths JSON array (deduplicated).
  // Calls monitor.updatePaths() for hot-reload within 5 seconds.
  // Requirement 18.4, 10.7.
  ipcMain.handle('settings:addPath', (_event, { path: newPath }) => {
    const db = getDb();
    const raw = getSetting(db, 'monitored_paths') || '[]';
    let paths;
    try {
      paths = JSON.parse(raw);
      if (!Array.isArray(paths)) paths = [];
    } catch (_) {
      paths = [];
    }

    // Deduplicate — ignore if path already present (case-sensitive)
    if (!paths.includes(newPath)) {
      paths.push(newPath);
      setSetting(db, 'monitored_paths', JSON.stringify(paths));
    }

    // Hot-reload the watcher (Requirement 10.7 — within 5 seconds)
    const monitor = getMonitor ? getMonitor() : null;
    if (monitor && typeof monitor.updatePaths === 'function') {
      try {
        monitor.updatePaths(monitor, paths);
      } catch (err) {
        console.error('[settings-handlers] monitor.updatePaths failed:', err.message);
      }
    }

    return { success: true };
  });

  // ── settings:removePath ──────────────────────────────────────────────────────
  // Filters a path out of monitored_paths and hot-reloads the watcher.
  // Requirement 18.4, 10.7.
  ipcMain.handle('settings:removePath', (_event, { path: removePath }) => {
    const db = getDb();
    const raw = getSetting(db, 'monitored_paths') || '[]';
    let paths;
    try {
      paths = JSON.parse(raw);
      if (!Array.isArray(paths)) paths = [];
    } catch (_) {
      paths = [];
    }

    const filtered = paths.filter((p) => p !== removePath);
    setSetting(db, 'monitored_paths', JSON.stringify(filtered));

    // Hot-reload the watcher
    const monitor = getMonitor ? getMonitor() : null;
    if (monitor && typeof monitor.updatePaths === 'function') {
      try {
        monitor.updatePaths(monitor, filtered);
      } catch (err) {
        console.error('[settings-handlers] monitor.updatePaths failed:', err.message);
      }
    }

    return { success: true };
  });

  // ── settings:getDefinitionInfo ───────────────────────────────────────────────
  // Returns { version, lastUpdate } from the settings table.
  // Requirement 8.5, 18.5.
  ipcMain.handle('settings:getDefinitionInfo', () => {
    const db = getDb();
    const version = getSetting(db, 'definition_version') || '';
    const lastUpdate = getSetting(db, 'last_definition_update') || null;
    return { version, lastUpdate };
  });

  // ── definitions:update ───────────────────────────────────────────────────────
  // Invokes the FreshClam updater and streams progress events to the renderer
  // via push IPC (definitions:progress, definitions:complete, definitions:error).
  // Requirements 8.1, 8.2, 8.3, 8.4.
  ipcMain.handle('definitions:update', async () => {
    const win = getMainWindow();

    // Helper: send a push event only when the window is alive
    const push = (channel, payload) => {
      if (win && !win.isDestroyed()) {
        win.webContents.send(channel, payload);
      }
    };

    // Lazy-require the updater — it may not exist yet in dev environments
    let updater = null;
    try {
      updater = getUpdater ? getUpdater() : require('../../engine/updater');
    } catch (_) {
      // Updater module not available yet
    }

    if (!updater || typeof updater.updateDefinitions !== 'function') {
      push('definitions:error', { message: 'Definition updater not available.' });
      return { started: false };
    }

    // Run the update asynchronously; push events as they arrive
    (async () => {
      try {
        const result = await updater.updateDefinitions({
          onProgress: ({ status, percent }) => {
            push('definitions:progress', { status, percent });
          },
        });

        if (result && result.success) {
          // Persist the new version info
          try {
            const db = getDb();
            if (result.version) setSetting(db, 'definition_version', result.version);
            if (result.date) setSetting(db, 'last_definition_update', result.date);
          } catch (dbErr) {
            console.error('[settings-handlers] Failed to persist definition version:', dbErr.message);
          }
          push('definitions:complete', {
            version: result.version || '',
            date: result.date || new Date().toISOString(),
          });
        } else {
          push('definitions:error', {
            message: (result && result.error) ? result.error : 'Update failed.',
          });
        }
      } catch (err) {
        push('definitions:error', { message: err.message || 'Update failed.' });
      }
    })();

    // Return immediately — actual result arrives via push IPC
    return { started: true };
  });
}

module.exports = { register };
