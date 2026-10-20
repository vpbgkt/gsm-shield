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
    const pathsRaw = getSetting(db, 'monitored_paths') || '[]';
    let monitoredPaths = [];
    try {
      monitoredPaths = JSON.parse(pathsRaw);
    } catch (_) {}
    if (!Array.isArray(monitoredPaths) || monitoredPaths.length === 0) {
      const monitorModule = require('../../monitor/monitor');
      monitoredPaths = monitorModule.getDefaultMonitoredPaths();
    }

    const config = {
      watchPaths: monitoredPaths,
      monitoredPaths,
      realtimeProtection: true,
      registeredAt: new Date().toISOString(),
    };
    
    const appDataDir = resolveAppDataDir();
    const programDataDir = path.join(process.env.ProgramData || 'C:\\ProgramData', 'GSMShieldAV');
    
    // Ensure directory exists (with better error handling)
    try {
      if (!fs.existsSync(appDataDir)) {
        fs.mkdirSync(appDataDir, { recursive: true });
      }
      if (!fs.existsSync(programDataDir)) {
        fs.mkdirSync(programDataDir, { recursive: true });
      }
    } catch (mkdirErr) {
      console.error('[settings-handlers] Failed to create AppData/ProgramData directory:', mkdirErr);
    }
    
    fs.writeFileSync(serviceConfigPath(), JSON.stringify(config, null, 2), 'utf8');
    try {
      fs.writeFileSync(path.join(programDataDir, 'service-config.json'), JSON.stringify(config, null, 2), 'utf8');
    } catch (_) {}

    // Lazy require — node-windows may not be installed in dev environment
    let NodeWindows;
    try {
      NodeWindows = require('node-windows'); // eslint-disable-line
    } catch (requireErr) {
      console.warn('[settings-handlers] node-windows not available:', requireErr.message);
      console.warn('[settings-handlers] Start-with-Windows feature disabled');
      return;
    }
    
    const Service = NodeWindows.Service;
    
    // Determine script path - must handle .asar packaging
    let scriptPath = path.join(__dirname, '..', '..', 'monitor', 'service-wrapper.js');
    
    // When running from .asar, extract service-wrapper.js to AppData
    if (scriptPath.includes('.asar')) {
      const extractedScriptPath = path.join(appDataDir, 'service-wrapper.js');
      
      // Copy service-wrapper.js from asar to real file system
      try {
        const scriptContent = fs.readFileSync(scriptPath, 'utf8');
        fs.writeFileSync(extractedScriptPath, scriptContent, 'utf8');
        scriptPath = extractedScriptPath;
        console.log('[settings-handlers] Extracted service script to:', scriptPath);
      } catch (extractErr) {
        console.error('[settings-handlers] Failed to extract service script:', extractErr);
        throw new Error(`Cannot extract service script: ${extractErr.message}`);
      }
    }

    const svc = new Service({
      name: 'GSM Shield AV Monitor',
      description: 'GSM Shield AV real-time file-system protection service',
      script: scriptPath,
    });

    svc.on('install', () => {
      console.log('[settings-handlers] Windows service installed successfully');
      svc.start();
    });
    
    svc.on('error', (err) => {
      console.error('[settings-handlers] Windows service error:', err);
    });

    svc.install();
  } catch (err) {
    console.error('[settings-handlers] Failed to register Windows service:', err.message);
    console.error('[settings-handlers] Full error:', err);
    throw err; // Re-throw so the outer try/catch in settings:set can handle it
  }
}

/**
 * Unregister (uninstall) the node-windows service.
 * Wrapped in try/catch because node-windows may not be installed.
 */
function unregisterWindowsService() {
  try {
    let NodeWindows;
    try {
      NodeWindows = require('node-windows'); // eslint-disable-line
    } catch (requireErr) {
      console.warn('[settings-handlers] node-windows not available:', requireErr.message);
      return;
    }
    
    const Service = NodeWindows.Service;
    
    // Use the same script path logic as register
    let scriptPath = path.join(__dirname, '..', '..', 'monitor', 'service-wrapper.js');
    
    // When running from .asar, use the extracted version
    if (scriptPath.includes('.asar')) {
      scriptPath = path.join(resolveAppDataDir(), 'service-wrapper.js');
    }

    const svc = new Service({
      name: 'GSM Shield AV Monitor',
      script: scriptPath,
    });

    svc.on('uninstall', () => {
      console.log('[settings-handlers] Windows service uninstalled.');
    });
    
    svc.on('error', (err) => {
      console.error('[settings-handlers] Windows service uninstall error:', err);
    });

    svc.uninstall();
  } catch (err) {
    console.error('[settings-handlers] Failed to unregister Windows service:', err.message);
    throw err; // Re-throw so the outer try/catch can handle it
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
  ipcMain.handle('settings:set', async (_event, { key, value }) => {
    if (!KNOWN_SETTINGS_KEYS.includes(key)) {
      return { success: false, error: `Unknown settings key: ${key}` };
    }

    const db = getDb();
    setSetting(db, key, value);

    // Side-effect: start_with_windows service registration (Requirement 11.1, 11.2)
    if (key === 'start_with_windows') {
      try {
        if (value === '1') {
          registerWindowsService(db);
        } else if (value === '0') {
          unregisterWindowsService();
        }
      } catch (serviceErr) {
        console.error('[settings:set] Windows service operation failed:', serviceErr);
        // Don't fail the entire settings update - just log the error
        // The setting will still be saved but service won't be registered
      }
    }

    // Side-effect: realtime_protection toggle (start/stop monitor)
    if (key === 'realtime_protection') {
      const monitor = getMonitor ? getMonitor() : null;
      const monitorModule = require('../../monitor/monitor');
      
      if (value === '1') {
        // Starting real-time protection
        if (!monitor) {
          // Get monitored paths from settings
          const pathsRaw = getSetting(db, 'monitored_paths') || '[]';
          let monitoredPaths = [];
          try {
            monitoredPaths = JSON.parse(pathsRaw);
            if (!Array.isArray(monitoredPaths)) monitoredPaths = [];
          } catch (_) {
            monitoredPaths = [];
          }
          if (monitoredPaths.length === 0) {
            monitoredPaths = monitorModule.getDefaultMonitoredPaths();
          }
          
          // Start the monitor
          const win = getMainWindow();
          monitorModule.setMainWindow(win);
          
          const newMonitor = monitorModule.startMonitor(monitoredPaths, {
            onThreat: (payload) => {
              if (win) {
                win.webContents.send('threat:detected', payload);
              }
            },
            onError: (err) => {
              console.error('[monitor] path error:', err);
              if (win) {
                win.webContents.send('monitor:path-error', { 
                  path: err.path,
                  message: err.error ? err.error.message : 'Unknown error' 
                });
              }
            },
          });
          
          // Note: We can't update the getMonitor closure from here,
          // but the monitor will be running. A full app restart is
          // recommended for complete integration.
          console.log(`[settings] Real-time monitor started with ${monitoredPaths.length} path(s)`);
        }
      } else if (value === '0') {
        // Stopping real-time protection
        if (monitor) {
          monitorModule.stopMonitor(monitor);
          console.log('[settings] Real-time monitor stopped');
        }
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
