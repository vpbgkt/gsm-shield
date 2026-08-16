'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

// ─── Global reference to prevent GC ───────────────────────────────────────────
let mainWindow = null;

// ─── Dev mode detection ────────────────────────────────────────────────────────
const isDev = process.env.NODE_ENV === 'development';

// ─── License state (global for access by IPC handlers and feature gates) ──────
let licenseState = {
  status: 'inactive',  // 'active' | 'grace' | 'inactive'
  expiresAt: null,
  storedAt: null,
  gates: {
    scanLimit: true,           // limit to 50 results / 1 folder when true
    whitelistCap: true,        // limit to 10 user entries when true
    realtimeDisabled: true     // disable real-time protection when true
  }
};

/**
 * Get the current license state (for use by IPC handlers)
 * @returns {Object} Current license state
 */
function getLicenseState() {
  return licenseState;
}

/**
 * Set the license state and notify renderer
 * @param {Object} newState - New license state
 */
function setLicenseState(newState) {
  licenseState = { ...licenseState, ...newState };
  
  // Push license:updated IPC to renderer
  if (mainWindow && mainWindow.webContents) {
    mainWindow.webContents.send('license:updated', {
      status: licenseState.status,
      gates: licenseState.gates
    });
  }
}

/**
 * Validate stored license and apply feature gates
 * 
 * Requirements 20.1, 20.2, 20.3, 20.5:
 * - On app:ready: call validateLicense(storedToken)
 * - If valid → status 'active', clear all feature gates
 * - If API unreachable AND storedAt < 7 days ago → status 'grace', allow full operation
 * - If absent/invalid/grace elapsed → status 'inactive', apply feature gates
 * - Emit license:updated push IPC to renderer whenever status changes
 * 
 * @returns {Promise<void>}
 */
async function validateStoredLicense() {
  try {
    const { loadLicense } = require('../license/license-store');
    const { validateLicense } = require('../license/keygen-client');
    const { getMachineFingerprint } = require('../license/machine-id');
    
    // Get machine fingerprint for loading encrypted license
    const fingerprint = await getMachineFingerprint();
    
    // Load stored license
    const stored = loadLicense(fingerprint);
    
    // If no stored license, apply inactive gates
    if (!stored || !stored.token) {
      console.log('[license] No stored license found — applying inactive gates');
      setLicenseState({
        status: 'inactive',
        expiresAt: null,
        storedAt: null,
        gates: {
          scanLimit: true,
          whitelistCap: true,
          realtimeDisabled: true
        }
      });
      return;
    }
    
    // Calculate grace period (7 days = 604800000 milliseconds)
    const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000;
    const storedAtTime = new Date(stored.storedAt).getTime();
    const now = Date.now();
    const isWithinGracePeriod = (now - storedAtTime) < GRACE_PERIOD_MS;
    
    // Validate token against Keygen.sh API
    const validationResult = await validateLicense(stored.token);
    
    // Check if API call succeeded (network reachable)
    if (!validationResult.success) {
      // API unreachable (network error)
      if (isWithinGracePeriod) {
        // Grace period: allow full operation
        console.log('[license] API unreachable, within grace period — status: grace');
        setLicenseState({
          status: 'grace',
          expiresAt: stored.expiresAt,
          storedAt: stored.storedAt,
          gates: {
            scanLimit: false,
            whitelistCap: false,
            realtimeDisabled: false
          }
        });
      } else {
        // Grace period elapsed
        console.log('[license] API unreachable, grace period elapsed — status: inactive');
        setLicenseState({
          status: 'inactive',
          expiresAt: null,
          storedAt: stored.storedAt,
          gates: {
            scanLimit: true,
            whitelistCap: true,
            realtimeDisabled: true
          }
        });
      }
      return;
    }
    
    // API call succeeded — check if license is valid
    if (validationResult.valid) {
      // License is valid — clear all feature gates
      console.log('[license] License valid — status: active');
      setLicenseState({
        status: 'active',
        expiresAt: validationResult.expiresAt || stored.expiresAt,
        storedAt: stored.storedAt,
        gates: {
          scanLimit: false,
          whitelistCap: false,
          realtimeDisabled: false
        }
      });
    } else {
      // License is invalid (expired, revoked, etc.)
      console.log('[license] License invalid — status: inactive');
      setLicenseState({
        status: 'inactive',
        expiresAt: null,
        storedAt: stored.storedAt,
        gates: {
          scanLimit: true,
          whitelistCap: true,
          realtimeDisabled: true
        }
      });
    }
    
  } catch (err) {
    // Any unexpected error: apply inactive gates as safety measure
    console.error('[license] License validation failed:', err);
    setLicenseState({
      status: 'inactive',
      expiresAt: null,
      storedAt: null,
      gates: {
        scanLimit: true,
        whitelistCap: true,
        realtimeDisabled: true
      }
    });
  }
}

// ─── Window factory ───────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    frame: false,
    titleBarStyle: 'hidden',
    backgroundColor: '#020617', // Tailwind slate-950
    show: false,                // avoid flash of unstyled content
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // Show window once it is ready to avoid white flash
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Requirement 12.1 — hide instead of quit on close
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  // Load renderer
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(
      path.join(__dirname, '..', 'renderer', 'dist', 'index.html')
    );
  }
}

// ─── Window-control IPC channels (Requirements 13.1, 13.2) ───────────────────
function registerWindowIpc() {
  ipcMain.handle('window:minimize', () => {
    if (mainWindow) mainWindow.minimize();
  });

  ipcMain.handle('window:maximize', () => {
    if (!mainWindow) return;
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  });

  ipcMain.handle('window:close', () => {
    if (mainWindow) mainWindow.hide();
  });
}

// ─── App lifecycle ─────────────────────────────────────────────────────────────
app.on('ready', async () => {
  createWindow();
  registerWindowIpc();

  // 1. Initialise database (implemented in task 2)
  try {
    const { initDatabase } = require('../database/init');
    await initDatabase();
  } catch (err) {
    console.error('[main] database/init failed:', err);
  }

  // 2. Register IPC handlers
  try {
    const { getDb } = require('../database');
    
    // Register whitelist handlers (task 3.5)
    const whitelistHandlers = require('./ipc/whitelist-handlers');
    whitelistHandlers.register(ipcMain, {
      getDb,
      getHasher: () => require('../whitelist/hasher'),
      getWhitelistDb: () => require('../whitelist/db'),
      getSync: () => require('../whitelist/sync'),
      getLicense: () => getLicenseState(),
    });

    // Register scan handlers
    const scanHandlers = require('./ipc/scan-handlers');
    scanHandlers.register(ipcMain, {
      getMainWindow: () => mainWindow,
      getDb,
    });

    // Register settings handlers (task 2.3)
    const settingsHandlers = require('./ipc/settings-handlers');
    settingsHandlers.register(ipcMain, {
      getDb,
      getMainWindow: () => mainWindow,
      getMonitor: () => null, // Implemented in task 7
      getUpdater: () => null, // Implemented in task 6
    });

    // Register quarantine handlers (task 5.2)
    const quarantineHandlers = require('./ipc/quarantine-handlers');
    quarantineHandlers.register(ipcMain, {
      getDb,
      getQuarantine: () => require('../engine/quarantine'),
    });

    // Register license handlers (task 8.5)
    const licenseHandlers = require('./ipc/license-handlers');
    licenseHandlers.register(ipcMain, {
      getMainWindow: () => mainWindow,
    });

    // Register first-run / Defender setup IPC handler (Requirements 21.1–21.4)
    // Wires up the defender:runSetup channel so Settings can re-trigger
    // Defender-disable + WSC-registration if it failed on first run.
    const firstRunModule = require('./first-run');
    firstRunModule.register(ipcMain, {
      getMainWindow: () => mainWindow,
    });
  } catch (err) {
    console.error('[main] IPC handler registration failed:', err);
  }

  // 3. Create system tray (implemented in task 7.2)
  try {
    const { createTray } = require('./tray-manager');
    createTray(mainWindow);
  } catch (err) {
    console.error('[main] tray-manager failed:', err);
  }

  // 3b. Warm up the ClamAV daemon in the background so scans are near-instant.
  // clamd loads the ~3.6M-signature database once (~14s) and stays resident;
  // subsequent scans via clamdscan return in milliseconds. Starting it here
  // (non-blocking) means it is typically ready by the time the user scans.
  try {
    const clamd = require('../engine/clamd-manager');
    clamd.start().then((ok) => {
      console.log('[main] clamd warm-up ' + (ok ? 'succeeded (scans will be fast)' : 'failed (falling back to clamscan)'));
    }).catch((err) => {
      console.error('[main] clamd warm-up error:', err.message);
    });
  } catch (err) {
    console.error('[main] clamd-manager load failed:', err.message);
  }

  // 4. Validate license and apply feature gates (implemented in task 8.4)
  await validateStoredLicense();

  // 5. First-run setup — disable Defender, register WSC (implemented in task 10)
  try {
    const { runFirstRunSetup, isFirstRun } = require('./first-run');
    if (await isFirstRun()) {
      await runFirstRunSetup(mainWindow);
    }
  } catch (err) {
    console.error('[main] first-run setup failed:', err);
  }

  // 6. Start real-time monitor if enabled and license allows (implemented in task 7)
  try {
    // Check if real-time protection is enabled in settings AND not disabled by feature gate
    const Database = require('better-sqlite3');
    const dbPath = require('path').join(
      app.getPath('appData'),
      'GSMShieldAV',
      'gsm-shield.db'
    );
    const db = new Database(dbPath);
    const row = db.prepare("SELECT value FROM settings WHERE key = 'realtime_protection'").get();
    db.close();

    // Only start monitor if setting is enabled AND license doesn't disable it
    if (row && row.value === '1' && !licenseState.gates.realtimeDisabled) {
      const { startMonitor } = require('../monitor/monitor');
      startMonitor([], {
        onThreat: (payload) => {
          if (mainWindow) {
            mainWindow.webContents.send('threat:detected', payload);
          }
        },
        onError: (err) => {
          console.error('[monitor] path error:', err);
          if (mainWindow) {
            mainWindow.webContents.send('monitor:path-error', { message: err.message });
          }
        },
      });
    } else if (licenseState.gates.realtimeDisabled) {
      console.log('[main] Real-time protection disabled by license feature gate');
    }
  } catch (err) {
    // Monitor or DB not yet implemented — non-fatal
    console.error('[main] monitor start failed:', err);
  }

  // 7. Schedule 24-hour whitelist cloud sync (implemented in task 11)
  try {
    const { scheduleSync } = require('../whitelist/sync');
    scheduleSync();
  } catch (err) {
    console.error('[main] whitelist sync schedule failed:', err);
  }
});

// Re-show window when app is activated (macOS convention — no-op on Windows
// but harmless to include for robustness)
app.on('activate', () => {
  if (mainWindow) {
    mainWindow.show();
  }
});

// Mark the app as intentionally quitting so the close handler does not
// swallow the exit (used by tray "Exit" menu item)
app.on('before-quit', () => {
  app.isQuitting = true;
  // Shut the ClamAV daemon down cleanly so it does not linger after exit.
  try {
    require('../engine/clamd-manager').stop();
  } catch (_) { /* ignore */ }
});

// On Windows/Linux, all windows closing should quit the app only when the
// tray manager explicitly calls app.quit() — otherwise the app hides.
app.on('window-all-closed', () => {
  // Do nothing: the tray keeps the process alive.
  // app.quit() is called explicitly from the tray "Exit" item.
});

// ─── Exports (for use by IPC handlers) ───────────────────────────────────────
module.exports = {
  getLicenseState,
  setLicenseState,
  validateStoredLicense
};
