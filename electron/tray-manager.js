'use strict';

/**
 * electron/tray-manager.js
 *
 * Manages a system-tray `Tray` instance for GSM Shield AV.
 *
 * State machine
 * ─────────────
 *   'protected'  →  green icon   (real-time protection active, no threats)
 *   'threat'     →  red icon     (threat detected or quarantine action needed)
 *   'off'        →  gray icon    (monitor disabled or license inactive)
 *
 * Public API
 * ──────────
 *   createTray(mainWindow)   – create Tray, build context menu, return Tray instance
 *   setState(state)          – switch tray icon; safe to call before createTray()
 *   setMainWindow(win)       – late-bind a new BrowserWindow reference
 *
 * Requirements: 12.2, 12.3, 12.4, 12.5, 12.6
 */

const path = require('path');
const { app, Tray, Menu, nativeImage } = require('electron');

// ─── Icon paths ───────────────────────────────────────────────────────────────

const ICONS_DIR = path.join(__dirname, '..', 'assets', 'icons');

const ICON_PATHS = {
  protected: path.join(ICONS_DIR, 'tray-green.ico'),
  threat:    path.join(ICONS_DIR, 'tray-red.ico'),
  off:       path.join(ICONS_DIR, 'tray-gray.ico'),
};

// ─── Module-level state ───────────────────────────────────────────────────────

/** @type {Tray | null} */
let tray = null;

/** @type {Electron.BrowserWindow | null} */
let mainWindow = null;

/** @type {'protected' | 'threat' | 'off'} */
let currentState = 'protected';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Load a nativeImage from path; falls back to an empty image on error so
 * the tray never crashes if an icon file is missing in dev/test environments.
 *
 * @param {string} iconPath
 * @returns {Electron.NativeImage}
 */
function loadIcon(iconPath) {
  try {
    const img = nativeImage.createFromPath(iconPath);
    // nativeImage.createFromPath returns an empty image (not null) for missing
    // files — log a warning so developers notice missing assets.
    if (img.isEmpty()) {
      console.warn(`[tray-manager] Icon is empty (file may be missing): ${iconPath}`);
    }
    return img;
  } catch (err) {
    console.error(`[tray-manager] Failed to load icon "${iconPath}":`, err.message);
    return nativeImage.createEmpty();
  }
}

/**
 * Build and set the tray context menu.
 * Called on creation and can be refreshed at any time.
 *
 * Context menu items (exactly 3, per Requirement 12.3):
 *   1. "Open"       – show the main window
 *   2. "Quick Scan" – show window + send scan:start quick
 *   3. "Exit"       – app.quit()
 */
function buildContextMenu() {
  const menu = Menu.buildFromTemplate([
    {
      label: 'Open',
      click() {
        if (mainWindow) {
          mainWindow.show();
          if (mainWindow.isMinimized()) mainWindow.restore();
          mainWindow.focus();
        }
      },
    },
    {
      label: 'Quick Scan',
      click() {
        if (mainWindow) {
          mainWindow.show();
          if (mainWindow.isMinimized()) mainWindow.restore();
          mainWindow.focus();
          // Requirement 12.5 — navigate to scanner and start a quick scan
          mainWindow.webContents.send('scan:start', { mode: 'quick' });
        }
      },
    },
    {
      label: 'Exit',
      click() {
        // Requirement 12.4 — terminate the Electron process
        app.quit();
      },
    },
  ]);

  return menu;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Create and initialise the system tray icon.
 *
 * @param {Electron.BrowserWindow} win – The application's main BrowserWindow.
 * @returns {Tray} The created Tray instance.
 */
function createTray(win) {
  mainWindow = win;

  const initialIcon = loadIcon(ICON_PATHS[currentState]);
  tray = new Tray(initialIcon);

  tray.setToolTip('GSM Shield AV');
  tray.setContextMenu(buildContextMenu());

  // Clicking the tray icon (left-click on Windows) shows the window
  tray.on('click', () => {
    if (mainWindow) {
      mainWindow.show();
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  return tray;
}

/**
 * Update the tray icon to reflect the given protection state.
 *
 * Safe to call before `createTray()` — logs a warning and returns without
 * crashing so that monitor/scanner/license modules can call this freely
 * during app startup.
 *
 * @param {'protected' | 'threat' | 'off'} state
 */
function setState(state) {
  const validStates = ['protected', 'threat', 'off'];

  if (!validStates.includes(state)) {
    console.warn(`[tray-manager] setState() called with unknown state: "${state}"`);
    return;
  }

  currentState = state;

  if (!tray) {
    console.warn(`[tray-manager] setState("${state}") called before createTray() — icon update deferred`);
    return;
  }

  const iconPath = ICON_PATHS[state];
  tray.setImage(loadIcon(iconPath));
}

/**
 * Late-bind (or replace) the BrowserWindow reference used by context-menu
 * actions. Useful when the window is recreated after the tray is initialised.
 *
 * @param {Electron.BrowserWindow} win
 */
function setMainWindow(win) {
  mainWindow = win;
  // Rebuild context menu so closures capture the new window reference
  if (tray) {
    tray.setContextMenu(buildContextMenu());
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  createTray,
  setState,
  setMainWindow,
  // Exposed for unit testing
  _getState: () => currentState,
  _getTray:  () => tray,
  _ICON_PATHS: ICON_PATHS,
};
