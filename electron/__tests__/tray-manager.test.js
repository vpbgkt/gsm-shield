'use strict';

/**
 * Unit tests for electron/tray-manager.js
 *
 * Requirements: 12.2, 12.3, 12.4, 12.5, 12.6
 *
 * Strategy: mock the entire 'electron' module so these tests run in Node.js
 * without a real Electron environment. We capture calls made to the Tray /
 * Menu / nativeImage stubs to verify state-machine and menu behaviour.
 */

const path = require('path');

// ─── Mocks ────────────────────────────────────────────────────────────────────

// Capture click handlers registered on the tray so we can invoke them in tests
let trayClickHandler = null;

// Track setImage calls
const mockSetImage = jest.fn();
const mockSetToolTip = jest.fn();
const mockSetContextMenu = jest.fn();
const mockTrayOn = jest.fn((event, handler) => {
  if (event === 'click') trayClickHandler = handler;
});

// Tray constructor mock
const MockTray = jest.fn(function (icon) {
  this._icon = icon;
  this.setImage = mockSetImage;
  this.setToolTip = mockSetToolTip;
  this.setContextMenu = mockSetContextMenu;
  this.on = mockTrayOn;
});

// nativeImage mock — track which path was loaded
const mockCreateFromPath = jest.fn((p) => ({ _path: p, isEmpty: () => false }));
const mockCreateEmpty = jest.fn(() => ({ _path: null, isEmpty: () => true }));

// Menu mock — captures template and returns a stub
let capturedMenuTemplate = null;
const mockBuildFromTemplate = jest.fn((template) => {
  capturedMenuTemplate = template;
  return { _template: template };
});

// app mock
const mockQuit = jest.fn();
const mockApp = { quit: mockQuit };

// BrowserWindow stub
function makeMockWindow() {
  return {
    show: jest.fn(),
    focus: jest.fn(),
    restore: jest.fn(),
    isMinimized: jest.fn(() => false),
    isDestroyed: jest.fn(() => false),
    webContents: { send: jest.fn() },
  };
}

jest.mock('electron', () => ({
  app: mockApp,
  Tray: MockTray,
  Menu: { buildFromTemplate: mockBuildFromTemplate },
  nativeImage: {
    createFromPath: mockCreateFromPath,
    createEmpty: mockCreateEmpty,
  },
}));

// ─── Module under test ────────────────────────────────────────────────────────

// We need a fresh module for each test group that verifies internal state
let trayManager;

beforeEach(() => {
  jest.resetModules();
  // Re-register mocks after module reset
  jest.mock('electron', () => ({
    app: mockApp,
    Tray: MockTray,
    Menu: { buildFromTemplate: mockBuildFromTemplate },
    nativeImage: {
      createFromPath: mockCreateFromPath,
      createEmpty: mockCreateEmpty,
    },
  }));

  // Reset all mock call history
  MockTray.mockClear();
  mockSetImage.mockClear();
  mockSetToolTip.mockClear();
  mockSetContextMenu.mockClear();
  mockTrayOn.mockClear();
  mockCreateFromPath.mockClear();
  mockCreateEmpty.mockClear();
  mockBuildFromTemplate.mockClear();
  mockQuit.mockClear();
  capturedMenuTemplate = null;
  trayClickHandler = null;

  trayManager = require(path.resolve(__dirname, '../tray-manager'));
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('tray-manager icon paths', () => {
  test('ICON_PATHS has entries for all three states', () => {
    const { _ICON_PATHS } = trayManager;
    expect(_ICON_PATHS).toHaveProperty('protected');
    expect(_ICON_PATHS).toHaveProperty('threat');
    expect(_ICON_PATHS).toHaveProperty('off');
  });

  test('protected state maps to tray-green.ico', () => {
    expect(trayManager._ICON_PATHS.protected).toMatch(/tray-green\.ico$/);
  });

  test('threat state maps to tray-red.ico', () => {
    expect(trayManager._ICON_PATHS.threat).toMatch(/tray-red\.ico$/);
  });

  test('off state maps to tray-gray.ico', () => {
    expect(trayManager._ICON_PATHS.off).toMatch(/tray-gray\.ico$/);
  });
});

describe('createTray()', () => {
  test('creates a Tray instance with the green icon on first call', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);

    expect(MockTray).toHaveBeenCalledTimes(1);
    expect(mockCreateFromPath).toHaveBeenCalledWith(
      expect.stringMatching(/tray-green\.ico$/)
    );
  });

  test('sets tooltip to "GSM Shield AV"', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    expect(mockSetToolTip).toHaveBeenCalledWith('GSM Shield AV');
  });

  test('sets a context menu immediately', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    expect(mockSetContextMenu).toHaveBeenCalledTimes(1);
  });

  test('returns the Tray instance', () => {
    const win = makeMockWindow();
    const result = trayManager.createTray(win);
    expect(result).toBeDefined();
    expect(result.setImage).toBe(mockSetImage);
  });

  test('registers a click listener on the tray', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    expect(mockTrayOn).toHaveBeenCalledWith('click', expect.any(Function));
  });

  test('clicking the tray icon shows and focuses the window', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    // trayClickHandler captured by mockTrayOn above
    trayClickHandler();
    expect(win.show).toHaveBeenCalled();
    expect(win.focus).toHaveBeenCalled();
  });
});

describe('context menu — structure (Requirement 12.3)', () => {
  test('menu has exactly 3 items', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    expect(capturedMenuTemplate).toHaveLength(3);
  });

  test('first item is "Open"', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    expect(capturedMenuTemplate[0].label).toBe('Open');
  });

  test('second item is "Quick Scan"', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    expect(capturedMenuTemplate[1].label).toBe('Quick Scan');
  });

  test('third item is "Exit"', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    expect(capturedMenuTemplate[2].label).toBe('Exit');
  });
});

describe('context menu — "Open" action', () => {
  test('"Open" click shows the main window', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    capturedMenuTemplate[0].click();
    expect(win.show).toHaveBeenCalled();
  });

  test('"Open" click focuses the main window', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    capturedMenuTemplate[0].click();
    expect(win.focus).toHaveBeenCalled();
  });

  test('"Open" click restores minimised window', () => {
    const win = makeMockWindow();
    win.isMinimized.mockReturnValue(true);
    trayManager.createTray(win);
    capturedMenuTemplate[0].click();
    expect(win.restore).toHaveBeenCalled();
  });
});

describe('context menu — "Quick Scan" action (Requirement 12.5)', () => {
  test('"Quick Scan" click shows the main window', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    capturedMenuTemplate[1].click();
    expect(win.show).toHaveBeenCalled();
  });

  test('"Quick Scan" sends scan:start with mode quick', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    capturedMenuTemplate[1].click();
    expect(win.webContents.send).toHaveBeenCalledWith('scan:start', { mode: 'quick' });
  });
});

describe('context menu — "Exit" action (Requirement 12.4)', () => {
  test('"Exit" click calls app.quit()', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    capturedMenuTemplate[2].click();
    expect(mockQuit).toHaveBeenCalledTimes(1);
  });
});

describe('setState() — state machine (Requirement 12.2)', () => {
  test('default state is "protected" before createTray()', () => {
    expect(trayManager._getState()).toBe('protected');
  });

  test('setState("threat") switches icon to tray-red.ico', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    mockSetImage.mockClear();
    mockCreateFromPath.mockClear();

    trayManager.setState('threat');

    expect(mockCreateFromPath).toHaveBeenCalledWith(
      expect.stringMatching(/tray-red\.ico$/)
    );
    expect(mockSetImage).toHaveBeenCalledTimes(1);
  });

  test('setState("off") switches icon to tray-gray.ico', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    mockSetImage.mockClear();
    mockCreateFromPath.mockClear();

    trayManager.setState('off');

    expect(mockCreateFromPath).toHaveBeenCalledWith(
      expect.stringMatching(/tray-gray\.ico$/)
    );
    expect(mockSetImage).toHaveBeenCalledTimes(1);
  });

  test('setState("protected") switches icon to tray-green.ico', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    trayManager.setState('threat');
    mockSetImage.mockClear();
    mockCreateFromPath.mockClear();

    trayManager.setState('protected');

    expect(mockCreateFromPath).toHaveBeenCalledWith(
      expect.stringMatching(/tray-green\.ico$/)
    );
    expect(mockSetImage).toHaveBeenCalledTimes(1);
  });

  test('setState() updates internal currentState', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);

    trayManager.setState('threat');
    expect(trayManager._getState()).toBe('threat');

    trayManager.setState('off');
    expect(trayManager._getState()).toBe('off');

    trayManager.setState('protected');
    expect(trayManager._getState()).toBe('protected');
  });

  test('setState() before createTray() does not throw (graceful no-op)', () => {
    // No createTray() called — tray is null
    expect(() => trayManager.setState('off')).not.toThrow();
    expect(trayManager._getState()).toBe('off');
    // setImage should NOT be called since tray doesn't exist yet
    expect(mockSetImage).not.toHaveBeenCalled();
  });

  test('setState() with unknown state is ignored', () => {
    const win = makeMockWindow();
    trayManager.createTray(win);
    mockSetImage.mockClear();

    expect(() => trayManager.setState('unknown')).not.toThrow();
    expect(mockSetImage).not.toHaveBeenCalled();
  });
});

describe('setMainWindow()', () => {
  test('setMainWindow() updates the window reference', () => {
    const win1 = makeMockWindow();
    const win2 = makeMockWindow();
    trayManager.createTray(win1);

    mockSetContextMenu.mockClear();
    trayManager.setMainWindow(win2);

    // After update, "Open" click should use the new window
    capturedMenuTemplate[0].click();
    expect(win2.show).toHaveBeenCalled();
    expect(win1.show).not.toHaveBeenCalled();
  });

  test('setMainWindow() rebuilds the context menu', () => {
    const win1 = makeMockWindow();
    const win2 = makeMockWindow();
    trayManager.createTray(win1);
    mockSetContextMenu.mockClear();

    trayManager.setMainWindow(win2);

    // Menu should be rebuilt so closures reference the new window
    expect(mockSetContextMenu).toHaveBeenCalledTimes(1);
  });
});
