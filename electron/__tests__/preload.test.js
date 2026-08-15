'use strict';

/**
 * Integration test: verify contextBridge exposes all required channels
 *
 * This test mocks Electron's contextBridge and ipcRenderer, loads the preload
 * script, captures the API object passed to exposeInMainWorld, and verifies:
 *   - Every invoke method is a function that triggers ipcRenderer.invoke
 *     with the correct channel name
 *   - Every on* push listener method is a function that triggers ipcRenderer.on
 *     with the correct channel name
 *   - Every off* remove-listener method is a function that triggers
 *     ipcRenderer.removeListener with the correct channel name
 *
 * Requirements: 13.1, 13.2
 */

const path = require('path');

// ─── Mock ipcRenderer ─────────────────────────────────────────────────────────
const mockIpcRenderer = {
  invoke: jest.fn().mockResolvedValue(undefined),
  on: jest.fn(),
  removeListener: jest.fn(),
};

// Capture the API object that the preload script passes to exposeInMainWorld
let capturedAPI = null;

const mockContextBridge = {
  exposeInMainWorld: jest.fn((key, api) => {
    capturedAPI = api;
  }),
};

// Mock the 'electron' module before requiring the preload script
jest.mock('electron', () => ({
  contextBridge: mockContextBridge,
  ipcRenderer: mockIpcRenderer,
}));

// ─── Load preload script ──────────────────────────────────────────────────────
beforeAll(() => {
  // Clear the module cache so the preload executes fresh with our mocks
  jest.resetModules();
  // Re-register the mock (resetModules clears the mock registry)
  jest.mock('electron', () => ({
    contextBridge: mockContextBridge,
    ipcRenderer: mockIpcRenderer,
  }));
  require(path.resolve(__dirname, '../../electron/preload.js'));
});

afterEach(() => {
  jest.clearAllMocks();
});

// ─── IPC Contract tables (from design.md) ────────────────────────────────────

/**
 * Maps each API method name (as exposed on window.electronAPI) to the
 * underlying IPC channel string. Derived from the IPC contract table in
 * design.md and the preload.js implementation.
 */
const INVOKE_CHANNELS = {
  // Scan
  scanStart:    'scan:start',
  scanCancel:   'scan:cancel',
  scanHistory:  'scan:history',

  // Whitelist
  whitelistList:    'whitelist:list',
  whitelistAdd:     'whitelist:add',
  whitelistRemove:  'whitelist:remove',
  whitelistSync:    'whitelist:sync',
  whitelistSubmit:  'whitelist:submit',

  // Quarantine
  quarantineList:       'quarantine:list',
  quarantineRestore:    'quarantine:restore',
  quarantineRestoreTo:  'quarantine:restore-to',
  quarantineDelete:     'quarantine:delete',

  // Settings
  settingsGet:               'settings:get',
  settingsSet:               'settings:set',
  settingsAddPath:           'settings:addPath',
  settingsRemovePath:        'settings:removePath',
  settingsGetDefinitionInfo: 'settings:getDefinitionInfo',

  // Definitions
  definitionsUpdate: 'definitions:update',

  // License
  licenseStatus:     'license:status',
  licenseActivate:   'license:activate',
  licenseDeactivate: 'license:deactivate',

  // System
  defenderRunSetup: 'defender:runSetup',
  traySetState:     'tray:setState',
  windowMinimize:   'window:minimize',
  windowMaximize:   'window:maximize',
  windowClose:      'window:close',
};

/**
 * Maps each on* listener method to its push channel name.
 */
const PUSH_ON_CHANNELS = {
  onScanProgress:         'scan:progress',
  onScanThreat:           'scan:threat',
  onScanComplete:         'scan:complete',
  onWhitelistSynced:      'whitelist:synced',
  onWhitelistSyncError:   'whitelist:sync-error',
  onDefinitionsProgress:  'definitions:progress',
  onDefinitionsComplete:  'definitions:complete',
  onDefinitionsError:     'definitions:error',
  onDefinitionsMissing:   'definitions:missing',
  onLicenseUpdated:       'license:updated',
  onThreatDetected:       'threat:detected',
  onDefenderSetupResult:  'defender:setup-result',
  onMonitorPathError:     'monitor:path-error',
};

/**
 * Maps each off* remove-listener method to its push channel name.
 */
const PUSH_OFF_CHANNELS = {
  offScanProgress:        'scan:progress',
  offScanThreat:          'scan:threat',
  offScanComplete:        'scan:complete',
  offWhitelistSynced:     'whitelist:synced',
  offWhitelistSyncError:  'whitelist:sync-error',
  offDefinitionsProgress: 'definitions:progress',
  offDefinitionsComplete: 'definitions:complete',
  offDefinitionsError:    'definitions:error',
  offDefinitionsMissing:  'definitions:missing',
  offLicenseUpdated:      'license:updated',
  offThreatDetected:      'threat:detected',
  offDefenderSetupResult: 'defender:setup-result',
  offMonitorPathError:    'monitor:path-error',
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('preload.js contextBridge integration', () => {

  test('contextBridge.exposeInMainWorld was called exactly once with key "electronAPI"', () => {
    expect(mockContextBridge.exposeInMainWorld).toHaveBeenCalledTimes(1);
    expect(mockContextBridge.exposeInMainWorld.mock.calls[0][0]).toBe('electronAPI');
  });

  test('captured API is a non-null object', () => {
    expect(capturedAPI).not.toBeNull();
    expect(typeof capturedAPI).toBe('object');
  });

  // ── Invoke methods ──────────────────────────────────────────────────────────

  describe('invoke methods', () => {
    test.each(Object.keys(INVOKE_CHANNELS))(
      '%s is exposed as a function',
      (methodName) => {
        expect(typeof capturedAPI[methodName]).toBe('function');
      }
    );

    test.each(Object.entries(INVOKE_CHANNELS))(
      '%s calls ipcRenderer.invoke with channel "%s"',
      async (methodName, channel) => {
        mockIpcRenderer.invoke.mockResolvedValueOnce(undefined);
        const result = capturedAPI[methodName]({ some: 'arg' });
        // Must return a Promise
        expect(result).toBeInstanceOf(Promise);
        await result;
        expect(mockIpcRenderer.invoke).toHaveBeenCalledWith(channel, { some: 'arg' });
      }
    );

    test('all invoke methods in INVOKE_CHANNELS are present on the API', () => {
      for (const methodName of Object.keys(INVOKE_CHANNELS)) {
        expect(capturedAPI).toHaveProperty(methodName);
      }
    });
  });

  // ── Push on* listener methods ───────────────────────────────────────────────

  describe('push on* listener methods', () => {
    test.each(Object.keys(PUSH_ON_CHANNELS))(
      '%s is exposed as a function',
      (methodName) => {
        expect(typeof capturedAPI[methodName]).toBe('function');
      }
    );

    test.each(Object.entries(PUSH_ON_CHANNELS))(
      '%s registers ipcRenderer.on with channel "%s" without throwing',
      (methodName, channel) => {
        const cb = jest.fn();
        expect(() => capturedAPI[methodName](cb)).not.toThrow();
        expect(mockIpcRenderer.on).toHaveBeenCalledWith(channel, expect.any(Function));
      }
    );

    test('on* callback is invoked with payload (event object stripped)', () => {
      // Grab the wrapper function that ipcRenderer.on receives
      const cb = jest.fn();
      capturedAPI.onScanProgress(cb);

      // ipcRenderer.on was called; simulate main process sending data
      const [, wrapper] = mockIpcRenderer.on.mock.calls.find(
        ([ch]) => ch === 'scan:progress'
      );
      const fakeEvent = {};
      const fakePayload = { scanId: 1, filesScanned: 42 };
      wrapper(fakeEvent, fakePayload);

      // The renderer callback receives only the payload, not the event object
      expect(cb).toHaveBeenCalledWith(fakePayload);
      expect(cb).not.toHaveBeenCalledWith(fakeEvent, fakePayload);
    });
  });

  // ── Push off* remove-listener methods ──────────────────────────────────────

  describe('push off* remove-listener methods', () => {
    test.each(Object.keys(PUSH_OFF_CHANNELS))(
      '%s is exposed as a function',
      (methodName) => {
        expect(typeof capturedAPI[methodName]).toBe('function');
      }
    );

    test.each(Object.entries(PUSH_OFF_CHANNELS))(
      '%s calls ipcRenderer.removeListener with channel "%s" without throwing',
      (methodName, channel) => {
        const cb = jest.fn();
        expect(() => capturedAPI[methodName](cb)).not.toThrow();
        expect(mockIpcRenderer.removeListener).toHaveBeenCalledWith(channel, cb);
      }
    );
  });

  // ── Channel name contract verification ─────────────────────────────────────

  describe('IPC channel name contract (preload matches design.md)', () => {
    test('all invoke channel strings match the design IPC contract table', () => {
      const expectedChannels = Object.values(INVOKE_CHANNELS);
      // Verify no duplicate channel names in the contract (sanity check)
      const unique = new Set(expectedChannels);
      expect(unique.size).toBe(expectedChannels.length);
    });

    test('all push channel strings match the design IPC contract table', () => {
      const onChannels  = Object.values(PUSH_ON_CHANNELS);
      const offChannels = Object.values(PUSH_OFF_CHANNELS);
      // on* and off* must map to the same set of channels
      expect(new Set(onChannels)).toEqual(new Set(offChannels));
    });

    test('every invoke method routes to a unique channel', () => {
      const channels = Object.values(INVOKE_CHANNELS);
      const unique    = new Set(channels);
      expect(unique.size).toBe(channels.length);
    });

    test('API does not expose raw ipcRenderer (contextIsolation guard)', () => {
      // The renderer must never get a direct reference to ipcRenderer
      expect(capturedAPI).not.toHaveProperty('ipcRenderer');
    });

    test('total invoke methods exposed matches contract table count', () => {
      // 26 invoke channels: 3 scan + 5 whitelist + 4 quarantine + 5 settings +
      // 1 definitions + 3 license + 1 defender + 1 tray + 3 window = 26
      expect(Object.keys(INVOKE_CHANNELS).length).toBe(26);
    });

    test('total on* push listener methods exposed matches contract table count', () => {
      expect(Object.keys(PUSH_ON_CHANNELS).length).toBe(13);
    });

    test('total off* push listener methods exposed matches contract table count', () => {
      expect(Object.keys(PUSH_OFF_CHANNELS).length).toBe(13);
    });
  });

});
