'use strict';

/**
 * electron/ipc/__tests__/settings-handlers.test.js
 *
 * Unit tests for settings IPC handlers:
 *   - settings:get
 *   - settings:set  (including start_with_windows service wiring)
 *   - settings:addPath
 *   - settings:removePath
 *   - settings:getDefinitionInfo
 *
 * Requirements: 11.1, 11.2, 18.1, 18.2, 18.3, 18.4, 18.5, 18.6
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// ─── Mock node-windows before requiring the handler ───────────────────────────
// We mock it at module level so that `require('node-windows')` inside
// registerWindowsService / unregisterWindowsService returns our mock.

const mockSvcInstall = jest.fn();
const mockSvcUninstall = jest.fn();
const mockSvcStart = jest.fn();
const mockSvcOn = jest.fn();

const MockService = jest.fn().mockImplementation(() => ({
  on: mockSvcOn,
  install: mockSvcInstall,
  uninstall: mockSvcUninstall,
  start: mockSvcStart,
}));

jest.mock('node-windows', () => ({ Service: MockService }), { virtual: true });

// ─── Mock electron (app.getPath) ──────────────────────────────────────────────
// The factory cannot reference out-of-scope variables, so we use process.env
// to resolve the temp directory at call time rather than at mock-definition time.
jest.mock('electron', () => ({
  app: {
    getPath: jest.fn((name) => {
      if (name === 'appData') return require('os').tmpdir();
      return require('os').tmpdir();
    }),
  },
}), { virtual: true });

const { register } = require('../settings-handlers');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildIpcMain() {
  const handlers = new Map();
  return {
    handle: jest.fn((channel, fn) => handlers.set(channel, fn)),
    _handlers: handlers,
  };
}

function buildDb(settingsMap = {}) {
  const store = { ...settingsMap };

  return {
    prepare: jest.fn((sql) => {
      if (/SELECT key, value FROM settings/.test(sql)) {
        return {
          all: jest.fn(() =>
            Object.entries(store).map(([key, value]) => ({ key, value }))
          ),
        };
      }
      if (/SELECT value FROM settings WHERE key/.test(sql)) {
        return {
          get: jest.fn((key) =>
            store[key] !== undefined ? { value: store[key] } : undefined
          ),
        };
      }
      if (/UPDATE settings SET value/.test(sql)) {
        return {
          run: jest.fn((value, key) => {
            store[key] = value;
          }),
        };
      }
      return { all: jest.fn(() => []), get: jest.fn(() => undefined), run: jest.fn() };
    }),
    _store: store,
  };
}

async function invoke(ipcMain, channel, args = {}) {
  const handler = ipcMain._handlers.get(channel);
  if (!handler) throw new Error(`Handler not registered: ${channel}`);
  return handler({}, args);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Settings IPC Handlers', () => {
  let ipcMain;
  let db;
  let getMainWindow;

  beforeEach(() => {
    jest.clearAllMocks();

    ipcMain = buildIpcMain();
    db = buildDb({
      realtime_protection: '1',
      auto_quarantine: '1',
      start_with_windows: '0',
      telemetry_enabled: '1',
      monitored_paths: '[]',
      definition_version: '1.0.0',
      last_definition_update: '2024-01-01',
      first_run_complete: '1',
      last_sync_at: '',
    });

    getMainWindow = jest.fn(() => null);

    register(ipcMain, {
      getDb: () => db,
      getMainWindow,
      getMonitor: () => null,
      getUpdater: () => null,
    });
  });

  // ─── settings:get ────────────────────────────────────────────────────────────

  describe('settings:get', () => {
    it('returns all settings as a key-value map', async () => {
      const result = await invoke(ipcMain, 'settings:get');

      expect(result).toMatchObject({
        realtime_protection: '1',
        auto_quarantine: '1',
        start_with_windows: '0',
      });
    });
  });

  // ─── settings:set — validation ────────────────────────────────────────────────

  describe('settings:set — unknown key', () => {
    it('rejects unknown keys with success: false', async () => {
      const result = await invoke(ipcMain, 'settings:set', {
        key: 'not_a_real_key',
        value: '1',
      });

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/unknown settings key/i);
    });
  });

  // ─── settings:set — start_with_windows = '1' (Req 11.1, 18.3) ────────────────

  describe('settings:set start_with_windows', () => {
    it('calls registerWindowsService (installs node-windows service) when value is "1"', async () => {
      const result = await invoke(ipcMain, 'settings:set', {
        key: 'start_with_windows',
        value: '1',
      });

      expect(result).toEqual({ success: true });
      // MockService constructor should have been called once
      expect(MockService).toHaveBeenCalledTimes(1);
      // install() should have been called on the service instance
      expect(mockSvcInstall).toHaveBeenCalledTimes(1);
    });

    it('writes service-config.json to AppData/GSMShieldAV/ when value is "1"', async () => {
      // Point AppData to a temp dir we can inspect
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsm-svc-test-'));
      const { app } = require('electron');
      app.getPath.mockReturnValue(tempDir);

      try {
        await invoke(ipcMain, 'settings:set', {
          key: 'start_with_windows',
          value: '1',
        });

        const configPath = path.join(tempDir, 'GSMShieldAV', 'service-config.json');
        expect(fs.existsSync(configPath)).toBe(true);

        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        expect(config).toHaveProperty('monitoredPaths');
        expect(config).toHaveProperty('registeredAt');
        expect(Array.isArray(config.monitoredPaths)).toBe(true);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
        app.getPath.mockReturnValue(os.tmpdir());
      }
    });

    // ─── Requirement 11.2 ──────────────────────────────────────────────────────

    it('calls unregisterWindowsService (uninstalls node-windows service) when value is "0"', async () => {
      const result = await invoke(ipcMain, 'settings:set', {
        key: 'start_with_windows',
        value: '0',
      });

      expect(result).toEqual({ success: true });
      expect(MockService).toHaveBeenCalledTimes(1);
      expect(mockSvcUninstall).toHaveBeenCalledTimes(1);
    });

    it('does not touch node-windows when value is neither "0" nor "1"', async () => {
      await invoke(ipcMain, 'settings:set', {
        key: 'start_with_windows',
        value: '2',
      });

      expect(MockService).not.toHaveBeenCalled();
    });

    it('persists the new value to the database', async () => {
      await invoke(ipcMain, 'settings:set', {
        key: 'start_with_windows',
        value: '1',
      });

      // The in-memory store should reflect the update
      expect(db._store.start_with_windows).toBe('1');
    });
  });

  // ─── settings:set — other keys (Req 18.1, 18.2, 18.6) ───────────────────────

  describe('settings:set — other keys', () => {
    it.each([
      ['realtime_protection', '0'],
      ['auto_quarantine', '0'],
      ['telemetry_enabled', '0'],
    ])('persists %s = %s without triggering node-windows', async (key, value) => {
      const result = await invoke(ipcMain, 'settings:set', { key, value });

      expect(result).toEqual({ success: true });
      expect(db._store[key]).toBe(value);
      expect(MockService).not.toHaveBeenCalled();
    });
  });

  // ─── settings:addPath (Req 18.4) ─────────────────────────────────────────────

  describe('settings:addPath', () => {
    it('appends a new path to monitored_paths', async () => {
      const result = await invoke(ipcMain, 'settings:addPath', {
        path: 'C:\\Users\\Test\\Documents',
      });

      expect(result).toEqual({ success: true });
      const stored = JSON.parse(db._store.monitored_paths);
      expect(stored).toContain('C:\\Users\\Test\\Documents');
    });

    it('deduplicates — does not add the same path twice', async () => {
      await invoke(ipcMain, 'settings:addPath', { path: 'C:\\Dup' });
      await invoke(ipcMain, 'settings:addPath', { path: 'C:\\Dup' });

      const stored = JSON.parse(db._store.monitored_paths);
      expect(stored.filter((p) => p === 'C:\\Dup').length).toBe(1);
    });
  });

  // ─── settings:removePath (Req 18.4) ──────────────────────────────────────────

  describe('settings:removePath', () => {
    beforeEach(async () => {
      // Pre-populate with two paths
      await invoke(ipcMain, 'settings:addPath', { path: 'C:\\Keep' });
      await invoke(ipcMain, 'settings:addPath', { path: 'C:\\Remove' });
    });

    it('removes the specified path from monitored_paths', async () => {
      const result = await invoke(ipcMain, 'settings:removePath', {
        path: 'C:\\Remove',
      });

      expect(result).toEqual({ success: true });
      const stored = JSON.parse(db._store.monitored_paths);
      expect(stored).not.toContain('C:\\Remove');
      expect(stored).toContain('C:\\Keep');
    });

    it('is a no-op when path does not exist in the list', async () => {
      const before = db._store.monitored_paths;
      await invoke(ipcMain, 'settings:removePath', { path: 'C:\\Ghost' });
      expect(db._store.monitored_paths).toBe(before);
    });
  });

  // ─── settings:getDefinitionInfo (Req 8.5, 18.5) ──────────────────────────────

  describe('settings:getDefinitionInfo', () => {
    it('returns version and lastUpdate from settings', async () => {
      const result = await invoke(ipcMain, 'settings:getDefinitionInfo');

      expect(result).toMatchObject({
        version: '1.0.0',
        lastUpdate: '2024-01-01',
      });
    });

    it('returns empty version string and null lastUpdate when not set', async () => {
      db = buildDb({});
      register(buildIpcMain(), {
        getDb: () => db,
        getMainWindow,
        getMonitor: () => null,
        getUpdater: () => null,
      });

      // Use a fresh ipcMain for this sub-test
      const freshIpc = buildIpcMain();
      register(freshIpc, {
        getDb: () => buildDb({}),
        getMainWindow,
        getMonitor: () => null,
        getUpdater: () => null,
      });

      const result = await invoke(freshIpc, 'settings:getDefinitionInfo');
      expect(result.version).toBe('');
      expect(result.lastUpdate).toBeNull();
    });
  });
});
