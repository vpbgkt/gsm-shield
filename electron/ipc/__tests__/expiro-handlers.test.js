'use strict';

/**
 * electron/ipc/__tests__/expiro-handlers.test.js
 *
 * Unit tests for Expiro IPC handlers:
 *   - expiro:scan-file
 *   - expiro:scan-files
 *   - expiro:scan-directory
 *   - expiro:get-config
 *   - expiro:set-threshold
 *   - expiro:disinfect-file
 *   - expiro:disinfect-batch
 *   - expiro:get-stats
 *   - expiro:generate-report
 *   - expiro:scan-before-execution
 *   - expiro:update-paths
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { register } = require('../expiro-handlers');
const expiroDetector = require('../../../engine/expiro-detector');

describe('Expiro IPC Handlers', () => {
  let ipcMain;
  let handlers;
  let mockQuarantine;
  let mockMainWindow;
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'expiro-ipc-test-'));
    handlers = new Map();
    ipcMain = {
      handle: jest.fn((channel, handler) => {
        handlers.set(channel, handler);
      }),
    };

    mockQuarantine = {
      quarantineFile: jest.fn().mockResolvedValue({
        quarantinePath: path.join(tempDir, 'quarantine', 'test.exe'),
        fileHash: 'abcdef123456',
        fileSize: 1024,
      }),
    };

    mockMainWindow = {
      isDestroyed: jest.fn().mockReturnValue(false),
      webContents: {
        send: jest.fn(),
      },
    };

    register(ipcMain, {
      getQuarantine: () => mockQuarantine,
      getMainWindow: () => mockMainWindow,
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (_) {}
  });

  describe('Registration', () => {
    test('registers all required Expiro IPC channels', () => {
      const requiredChannels = [
        'expiro:scan-file',
        'expiro:scan-files',
        'expiro:scan-directory',
        'expiro:get-config',
        'expiro:set-threshold',
        'expiro:disinfect-file',
        'expiro:disinfect-batch',
        'expiro:get-stats',
        'expiro:generate-report',
        'expiro:scan-before-execution',
        'expiro:update-paths',
      ];

      for (const channel of requiredChannels) {
        expect(handlers.has(channel)).toBe(true);
      }
    });
  });

  describe('expiro:get-config & expiro:set-threshold', () => {
    test('retrieves current heuristic configuration', async () => {
      const handler = handlers.get('expiro:get-config');
      const res = await handler({});
      expect(res.success).toBe(true);
      expect(res.detectionThreshold).toBeDefined();
      expect(res.certaintyThreshold).toBeDefined();
    });

    test('sets detection threshold within valid bounds', async () => {
      const setHandler = handlers.get('expiro:set-threshold');
      const res = await setHandler({}, { threshold: 75 });
      expect(res.success).toBe(true);
      expect(res.threshold).toBe(75);
      expect(expiroDetector.EXPIRO_SIGNATURES.detectionThreshold).toBe(75);

      // Reset to 60
      await setHandler({}, { threshold: 60 });
      expect(expiroDetector.EXPIRO_SIGNATURES.detectionThreshold).toBe(60);
    });

    test('rejects threshold outside bounds (e.g. 10 or 150)', async () => {
      const setHandler = handlers.get('expiro:set-threshold');
      const resLow = await setHandler({}, { threshold: 10 });
      expect(resLow.success).toBe(false);

      const resHigh = await setHandler({}, { threshold: 150 });
      expect(resHigh.success).toBe(false);
    });
  });

  describe('expiro:scan-directory', () => {
    test('scans PE files in directory and sends progress', async () => {
      // Create test PE mock file
      const fakeExe = path.join(tempDir, 'test-app.exe');
      fs.writeFileSync(fakeExe, Buffer.alloc(100)); // Minimal non-PE buffer

      const handler = handlers.get('expiro:scan-directory');
      const res = await handler({}, { dirPath: tempDir });

      expect(res.success).toBe(true);
      expect(res.totalFiles).toBe(1);
      expect(res.results.length).toBe(0); // Clean file is filtered out of detections array
      expect(res.summary.total).toBe(1);
      expect(res.summary.clean).toBe(1);
    });

    test('returns error for nonexistent directory', async () => {
      const handler = handlers.get('expiro:scan-directory');
      const res = await handler({}, { dirPath: 'C:\\nonexistent\\dir\\path' });
      expect(res.success).toBe(false);
      expect(res.error).toBe('Directory does not exist');
    });
  });

  describe('expiro:disinfect-file', () => {
    test('quarantines infected file when no clean source is available', async () => {
      const testFile = path.join(tempDir, 'infected.exe');
      fs.writeFileSync(testFile, 'dummy infected content');

      const handler = handlers.get('expiro:disinfect-file');
      const res = await handler({}, {
        filePath: testFile,
        detection: {
          filePath: testFile,
          confidence: 85,
          threatName: 'Virus:Win32/Expiro.EK!MTB',
        },
      });

      expect(res.success).toBe(true);
      expect(res.result.action).toBe('quarantined');
      expect(mockQuarantine.quarantineFile).toHaveBeenCalledWith(
        testFile,
        'Virus:Win32/Expiro.EK!MTB'
      );
    });
  });

  describe('expiro:get-stats & expiro:scan-before-execution', () => {
    test('handles uninitialized monitor gracefully', async () => {
      delete global.expiroMonitor;

      const statsHandler = handlers.get('expiro:get-stats');
      const statsRes = await statsHandler({});
      expect(statsRes.success).toBe(true);
      expect(statsRes.stats.isActive).toBe(false);

      const preExecHandler = handlers.get('expiro:scan-before-execution');
      const preExecRes = await preExecHandler({}, { filePath: 'test.exe' });
      expect(preExecRes.success).toBe(true);
      expect(preExecRes.allowed).toBe(true);
    });

    test('queries monitor when initialized', async () => {
      global.expiroMonitor = {
        getStats: jest.fn().mockReturnValue({
          filesMonitored: 42,
          threatsBlocked: 0,
        }),
        scanBeforeExecution: jest.fn().mockResolvedValue({
          allowed: true,
          confidence: 0,
        }),
      };

      const statsHandler = handlers.get('expiro:get-stats');
      const statsRes = await statsHandler({});
      expect(statsRes.success).toBe(true);
      expect(statsRes.stats.filesMonitored).toBe(42);

      const preExecHandler = handlers.get('expiro:scan-before-execution');
      const preExecRes = await preExecHandler({}, { filePath: 'test.exe' });
      expect(preExecRes.success).toBe(true);
      expect(preExecRes.allowed).toBe(true);

      delete global.expiroMonitor;
    });
  });
});
