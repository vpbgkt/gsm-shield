'use strict';

/**
 * monitor/monitor.test.js
 *
 * Unit tests for monitor/monitor.js
 *
 * Tests cover:
 *  - MONITORED_EXTENSIONS and QUARANTINE_DIR exports
 *  - filterPaths (via startMonitor): quarantine dir excluded, dedup
 *  - Extension filtering: only eligible extensions processed
 *  - startMonitor / stopMonitor / updatePaths APIs
 *  - Watcher event plumbing with mocked dependencies
 */

// ── Mock electron so the module loads outside Electron ───────────────────────
jest.mock('electron', () => ({
  app: { getPath: () => 'C:\\Users\\Test\\AppData\\Roaming' },
  Notification: class { show() {} },
}), { virtual: true });

// ── Mock chokidar so we control the watcher ───────────────────────────────────
const mockWatcher = {
  on:      jest.fn().mockReturnThis(),
  add:     jest.fn(),
  unwatch: jest.fn(),
  close:   jest.fn(),
};
jest.mock('chokidar', () => ({
  watch: jest.fn(() => mockWatcher),
}));

// ── Mock whitelist/checker ────────────────────────────────────────────────────
jest.mock('../whitelist/checker', () => ({
  isWhitelisted: jest.fn().mockResolvedValue(false),
}));

// ── Mock engine/scanner ───────────────────────────────────────────────────────
jest.mock('../engine/scanner', () => ({
  scan: jest.fn().mockResolvedValue({ filesScanned: 1, threatsFound: 0, cancelled: false }),
}));

// ── Mock engine/quarantine ────────────────────────────────────────────────────
jest.mock('../engine/quarantine', () => ({
  quarantineFile: jest.fn().mockResolvedValue(undefined),
  QUARANTINE_DIR: 'C:\\Users\\Test\\AppData\\Roaming\\GSMShieldAV\\quarantine',
}));

const chokidar  = require('chokidar');
const checker   = require('../whitelist/checker');
const scannerMod = require('../engine/scanner');
const quarantine = require('../engine/quarantine');

const {
  startMonitor,
  stopMonitor,
  updatePaths,
  MONITORED_EXTENSIONS,
  QUARANTINE_DIR,
} = require('./monitor');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Return the callback registered for a given event on the mock watcher. */
function getWatcherListener(event) {
  const call = mockWatcher.on.mock.calls.find(([ev]) => ev === event);
  return call ? call[1] : null;
}

beforeEach(() => {
  jest.clearAllMocks();
  // Re-attach .on mock chain so each test starts fresh
  mockWatcher.on.mockReturnValue(mockWatcher);
  mockWatcher._monitorPaths = undefined;
});

// ─── MONITORED_EXTENSIONS ─────────────────────────────────────────────────────

describe('MONITORED_EXTENSIONS', () => {
  test('is a Set', () => {
    expect(MONITORED_EXTENSIONS).toBeInstanceOf(Set);
  });

  test('contains all required extensions', () => {
    const required = [
      '.exe', '.dll', '.msi', '.bat', '.cmd',
      '.vbs', '.ps1', '.js',  '.scr', '.com',
      '.zip', '.rar', '.7z',
    ];
    for (const ext of required) {
      expect(MONITORED_EXTENSIONS.has(ext)).toBe(true);
    }
  });

  test('does not contain .txt or .png', () => {
    expect(MONITORED_EXTENSIONS.has('.txt')).toBe(false);
    expect(MONITORED_EXTENSIONS.has('.png')).toBe(false);
  });
});

// ─── QUARANTINE_DIR ───────────────────────────────────────────────────────────

describe('QUARANTINE_DIR', () => {
  test('is a non-empty string', () => {
    expect(typeof QUARANTINE_DIR).toBe('string');
    expect(QUARANTINE_DIR.length).toBeGreaterThan(0);
  });

  test('ends with "quarantine"', () => {
    expect(QUARANTINE_DIR.toLowerCase()).toMatch(/quarantine$/);
  });
});

// ─── startMonitor ─────────────────────────────────────────────────────────────

describe('startMonitor', () => {
  test('calls chokidar.watch with the expected options', () => {
    startMonitor(['/some/path'], {});

    expect(chokidar.watch).toHaveBeenCalledWith(
      ['/some/path'],
      expect.objectContaining({
        persistent:    true,
        ignoreInitial: true,
        awaitWriteFinish: {
          stabilityThreshold: 2000,
          pollInterval:        100,
        },
      }),
    );
  });

  test('strips QUARANTINE_DIR from watchPaths before passing to Chokidar', () => {
    const paths = ['/user/path', QUARANTINE_DIR, '/another/path'];
    startMonitor(paths, {});

    const passedPaths = chokidar.watch.mock.calls[0][0];
    expect(passedPaths).not.toContain(QUARANTINE_DIR);
    expect(passedPaths).toContain('/user/path');
    expect(passedPaths).toContain('/another/path');
  });

  test('deduplicates watch paths', () => {
    startMonitor(['/user/path', '/user/path', '/other'], {});

    const passedPaths = chokidar.watch.mock.calls[0][0];
    const count = passedPaths.filter(p => p === '/user/path').length;
    expect(count).toBe(1);
  });

  test('returns the chokidar watcher object', () => {
    const watcher = startMonitor(['/path'], {});
    expect(watcher).toBe(mockWatcher);
  });

  test('registers "add", "change", and "error" event listeners', () => {
    startMonitor(['/path'], {});

    const registeredEvents = mockWatcher.on.mock.calls.map(([ev]) => ev);
    expect(registeredEvents).toContain('add');
    expect(registeredEvents).toContain('change');
    expect(registeredEvents).toContain('error');
  });
});

// ─── stopMonitor ──────────────────────────────────────────────────────────────

describe('stopMonitor', () => {
  test('calls watcher.close()', () => {
    const watcher = startMonitor(['/path'], {});
    stopMonitor(watcher);
    expect(mockWatcher.close).toHaveBeenCalled();
  });

  test('does not throw when called with null', () => {
    expect(() => stopMonitor(null)).not.toThrow();
  });
});

// ─── updatePaths ──────────────────────────────────────────────────────────────

describe('updatePaths', () => {
  test('unwatch old paths and adds new paths', () => {
    const watcher = startMonitor(['/old'], {});
    watcher._monitorPaths = new Set(['/old']);

    updatePaths(watcher, ['/new']);

    expect(mockWatcher.unwatch).toHaveBeenCalledWith('/old');
    expect(mockWatcher.add).toHaveBeenCalledWith('/new');
  });

  test('strips QUARANTINE_DIR from newPaths', () => {
    const watcher = startMonitor(['/existing'], {});
    watcher._monitorPaths = new Set(['/existing']);

    updatePaths(watcher, ['/new', QUARANTINE_DIR]);

    const addCalls = mockWatcher.add.mock.calls.map(([p]) => p);
    expect(addCalls).not.toContain(QUARANTINE_DIR);
    expect(addCalls).toContain('/new');
  });

  test('does not add a path that is already being watched', () => {
    const watcher = startMonitor(['/already'], {});
    watcher._monitorPaths = new Set(['/already']);

    updatePaths(watcher, ['/already', '/new']);

    const addCalls = mockWatcher.add.mock.calls.map(([p]) => p);
    expect(addCalls).not.toContain('/already');
    expect(addCalls).toContain('/new');
  });

  test('does not throw when called with null watcher', () => {
    expect(() => updatePaths(null, ['/path'])).not.toThrow();
  });

  test('updates _monitorPaths to the new filtered set', () => {
    const watcher = startMonitor(['/old'], {});
    watcher._monitorPaths = new Set(['/old']);

    updatePaths(watcher, ['/new', '/other']);

    expect(watcher._monitorPaths.has('/new')).toBe(true);
    expect(watcher._monitorPaths.has('/other')).toBe(true);
    expect(watcher._monitorPaths.has('/old')).toBe(false);
  });
});

// ─── File event filtering (extension check) ───────────────────────────────────

describe('file event extension filtering', () => {
  async function triggerAddEvent(filePath) {
    startMonitor(['/watch'], {});
    const addCb = getWatcherListener('add');
    if (addCb) await addCb(filePath);
  }

  test('eligible .exe file triggers whitelist check', async () => {
    await triggerAddEvent('/tmp/malware.exe');
    expect(checker.isWhitelisted).toHaveBeenCalledWith('/tmp/malware.exe');
  });

  test('eligible .ps1 file triggers whitelist check', async () => {
    await triggerAddEvent('/tmp/script.ps1');
    expect(checker.isWhitelisted).toHaveBeenCalledWith('/tmp/script.ps1');
  });

  test('ineligible .txt file does NOT trigger whitelist check', async () => {
    await triggerAddEvent('/tmp/readme.txt');
    expect(checker.isWhitelisted).not.toHaveBeenCalled();
  });

  test('ineligible .log file does NOT trigger scan', async () => {
    await triggerAddEvent('/tmp/app.log');
    expect(scannerMod.scan).not.toHaveBeenCalled();
  });

  test('extension check is case-insensitive (.EXE treated as .exe)', async () => {
    await triggerAddEvent('/tmp/MALWARE.EXE');
    expect(checker.isWhitelisted).toHaveBeenCalled();
  });
});

// ─── Whitelist gate ────────────────────────────────────────────────────────────

describe('whitelist gate', () => {
  test('whitelisted file is NOT passed to scanner', async () => {
    checker.isWhitelisted.mockResolvedValueOnce(true);

    startMonitor(['/watch'], {});
    const addCb = getWatcherListener('add');
    await addCb('/tmp/legit.exe');

    expect(scannerMod.scan).not.toHaveBeenCalled();
  });

  test('non-whitelisted file IS passed to scanner', async () => {
    checker.isWhitelisted.mockResolvedValueOnce(false);

    startMonitor(['/watch'], {});
    const addCb = getWatcherListener('add');
    await addCb('/tmp/unknown.exe');

    expect(scannerMod.scan).toHaveBeenCalledWith(
      '/tmp/unknown.exe',
      expect.any(Object),
    );
  });
});

// ─── Threat handling ──────────────────────────────────────────────────────────

describe('threat handling', () => {
  test('when scanner finds a threat, quarantineFile is called', async () => {
    checker.isWhitelisted.mockResolvedValueOnce(false);
    scannerMod.scan.mockImplementationOnce(async (fp, { onThreat }) => {
      onThreat({ filePath: fp, threatName: 'Trojan.Test' });
      return { filesScanned: 1, threatsFound: 1, cancelled: false };
    });

    startMonitor(['/watch'], {});
    const addCb = getWatcherListener('add');
    await addCb('/tmp/virus.exe');

    expect(quarantine.quarantineFile).toHaveBeenCalledWith(
      '/tmp/virus.exe',
      'Trojan.Test',
    );
  });

  test('onThreat callback is called when threat detected', async () => {
    checker.isWhitelisted.mockResolvedValueOnce(false);
    scannerMod.scan.mockImplementationOnce(async (fp, { onThreat }) => {
      onThreat({ filePath: fp, threatName: 'Worm.Test' });
      return { filesScanned: 1, threatsFound: 1, cancelled: false };
    });

    const onThreat = jest.fn();
    startMonitor(['/watch'], { onThreat });
    const addCb = getWatcherListener('add');
    await addCb('/tmp/worm.exe');

    expect(onThreat).toHaveBeenCalledWith(
      expect.objectContaining({ filePath: '/tmp/worm.exe', threatName: 'Worm.Test' }),
    );
  });

  test('clean file does NOT invoke quarantineFile', async () => {
    checker.isWhitelisted.mockResolvedValueOnce(false);
    scannerMod.scan.mockResolvedValueOnce({ filesScanned: 1, threatsFound: 0, cancelled: false });

    startMonitor(['/watch'], {});
    const addCb = getWatcherListener('add');
    await addCb('/tmp/clean.exe');

    expect(quarantine.quarantineFile).not.toHaveBeenCalled();
  });
});

// ─── Chokidar path error handling ─────────────────────────────────────────────

describe('path error handling', () => {
  test('onError callback is invoked on Chokidar error', () => {
    const onError = jest.fn();
    startMonitor(['/watch'], { onError });

    const errCb = getWatcherListener('error');
    const fakeErr = Object.assign(new Error('ENOENT'), { path: '/watch/gone' });
    errCb(fakeErr);

    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({ path: '/watch/gone' }),
    );
  });

  test('erroring path is unwatched on error', () => {
    const watcher = startMonitor(['/watch'], {});
    watcher._monitorPaths = new Set(['/watch/gone']);

    const errCb = getWatcherListener('error');
    const fakeErr = Object.assign(new Error('ENOENT'), { path: '/watch/gone' });
    errCb(fakeErr);

    expect(mockWatcher.unwatch).toHaveBeenCalledWith('/watch/gone');
  });

  test('erroring path is removed from _monitorPaths', () => {
    const watcher = startMonitor(['/watch'], {});
    watcher._monitorPaths = new Set(['/watch/gone', '/watch/ok']);

    const errCb = getWatcherListener('error');
    const fakeErr = Object.assign(new Error('ENOENT'), { path: '/watch/gone' });
    errCb(fakeErr);

    expect(watcher._monitorPaths.has('/watch/gone')).toBe(false);
    expect(watcher._monitorPaths.has('/watch/ok')).toBe(true);
  });
});
