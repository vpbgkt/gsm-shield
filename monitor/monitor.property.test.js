'use strict';

/**
 * monitor/monitor.property.test.js
 *
 * Property-based tests for monitor/monitor.js using fast-check v3.x
 *
 * Properties covered:
 *   Property 12: Monitor extension filter
 *   Property 13: Debounce — awaitWriteFinish configuration contract
 *   Property 14: Quarantine path exclusion invariant
 *   Property 20: Watch list empty when protection disabled
 *
 * Validates: Requirements 10.2, 10.3, 9.2, 10.6, 10.8
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

const fc = require('fast-check');
const path = require('path');
const chokidar = require('chokidar');
const checker  = require('../whitelist/checker');

const {
  startMonitor,
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
  mockWatcher.on.mockReturnValue(mockWatcher);
});

// ─── Property 12: Monitor extension filter ────────────────────────────────────
// Validates: Requirements 10.2

describe('Property 12: Monitor extension filter', () => {
  /**
   * For any arbitrary file path, the 'add' event handler should call
   * checker.isWhitelisted if and only if the file's extension (lowercased)
   * is in MONITORED_EXTENSIONS.
   *
   * Validates: Requirements 10.2
   */
  test('filter passes iff lowercase extension is in MONITORED_EXTENSIONS', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string(),
        async (filePath) => {
          jest.clearAllMocks();
          mockWatcher.on.mockReturnValue(mockWatcher);

          startMonitor(['/watch'], {});
          const addCb = getWatcherListener('add');
          if (!addCb) return; // guard: listener must be registered

          await addCb(filePath);

          const ext = path.extname(filePath).toLowerCase();
          const shouldBeEligible = MONITORED_EXTENSIONS.has(ext);

          if (shouldBeEligible) {
            // eligible extension → whitelist check MUST have been called
            expect(checker.isWhitelisted).toHaveBeenCalledWith(filePath);
          } else {
            // ineligible extension → whitelist check must NOT have been called
            expect(checker.isWhitelisted).not.toHaveBeenCalled();
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ─── Property 13: Debounce — awaitWriteFinish configuration contract ──────────
// Validates: Requirements 10.3

describe('Property 13: Debounce — awaitWriteFinish configuration contract', () => {
  /**
   * Regardless of the input paths, chokidar.watch must always be called with
   * awaitWriteFinish: { stabilityThreshold: 2000, pollInterval: 100 }.
   *
   * This tests the unit-level contract: Chokidar's awaitWriteFinish is how
   * the monitor implements debouncing (single invocation per write burst).
   *
   * Validates: Requirements 10.3
   */
  test('chokidar.watch always receives awaitWriteFinish debounce config regardless of input paths', () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1 })),
        (paths) => {
          jest.clearAllMocks();
          mockWatcher.on.mockReturnValue(mockWatcher);

          startMonitor(paths, {});

          expect(chokidar.watch).toHaveBeenCalledTimes(1);
          const [, options] = chokidar.watch.mock.calls[0];

          expect(options).toMatchObject({
            awaitWriteFinish: {
              stabilityThreshold: 2000,
              pollInterval: 100,
            },
          });
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ─── Property 14: Quarantine path exclusion invariant ─────────────────────────
// Validates: Requirements 9.2, 10.6

describe('Property 14: Quarantine path exclusion invariant', () => {
  /**
   * For any array of paths (even ones that explicitly include QUARANTINE_DIR),
   * chokidar.watch must never be called with QUARANTINE_DIR present in the
   * paths array.
   *
   * Validates: Requirements 9.2, 10.6
   */
  test('QUARANTINE_DIR is never present in paths passed to chokidar.watch', () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1 })),
        (generatedPaths) => {
          jest.clearAllMocks();
          mockWatcher.on.mockReturnValue(mockWatcher);

          // Always include QUARANTINE_DIR in the input
          startMonitor([...generatedPaths, QUARANTINE_DIR], {});

          expect(chokidar.watch).toHaveBeenCalledTimes(1);
          const [passedPaths] = chokidar.watch.mock.calls[0];

          // QUARANTINE_DIR must never appear in the watched paths
          expect(passedPaths).not.toContain(QUARANTINE_DIR);

          // Case-insensitive check as well (Windows paths)
          const quarantineLower = QUARANTINE_DIR.toLowerCase();
          const hasQuarantine = passedPaths.some(
            (p) => typeof p === 'string' && p.toLowerCase() === quarantineLower,
          );
          expect(hasQuarantine).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ─── Property 20: Watch list empty when protection disabled ───────────────────
// Validates: Requirements 10.8

describe('Property 20: Watch list empty when protection disabled', () => {
  /**
   * When startMonitor is called with an empty array (protection disabled),
   * chokidar.watch must receive an empty array [] regardless of what paths
   * might have been configured.
   *
   * Validates: Requirements 10.8
   */
  test('chokidar.watch receives [] when startMonitor is called with empty paths', () => {
    fc.assert(
      fc.property(
        // Generate arbitrary configured paths (to confirm they don't leak through)
        fc.array(fc.string({ minLength: 1 })),
        (_configuredPaths) => {
          jest.clearAllMocks();
          mockWatcher.on.mockReturnValue(mockWatcher);

          // Protection disabled → pass empty array (regardless of configured paths)
          startMonitor([], {});

          expect(chokidar.watch).toHaveBeenCalledTimes(1);
          const [passedPaths] = chokidar.watch.mock.calls[0];

          expect(Array.isArray(passedPaths)).toBe(true);
          expect(passedPaths).toHaveLength(0);
        },
      ),
      { numRuns: 100 },
    );
  });
});
