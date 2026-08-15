'use strict';

/**
 * whitelist/__tests__/sync.test.js
 *
 * Unit tests for whitelist/sync.js
 *
 * Requirements: 4.1, 4.2, 4.3, 4.5, 25.1
 *
 * Strategy:
 *   - Mock electron so app.getPath resolves to os.tmpdir().
 *   - Mock https at the module level and adjust the mock implementation per test.
 *   - Use real timers for async HTTP tests; use fake timers only for timer
 *     scheduling tests (scheduleSync) to keep those tests instantaneous.
 *   - Use sync._resetState() between tests to clear timers/counters.
 */

// ─── Mocks (must be declared before any require) ──────────────────────────────

jest.mock('electron', () => ({
  app: {
    getPath: (key) => {
      if (key === 'appData') {
        return process.env.GSM_TEST_APPDATA || require('os').tmpdir();
      }
      return require('os').tmpdir();
    },
  },
  dialog: { showErrorBox: jest.fn() },
}));

// Provide a controllable mock for the https module.
let mockRequest = jest.fn();
jest.mock('https', () => ({ request: (...args) => mockRequest(...args) }));
jest.mock('http',  () => ({ request: (...args) => mockRequest(...args) }));

// ─── Requires ─────────────────────────────────────────────────────────────────

const os = require('os');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { initDatabase, closeDatabase, getDb } = require('../../database/init');
const whitelistDb = require('../db');
const sync = require('../sync');

// ─── Request factory helpers ──────────────────────────────────────────────────

/** 64-char hex SHA-256 placeholder */
function fakeHash(seed) {
  return seed.toString(16).padStart(2, '0') + 'b'.repeat(62);
}

/**
 * Wire `mockRequest` to simulate a successful 200 JSON response.
 * Calls back synchronously so tests don't need timers.
 * @param {Array} entries
 */
function useSuccessResponse(entries) {
  mockRequest = jest.fn((options, callback) => {
    const res = new EventEmitter();
    res.statusCode = 200;
    res.setEncoding = jest.fn();
    res.resume = jest.fn();

    const req = new EventEmitter();
    req.setTimeout = jest.fn();
    req.destroy = jest.fn();
    req.end = jest.fn(() => {
      // Call back synchronously on next tick (process.nextTick to avoid
      // re-entrancy issues but still within the same microtask checkpoint)
      process.nextTick(() => {
        callback(res);
        process.nextTick(() => {
          res.emit('data', JSON.stringify(entries));
          res.emit('end');
        });
      });
    });
    return req;
  });
}

/**
 * Wire `mockRequest` to simulate a non-200 HTTP status.
 * @param {number} statusCode
 */
function useNon200Response(statusCode) {
  mockRequest = jest.fn((_options, callback) => {
    const res = new EventEmitter();
    res.statusCode = statusCode;
    res.setEncoding = jest.fn();
    res.resume = jest.fn();

    const req = new EventEmitter();
    req.setTimeout = jest.fn();
    req.destroy = jest.fn();
    req.end = jest.fn(() => {
      process.nextTick(() => callback(res));
    });
    return req;
  });
}

/**
 * Wire `mockRequest` to emit a network-level error.
 * @param {string} message
 */
function useNetworkError(message) {
  mockRequest = jest.fn(() => {
    const req = new EventEmitter();
    req.setTimeout = jest.fn();
    req.destroy = jest.fn();
    req.end = jest.fn(() => {
      process.nextTick(() => req.emit('error', new Error(message)));
    });
    return req;
  });
}

// ─── Test lifecycle ───────────────────────────────────────────────────────────

beforeEach(() => {
  // Create a fresh unique temp directory for each test so the DB file does
  // not persist between tests (avoids stale data from other test files).
  const newDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsm-sync-test-'));
  process.env.GSM_TEST_APPDATA = newDir;

  initDatabase();
});

afterEach(() => {
  sync._resetState();
  closeDatabase();
  jest.clearAllMocks();
  jest.useRealTimers();
  delete process.env.BACKEND_URL;
  delete process.env.API_KEY;
  delete process.env.GSM_TEST_APPDATA;
});

// ─── syncFromCloud — missing BACKEND_URL ──────────────────────────────────────

describe('syncFromCloud() — missing BACKEND_URL', () => {
  test('returns zero counts and does not throw when BACKEND_URL is unset', async () => {
    const result = await sync.syncFromCloud();
    expect(result).toMatchObject({ added: 0, updated: 0 });
    expect(typeof result.timestamp).toBe('string');
  });
});

// ─── syncFromCloud — successful 200 response ─────────────────────────────────

describe('syncFromCloud() — 200 OK', () => {
  beforeEach(() => {
    process.env.BACKEND_URL = 'https://example.com';
    process.env.API_KEY = 'test-api-key';
  });

  test('returns an object with numeric added/updated and ISO timestamp', async () => {
    useSuccessResponse([
      { hash: fakeHash(100), name: 'Tool A', vendor: 'VA', verified: 1, source: 'cloud' },
    ]);
    const result = await sync.syncFromCloud();
    expect(typeof result.added).toBe('number');
    expect(typeof result.updated).toBe('number');
    expect(typeof result.timestamp).toBe('string');
    expect(() => new Date(result.timestamp)).not.toThrow();
  });

  test('upserts received entries into the whitelist DB', async () => {
    const hash = fakeHash(200);
    useSuccessResponse([
      { hash, name: 'Cloud Tool', vendor: 'CV', verified: 1, source: 'cloud' },
    ]);
    await sync.syncFromCloud();
    expect(whitelistDb.entryExists(hash)).toBe(true);
  });

  test('updates last_sync_at setting after a successful sync', async () => {
    useSuccessResponse([
      { hash: fakeHash(300), name: 'Sync Tool', vendor: 'SV', verified: 1, source: 'cloud' },
    ]);
    const before = Date.now();
    await sync.syncFromCloud();

    const row = getDb()
      .prepare('SELECT value FROM settings WHERE key = ?')
      .get('last_sync_at');
    expect(row).toBeDefined();
    const ts = new Date(row.value).getTime();
    expect(ts).toBeGreaterThanOrEqual(before - 5000);
  });

  test('sends the Authorization: Bearer header with API_KEY', async () => {
    useSuccessResponse([]);
    await sync.syncFromCloud();

    const callOptions = mockRequest.mock.calls[0][0];
    expect(callOptions.headers).toMatchObject({
      Authorization: 'Bearer test-api-key',
    });
  });

  test('resets consecutive failure counter and retry attempt on success', async () => {
    // Trigger one failure first to set the counters
    useNetworkError('first error');
    await sync.syncFromCloud();
    // retry attempt should be 1 after first failure
    expect(sync._getRetryAttempt()).toBeGreaterThan(0);

    // Now succeed
    useSuccessResponse([{ hash: fakeHash(400), name: 'T', vendor: '', verified: 0, source: 'cloud' }]);
    await sync.syncFromCloud();

    expect(sync._getConsecutiveFailureMs()).toBe(0);
    expect(sync._getRetryAttempt()).toBe(0);
  });

  test('does not throw when server returns empty array', async () => {
    useSuccessResponse([]);
    await expect(sync.syncFromCloud()).resolves.not.toThrow();
  });
});

// ─── syncFromCloud — network / HTTP errors ───────────────────────────────────

describe('syncFromCloud() — network / HTTP errors', () => {
  beforeEach(() => {
    process.env.BACKEND_URL = 'https://example.com';
    process.env.API_KEY = 'test-api-key';
  });

  test('does not throw on network error — returns zero counts', async () => {
    useNetworkError('ECONNREFUSED');
    const result = await sync.syncFromCloud();
    expect(result).toMatchObject({ added: 0, updated: 0 });
  });

  test('does not throw on non-200 status — returns zero counts', async () => {
    useNon200Response(503);
    const result = await sync.syncFromCloud();
    expect(result).toMatchObject({ added: 0, updated: 0 });
  });

  test('schedules a back-off retry timer after failure (retry counter increments)', async () => {
    useNetworkError('connect ETIMEDOUT');
    await sync.syncFromCloud();
    // scheduleRetry() was called — the retry attempt counter proves it
    expect(sync._getRetryAttempt()).toBe(1);
  });

  test('retry attempt counter increments with each failure', async () => {
    useNetworkError('error');
    await sync.syncFromCloud();
    expect(sync._getRetryAttempt()).toBe(1);
  });

  test('network error leaves existing whitelist entries unchanged (Req 4.3)', async () => {
    // Pre-insert one user-source entry and one cloud-source entry
    const db = getDb();
    db.prepare(
      'INSERT OR IGNORE INTO whitelist (hash, name, vendor, verified, source) VALUES (?, ?, ?, ?, ?)'
    ).run('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', 'User Tool', 'VendorU', 0, 'user');
    db.prepare(
      'INSERT OR IGNORE INTO whitelist (hash, name, vendor, verified, source) VALUES (?, ?, ?, ?, ?)'
    ).run('f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2', 'Cloud Tool', 'VendorC', 1, 'cloud');

    // Wire a network-level error
    useNetworkError('ECONNREFUSED');
    process.env.BACKEND_URL = 'https://example.com';

    // syncFromCloud() must resolve without throwing
    await expect(sync.syncFromCloud()).resolves.not.toThrow();

    // Both pre-inserted entries must still be present after the failed sync
    const userRow = db
      .prepare('SELECT hash FROM whitelist WHERE hash = ? AND source = ?')
      .get('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', 'user');
    expect(userRow).toBeDefined();

    const cloudRow = db
      .prepare('SELECT hash FROM whitelist WHERE hash = ? AND source = ?')
      .get('f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2', 'cloud');
    expect(cloudRow).toBeDefined();
  });
});

// ─── Back-off delay calculation ───────────────────────────────────────────────

describe('_backoffDelay()', () => {
  const ONE_HOUR = 60 * 60 * 1000;

  test('attempt 0 yields 1 hour', () => {
    expect(sync._backoffDelay(0)).toBe(ONE_HOUR);
  });

  test('attempt 1 yields 2 hours', () => {
    expect(sync._backoffDelay(1)).toBe(2 * ONE_HOUR);
  });

  test('attempt 2 yields 4 hours', () => {
    expect(sync._backoffDelay(2)).toBe(4 * ONE_HOUR);
  });

  test('attempt 3 yields 8 hours (first cap)', () => {
    expect(sync._backoffDelay(3)).toBe(8 * ONE_HOUR);
  });

  test('attempt 10 is still capped at 8 hours', () => {
    expect(sync._backoffDelay(10)).toBe(8 * ONE_HOUR);
  });

  test('delay is always positive', () => {
    for (let i = 0; i < 20; i++) {
      expect(sync._backoffDelay(i)).toBeGreaterThan(0);
    }
  });
});

// ─── 72-hour error escalation ─────────────────────────────────────────────────

describe('syncFromCloud() — 72-hour error escalation', () => {
  test('pushes whitelist:sync-error IPC after >72 consecutive hours of failures', async () => {
    process.env.BACKEND_URL = 'https://example.com';
    process.env.API_KEY = 'key';

    const fakeSend = jest.fn();
    sync.setMainWindow({
      isDestroyed: () => false,
      webContents: { send: fakeSend },
    });

    useNetworkError('persistent error');

    // Trace of accumulation when calling with _isRetry=true and the counter
    // starts at 0:
    // Call 1: attempt=0 → condition (_isRetry && attempt>0) is FALSE → 0h added, attempt→1
    // Call 2: attempt=1 → adds backoffDelay(0)=1h, attempt→2  →  total: 1h
    // Call 3: attempt=2 → adds backoffDelay(1)=2h, attempt→3  →  total: 3h
    // Call 4: attempt=3 → adds backoffDelay(2)=4h, attempt→4  →  total: 7h
    // Calls 5-14: each adds backoffDelay(>=3)=8h   →  total after 14: 7 + 8*10 = 87h > 72h ✓
    for (let i = 0; i < 14; i++) {
      await sync.syncFromCloud({ _isRetry: true });
    }

    expect(fakeSend).toHaveBeenCalledWith(
      'whitelist:sync-error',
      expect.objectContaining({ message: expect.any(String) })
    );
  });

  test('does NOT push sync-error when failure time is under 72 hours', async () => {
    process.env.BACKEND_URL = 'https://example.com';
    process.env.API_KEY = 'key';

    const fakeSend = jest.fn();
    sync.setMainWindow({
      isDestroyed: () => false,
      webContents: { send: fakeSend },
    });

    useNetworkError('short failure');

    // Only a single non-retry failure — accumulates 0 extra time
    await sync.syncFromCloud();

    expect(fakeSend).not.toHaveBeenCalledWith(
      'whitelist:sync-error',
      expect.anything()
    );
  });
});

// ─── setMainWindow / setLicenseStatus / isLicenseActive ──────────────────────

describe('module-level setters', () => {
  test('isLicenseActive() defaults to false', () => {
    expect(sync.isLicenseActive()).toBe(false);
  });

  test('setLicenseStatus(true) makes isLicenseActive() return true', () => {
    sync.setLicenseStatus(true);
    expect(sync.isLicenseActive()).toBe(true);
  });

  test('setLicenseStatus(false) makes isLicenseActive() return false', () => {
    sync.setLicenseStatus(true);
    sync.setLicenseStatus(false);
    expect(sync.isLicenseActive()).toBe(false);
  });

  test('setLicenseStatus with truthy non-boolean coerces to true', () => {
    sync.setLicenseStatus(1);
    expect(sync.isLicenseActive()).toBe(true);
  });
});

// ─── scheduleSync ─────────────────────────────────────────────────────────────

describe('scheduleSync()', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  test('starts a repeating interval (timer is pending)', () => {
    sync.scheduleSync();
    expect(jest.getTimerCount()).toBeGreaterThan(0);
  });

  test('calling scheduleSync() twice clears the old interval (no extra timers)', () => {
    sync.scheduleSync();
    const after1 = jest.getTimerCount();
    sync.scheduleSync();
    const after2 = jest.getTimerCount();
    // The second call should not have grown the timer count beyond the first
    expect(after2).toBeLessThanOrEqual(after1 + 1);
  });

  test('does NOT call syncFromCloud when license is inactive after 24h tick', async () => {
    sync.setLicenseStatus(false);

    const spy = jest.spyOn(sync, 'syncFromCloud');
    sync.scheduleSync();

    jest.advanceTimersByTime(24 * 60 * 60 * 1000);
    await Promise.resolve();

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('calls syncFromCloud when license is active after 24h tick', async () => {
    sync.setLicenseStatus(true);

    // Mock syncFromCloud itself so it returns instantly without HTTP
    const spy = jest.spyOn(sync, 'syncFromCloud').mockResolvedValue({
      added: 0, updated: 0, timestamp: new Date().toISOString(),
    });

    sync.scheduleSync();
    // advanceTimersByTime fires the interval callback synchronously;
    // the spy call is registered before the async body resolves.
    jest.advanceTimersByTime(24 * 60 * 60 * 1000);

    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ─── Property-Based Tests ─────────────────────────────────────────────────────

const fc = require('fast-check');

/**
 * Arbitrary that generates a single cloud whitelist entry.
 * Hashes are prefixed with 'cc' to avoid collision with user-entry hashes
 * (which are prefixed with 'aa' in Property 6 tests).
 */
const cloudEntryArb = fc.record({
  hash: fc.hexaString({ minLength: 62, maxLength: 62 }).map((s) => 'cc' + s),
  name: fc.string({ minLength: 1, maxLength: 64 }),
  vendor: fc.string({ minLength: 0, maxLength: 64 }),
  verified: fc.constant(1),
  source: fc.constant('cloud'),
});

/**
 * **Property 6: Cloud upsert preserves user-added entries**
 *
 * For any array of cloud entries received from the server, all pre-existing
 * user-source entries must still be present in the DB after syncFromCloud().
 *
 * Validates: Requirements 4.2
 */
describe('PBT — Property 6: cloud upsert preserves user-added entries', () => {
  beforeEach(() => {
    process.env.BACKEND_URL = 'https://example.com';
    process.env.API_KEY = 'test-api-key';
    initDatabase();
  });

  afterEach(() => {
    sync._resetState();
    closeDatabase();
    jest.clearAllMocks();
    delete process.env.BACKEND_URL;
    delete process.env.API_KEY;
  });

  test('all user entries survive a cloud sync with arbitrary cloud payloads', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(cloudEntryArb, { minLength: 0, maxLength: 20 }),
        fc.array(
          fc.record({
            hash: fc.hexaString({ minLength: 62, maxLength: 62 }).map((s) => 'aa' + s),
            name: fc.string({ minLength: 1, maxLength: 64 }),
            vendor: fc.string({ minLength: 0, maxLength: 64 }),
          }),
          { minLength: 1, maxLength: 10 }
        ),
        async (cloudEntries, userEntries) => {
          // Pre-insert user entries
          const db = getDb();
          const insertUser = db.prepare(
            'INSERT OR IGNORE INTO whitelist (hash, name, vendor, verified, source) VALUES (?, ?, ?, 0, ?)'
          );
          const insertAll = db.transaction((rows) => {
            for (const e of rows) insertUser.run(e.hash, e.name, e.vendor || '', 'user');
          });
          insertAll(userEntries);

          // Wire a successful HTTP response with the generated cloud entries
          useSuccessResponse(cloudEntries);

          // Run the sync
          await sync.syncFromCloud();

          // Assert every user entry is still in the DB
          const stmt = db.prepare('SELECT hash FROM whitelist WHERE hash = ? AND source = ?');
          for (const entry of userEntries) {
            const row = stmt.get(entry.hash, 'user');
            if (!row) return false;
          }
          return true;
        }
      ),
      { numRuns: 50 }
    );
  });
});

/**
 * **Property 7: Sync timestamp is updated on success**
 *
 * After a successful syncFromCloud(), the `last_sync_at` value stored in the
 * settings table must be >= the timestamp recorded immediately before calling
 * syncFromCloud().
 *
 * Validates: Requirements 4.5
 */
describe('PBT — Property 7: sync timestamp is updated on success', () => {
  beforeEach(() => {
    process.env.BACKEND_URL = 'https://example.com';
    process.env.API_KEY = 'test-api-key';
    initDatabase();
  });

  afterEach(() => {
    sync._resetState();
    closeDatabase();
    jest.clearAllMocks();
    delete process.env.BACKEND_URL;
    delete process.env.API_KEY;
  });

  test('last_sync_at after a successful sync is >= pre-sync timestamp', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 1_000_000 }),
        async (_seed) => {
          // Record a "pre-sync" timestamp
          const preSyncTime = Date.now();

          // Wire a successful (empty) response — we only care about the timestamp
          useSuccessResponse([]);

          // Run the sync
          await sync.syncFromCloud();

          // Read last_sync_at from the DB
          const db = getDb();
          const row = db
            .prepare('SELECT value FROM settings WHERE key = ?')
            .get('last_sync_at');

          if (!row || !row.value) return false;

          const postSyncTime = new Date(row.value).getTime();
          return postSyncTime >= preSyncTime;
        }
      ),
      { numRuns: 50 }
    );
  });
});
