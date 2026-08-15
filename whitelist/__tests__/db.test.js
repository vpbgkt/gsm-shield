'use strict';

/**
 * whitelist/__tests__/db.test.js
 *
 * Example tests for all SQLite CRUD operations in whitelist/db.js.
 *
 * Requirements: 2.4, 3.1, 3.2, 3.3, 4.2
 *
 * The electron module is mocked so that app.getPath('appData') resolves to
 * a unique tmpdir per test, ensuring full test isolation (no stale DB data
 * from other test files or previous runs).
 * Each test gets a fresh database via beforeEach/afterEach.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

// Mock electron before requiring any module that pulls it in.
// app.getPath reads process.env.GSM_TEST_APPDATA (set per-test in beforeEach)
// so each test gets an isolated database directory.
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

const { initDatabase, closeDatabase } = require('../../database/init');
const {
  listEntries,
  insertEntry,
  deleteEntry,
  entryExists,
  upsertCloudEntries,
  countUserEntries,
} = require('../db');

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Generate a deterministic 64-char hex hash string from a seed number. */
function fakeHash(seed) {
  return seed.toString(16).padStart(2, '0') + 'a'.repeat(62);
}

/** Insert a minimal user entry and return the hash used. */
function insertUserEntry(overrides = {}) {
  const hash = overrides.hash || fakeHash(Math.floor(Math.random() * 0xfff) + 0x100);
  insertEntry({
    hash,
    name: overrides.name || 'Test Tool',
    vendor: overrides.vendor || 'Test Vendor',
    source: 'user',
    verified: 0,
    ...overrides,
    // ensure hash is applied from above
  });
  return hash;
}

// ─── Test lifecycle ───────────────────────────────────────────────────────────

beforeEach(() => {
  // Create a fresh unique temp directory for each test so the DB file does
  // not persist between tests (avoids stale data from other test files).
  const newDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsm-db-test-'));
  process.env.GSM_TEST_APPDATA = newDir;

  // Initialise a fresh DB for every test; seed-data will be loaded but
  // all bundled entries use placeholder hashes that won't conflict with tests.
  initDatabase();
});

afterEach(() => {
  closeDatabase();
  delete process.env.GSM_TEST_APPDATA;
});

// ─── listEntries ─────────────────────────────────────────────────────────────

describe('listEntries()', () => {
  test('returns an array (even when whitelist has only bundled entries)', () => {
    const rows = listEntries();
    expect(Array.isArray(rows)).toBe(true);
  });

  test('returns all rows when no query is supplied', () => {
    const before = listEntries().length;
    // Use higher seed values to avoid collision with bundled entries (0-19)
    insertEntry({ hash: fakeHash(2000), name: 'ToolA', vendor: 'VendorA', source: 'user' });
    insertEntry({ hash: fakeHash(2001), name: 'ToolB', vendor: 'VendorB', source: 'user' });
    const after = listEntries().length;
    expect(after).toBe(before + 2);
  });

  test('each row has the expected columns', () => {
    insertEntry({ hash: fakeHash(202), name: 'ColumnCheck', vendor: 'Acme', source: 'user' });
    const rows = listEntries();
    const row = rows.find((r) => r.name === 'ColumnCheck');
    expect(row).toBeDefined();
    expect(row).toHaveProperty('hash');
    expect(row).toHaveProperty('name');
    expect(row).toHaveProperty('vendor');
    expect(row).toHaveProperty('verified');
    expect(row).toHaveProperty('source');
    expect(row).toHaveProperty('created_at');
  });

  test('filters by name substring (case-insensitive)', () => {
    insertEntry({ hash: fakeHash(210), name: 'Miracle Box', vendor: 'Miracle Team', source: 'user' });
    insertEntry({ hash: fakeHash(211), name: 'Unrelated Tool', vendor: 'Other', source: 'user' });

    const results = listEntries('miracle');
    const names = results.map((r) => r.name);
    expect(names).toContain('Miracle Box');
    expect(names).not.toContain('Unrelated Tool');
  });

  test('filters by vendor substring (case-insensitive)', () => {
    insertEntry({ hash: fakeHash(212), name: 'Some Tool', vendor: 'Samsung Special', source: 'user' });
    insertEntry({ hash: fakeHash(213), name: 'Other Tool', vendor: 'Unrelated Vendor', source: 'user' });

    const results = listEntries('samsung');
    expect(results.some((r) => r.vendor === 'Samsung Special')).toBe(true);
    expect(results.every((r) => r.vendor !== 'Unrelated Vendor')).toBe(true);
  });

  test('returns empty array when query matches nothing', () => {
    const results = listEntries('zzz_no_match_zzz');
    expect(results).toHaveLength(0);
  });

  test('empty string query returns all rows (same as no query)', () => {
    const withoutQuery = listEntries().length;
    const withEmpty = listEntries('').length;
    expect(withEmpty).toBe(withoutQuery);
  });
});

// ─── insertEntry ─────────────────────────────────────────────────────────────

describe('insertEntry()', () => {
  test('inserts a user entry successfully', () => {
    const hash = fakeHash(300);
    insertEntry({ hash, name: 'MyTool', vendor: 'MyVendor', source: 'user', verified: 0 });
    expect(entryExists(hash)).toBe(true);
  });

  test('inserts a bundled entry successfully', () => {
    const hash = fakeHash(301);
    insertEntry({ hash, name: 'BundledTool', vendor: 'BundledVendor', source: 'bundled', verified: 1 });
    expect(entryExists(hash)).toBe(true);
  });

  test('inserts a cloud entry successfully', () => {
    const hash = fakeHash(302);
    insertEntry({ hash, name: 'CloudTool', vendor: 'CloudVendor', source: 'cloud', verified: 1 });
    expect(entryExists(hash)).toBe(true);
  });

  test('throws when source is invalid', () => {
    expect(() => {
      insertEntry({ hash: fakeHash(303), name: 'Bad', vendor: '', source: 'invalid' });
    }).toThrow(/Invalid source/);
  });

  test('silently ignores duplicate hash (INSERT OR IGNORE)', () => {
    const hash = fakeHash(304);
    insertEntry({ hash, name: 'First', vendor: '', source: 'user' });
    // second insert with same hash — should not throw
    expect(() => {
      insertEntry({ hash, name: 'Second', vendor: '', source: 'user' });
    }).not.toThrow();
    // name should still be 'First' (original row not replaced)
    const rows = listEntries();
    const row = rows.find((r) => r.hash === hash);
    expect(row.name).toBe('First');
  });

  test('vendor defaults to empty string when omitted', () => {
    const hash = fakeHash(305);
    insertEntry({ hash, name: 'NoVendor', source: 'user' });
    const rows = listEntries();
    const row = rows.find((r) => r.hash === hash);
    expect(row.vendor).toBe('');
  });

  test('verified defaults to 0 when omitted', () => {
    const hash = fakeHash(306);
    insertEntry({ hash, name: 'Unverified', vendor: '', source: 'user' });
    const rows = listEntries();
    const row = rows.find((r) => r.hash === hash);
    expect(row.verified).toBe(0);
  });
});

// ─── deleteEntry ─────────────────────────────────────────────────────────────

describe('deleteEntry()', () => {
  test('deletes a user-source entry and returns { success: true }', () => {
    const hash = fakeHash(400);
    insertEntry({ hash, name: 'DeleteMe', vendor: '', source: 'user' });
    const result = deleteEntry(hash);
    expect(result).toEqual({ success: true });
    expect(entryExists(hash)).toBe(false);
  });

  test('returns { success: false, forbidden: true } for bundled entry', () => {
    const hash = fakeHash(401);
    insertEntry({ hash, name: 'Protected', vendor: '', source: 'bundled', verified: 1 });
    const result = deleteEntry(hash);
    expect(result).toEqual({ success: false, forbidden: true });
    expect(entryExists(hash)).toBe(true);
  });

  test('returns { success: false, forbidden: true } for cloud entry', () => {
    const hash = fakeHash(402);
    insertEntry({ hash, name: 'CloudEntry', vendor: '', source: 'cloud', verified: 1 });
    const result = deleteEntry(hash);
    expect(result).toEqual({ success: false, forbidden: true });
    expect(entryExists(hash)).toBe(true);
  });

  test('returns { success: false } when hash does not exist', () => {
    const result = deleteEntry('f'.repeat(64));
    expect(result).toEqual({ success: false });
    // no forbidden flag — entry simply did not exist
    expect(result.forbidden).toBeUndefined();
  });
});

// ─── entryExists ─────────────────────────────────────────────────────────────

describe('entryExists()', () => {
  test('returns true for an inserted entry', () => {
    const hash = fakeHash(500);
    insertEntry({ hash, name: 'Exists', vendor: '', source: 'user' });
    expect(entryExists(hash)).toBe(true);
  });

  test('returns false for a hash that was never inserted', () => {
    // Use a hash that definitely won't be in the bundled seed data
    // Bundled hashes have format: 'XX' + '0'.repeat(62) where XX is 00-19 in hex
    const nonExistentHash = 'ff' + '0'.repeat(62);
    expect(entryExists(nonExistentHash)).toBe(false);
  });

  test('returns false after the entry has been deleted', () => {
    const hash = fakeHash(501);
    insertEntry({ hash, name: 'WillBeDeleted', vendor: '', source: 'user' });
    deleteEntry(hash);
    expect(entryExists(hash)).toBe(false);
  });
});

// ─── upsertCloudEntries ───────────────────────────────────────────────────────

describe('upsertCloudEntries()', () => {
  test('inserts multiple cloud entries in one call', () => {
    const entries = [
      { hash: fakeHash(600), name: 'Cloud1', vendor: 'V1', source: 'cloud', verified: 1 },
      { hash: fakeHash(601), name: 'Cloud2', vendor: 'V2', source: 'cloud', verified: 0 },
    ];
    upsertCloudEntries(entries);
    expect(entryExists(fakeHash(600))).toBe(true);
    expect(entryExists(fakeHash(601))).toBe(true);
  });

  test('updates an existing cloud entry (upsert behaviour)', () => {
    const hash = fakeHash(602);
    insertEntry({ hash, name: 'OldName', vendor: 'OldVendor', source: 'cloud', verified: 0 });
    upsertCloudEntries([{ hash, name: 'NewName', vendor: 'NewVendor', source: 'cloud', verified: 1 }]);
    const rows = listEntries();
    const row = rows.find((r) => r.hash === hash);
    expect(row.name).toBe('NewName');
    expect(row.verified).toBe(1);
  });

  test('never overwrites a user-source entry', () => {
    const hash = fakeHash(603);
    insertEntry({ hash, name: 'UserEntry', vendor: 'UserVendor', source: 'user', verified: 0 });
    upsertCloudEntries([{ hash, name: 'CloudOverwrite', vendor: 'CloudVendor', source: 'cloud', verified: 1 }]);
    const rows = listEntries();
    const row = rows.find((r) => r.hash === hash);
    // Original user entry must be preserved
    expect(row.name).toBe('UserEntry');
    expect(row.source).toBe('user');
  });

  test('skips entries explicitly flagged source=user in the payload', () => {
    const hash = fakeHash(604);
    upsertCloudEntries([{ hash, name: 'BadSource', vendor: '', source: 'user', verified: 0 }]);
    // Entry flagged as user in the payload should be silently skipped
    expect(entryExists(hash)).toBe(false);
  });

  test('does nothing for an empty array', () => {
    const before = listEntries().length;
    upsertCloudEntries([]);
    expect(listEntries().length).toBe(before);
  });

  test('does nothing for a non-array argument', () => {
    const before = listEntries().length;
    upsertCloudEntries(null);
    expect(listEntries().length).toBe(before);
  });
});

// ─── countUserEntries ────────────────────────────────────────────────────────

describe('countUserEntries()', () => {
  test('returns 0 when no user entries exist', () => {
    // Get the current count and clean up any existing user entries
    const db = require('../../database').getDb();
    db.prepare("DELETE FROM whitelist WHERE source = 'user'").run();
    
    // Now fresh DB only has bundled seed entries
    expect(countUserEntries()).toBe(0);
  });

  test('increments by 1 for each new user entry', () => {
    const before = countUserEntries();
    insertEntry({ hash: fakeHash(700), name: 'U1', vendor: '', source: 'user' });
    expect(countUserEntries()).toBe(before + 1);
    insertEntry({ hash: fakeHash(701), name: 'U2', vendor: '', source: 'user' });
    expect(countUserEntries()).toBe(before + 2);
  });

  test('does not count bundled or cloud entries', () => {
    const before = countUserEntries();
    insertEntry({ hash: fakeHash(702), name: 'B1', vendor: '', source: 'bundled', verified: 1 });
    insertEntry({ hash: fakeHash(703), name: 'C1', vendor: '', source: 'cloud', verified: 1 });
    expect(countUserEntries()).toBe(before); // unchanged
  });

  test('decrements after a user entry is deleted', () => {
    const hash = fakeHash(704);
    insertEntry({ hash, name: 'ToRemove', vendor: '', source: 'user' });
    const before = countUserEntries();
    deleteEntry(hash);
    expect(countUserEntries()).toBe(before - 1);
  });
});
