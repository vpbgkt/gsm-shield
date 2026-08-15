'use strict';

/**
 * database/__tests__/init.test.js
 *
 * Example tests for database schema creation and settings seeding.
 *
 * Tests:
 *   - All 5 tables exist after initDatabase() on a fresh in-memory DB
 *   - settings table contains exactly the 9 default key-value pairs on first creation
 *   - initDatabase() called twice does not duplicate settings rows
 *
 * Requirements: 1.1, 1.2, 1.5
 *
 * The electron module is mocked so that app.getPath('appData') resolves to
 * a unique tmpdir per test, avoiding any dependency on the Electron runtime
 * and ensuring full test isolation (no stale DB file from a previous run).
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

// Import AFTER the mock is set up
const { initDatabase, closeDatabase } = require('../init');

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Return the sorted list of table names present in the given database. */
function getTableNames(db) {
  return db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    .all()
    .map((r) => r.name);
}

/** Return all rows from the settings table as { key, value } objects. */
function getSettingsRows(db) {
  return db.prepare('SELECT key, value FROM settings ORDER BY key').all();
}

// ─── Test lifecycle ───────────────────────────────────────────────────────────

beforeEach(() => {
  // Create a fresh unique temp directory for each test so the DB file does
  // not persist between tests (avoids stale data from other test files).
  const newDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsm-init-test-'));
  process.env.GSM_TEST_APPDATA = newDir;
});

afterEach(() => {
  // Reset the singleton so each test gets a fresh database connection.
  closeDatabase();
  delete process.env.GSM_TEST_APPDATA;
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('initDatabase() — schema creation', () => {
  /**
   * Requirement 1.2: THE Database SHALL contain exactly five tables on
   * creation: whitelist, quarantine, scan_history, settings, and telemetry.
   */
  test('all 5 required tables exist after initDatabase() on a fresh DB', () => {
    const db = initDatabase();

    const tables = getTableNames(db);

    const EXPECTED_TABLES = [
      'quarantine',
      'scan_history',
      'settings',
      'telemetry',
      'whitelist',
    ].sort();

    expect(tables).toEqual(EXPECTED_TABLES);
    expect(tables).toHaveLength(5);
  });

  test('whitelist table has the correct columns', () => {
    const db = initDatabase();

    const info = db.pragma('table_info(whitelist)');
    const columnNames = info.map((c) => c.name).sort();

    expect(columnNames).toEqual(
      ['hash', 'name', 'vendor', 'verified', 'source', 'created_at'].sort()
    );
  });

  test('quarantine table has the correct columns', () => {
    const db = initDatabase();

    const info = db.pragma('table_info(quarantine)');
    const columnNames = info.map((c) => c.name).sort();

    expect(columnNames).toEqual(
      ['id', 'original_path', 'quarantine_path', 'threat_name', 'file_hash', 'detected_at', 'file_size'].sort()
    );
  });

  test('scan_history table has the correct columns', () => {
    const db = initDatabase();

    const info = db.pragma('table_info(scan_history)');
    const columnNames = info.map((c) => c.name).sort();

    expect(columnNames).toEqual(
      ['id', 'mode', 'target_path', 'started_at', 'ended_at', 'files_scanned', 'threats_found', 'status'].sort()
    );
  });

  test('settings table has the correct columns', () => {
    const db = initDatabase();

    const info = db.pragma('table_info(settings)');
    const columnNames = info.map((c) => c.name).sort();

    expect(columnNames).toEqual(['key', 'value'].sort());
  });

  test('telemetry table has the correct columns', () => {
    const db = initDatabase();

    const info = db.pragma('table_info(telemetry)');
    const columnNames = info.map((c) => c.name).sort();

    expect(columnNames).toEqual(
      ['id', 'event_type', 'payload', 'created_at', 'synced'].sort()
    );
  });
});

describe('initDatabase() — settings seeding', () => {
  /**
   * Requirement 1.5: THE settings table SHALL be populated with default
   * values on first creation so that the Application has a valid
   * configuration state before the user changes any settings.
   */
  test('settings table contains exactly 9 rows on first creation', () => {
    const db = initDatabase();

    const rows = getSettingsRows(db);

    expect(rows).toHaveLength(9);
  });

  test('settings table contains all 9 expected default keys', () => {
    const db = initDatabase();

    const rows = getSettingsRows(db);
    const keys = rows.map((r) => r.key).sort();

    const EXPECTED_KEYS = [
      'auto_quarantine',
      'definition_version',
      'first_run_complete',
      'last_definition_update',
      'last_sync_at',
      'monitored_paths',
      'realtime_protection',
      'start_with_windows',
      'telemetry_enabled',
    ].sort();

    expect(keys).toEqual(EXPECTED_KEYS);
  });

  test('each default setting has the correct seeded value', () => {
    const db = initDatabase();

    const rows = getSettingsRows(db);
    const map = Object.fromEntries(rows.map((r) => [r.key, r.value]));

    expect(map.realtime_protection).toBe('1');
    expect(map.auto_quarantine).toBe('1');
    expect(map.start_with_windows).toBe('0');
    expect(map.telemetry_enabled).toBe('1');
    expect(map.last_sync_at).toBe('');
    expect(map.first_run_complete).toBe('0');
    expect(map.monitored_paths).toBe('[]');
    expect(map.definition_version).toBe('');
    expect(map.last_definition_update).toBe('');
  });
});

describe('initDatabase() — whitelist seeding', () => {
  /**
   * Requirement 2.1, 2.5: THE Whitelist SHALL include SHA-256 hash entries
   * for at least 20 known GSM tools on initial installation, all marked as
   * source='bundled' and verified=1.
   *
   * Task 3.3: Seed pre-built GSM tool whitelist entries on first run.
   */
  test('whitelist table contains exactly 20 bundled entries on first creation', () => {
    const db = initDatabase();

    const count = db
      .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'bundled'")
      .get().cnt;

    expect(count).toBe(20);
  });

  test('all bundled whitelist entries have verified=1', () => {
    const db = initDatabase();

    const rows = db
      .prepare("SELECT verified FROM whitelist WHERE source = 'bundled'")
      .all();

    expect(rows).toHaveLength(20);
    rows.forEach((row) => {
      expect(row.verified).toBe(1);
    });
  });

  test('bundled whitelist entries include all required GSM tools', () => {
    const db = initDatabase();

    const names = db
      .prepare("SELECT name FROM whitelist WHERE source = 'bundled' ORDER BY name")
      .all()
      .map((r) => r.name);

    const EXPECTED_TOOLS = [
      'ATF Box',
      'Chimera Tool',
      'EFT Pro Dongle',
      'Easy JTAG',
      'Falcon Box',
      'Furious Gold',
      'GPG Dragon',
      'Hydra Tool',
      'Infinity CM2',
      'MRT Dongle',
      'Miracle Box',
      'NCK Box',
      'Odin3',
      'Pandora Box',
      'Riff Box',
      'SP Flash Tool',
      'Sigma Box',
      'UFI Box',
      'Volcano Box',
      'Z3X Pro',
    ].sort();

    expect(names).toEqual(EXPECTED_TOOLS);
  });

  test('all bundled entries have unique placeholder hashes', () => {
    const db = initDatabase();

    const hashes = db
      .prepare("SELECT hash FROM whitelist WHERE source = 'bundled'")
      .all()
      .map((r) => r.hash);

    // Check uniqueness using a Set
    const uniqueHashes = new Set(hashes);
    expect(uniqueHashes.size).toBe(20);

    // Verify each hash is 64 characters
    hashes.forEach((hash) => {
      expect(hash).toHaveLength(64);
    });
  });

  test('calling initDatabase() twice does not duplicate bundled whitelist entries', () => {
    // First call — creates and seeds
    initDatabase();

    // Second call — should return existing connection, not re-seed
    const db = initDatabase();

    const count = db
      .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'bundled'")
      .get().cnt;

    // Still exactly 20 bundled entries — no duplicates
    expect(count).toBe(20);
  });

  test('bundled entries are seeded even when user entries exist', () => {
    const db = initDatabase();

    // Manually add a user entry
    db.prepare(
      "INSERT INTO whitelist (hash, name, vendor, verified, source) VALUES (?, ?, ?, ?, ?)"
    ).run('a'.repeat(64), 'User Tool', 'User Vendor', 0, 'user');

    // Close and reinitialize to trigger seeding logic
    closeDatabase();
    const db2 = initDatabase();

    const bundledCount = db2
      .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'bundled'")
      .get().cnt;

    const userCount = db2
      .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'user'")
      .get().cnt;

    expect(bundledCount).toBe(20);
    expect(userCount).toBe(1);
  });
});

describe('initDatabase() — idempotency', () => {
  /**
   * Requirement 1.1 / 1.5: Calling initDatabase() more than once (e.g. after
   * app re-initialisation) must not duplicate settings rows.
   *
   * The singleton guard in initDatabase() returns the existing connection on
   * subsequent calls, so settings seeding is only attempted once per process
   * lifetime. We simulate a "second call" by calling initDatabase() twice
   * within the same test before closeDatabase() resets the singleton.
   */
  test('calling initDatabase() twice does not duplicate settings rows', () => {
    // First call — creates and seeds
    initDatabase();

    // Second call — should return the existing connection, not re-seed
    const db = initDatabase();

    const rows = getSettingsRows(db);

    // Still exactly 9 rows — no duplicates
    expect(rows).toHaveLength(9);
  });

  test('calling initDatabase() twice returns the same database instance', () => {
    const db1 = initDatabase();
    const db2 = initDatabase();

    // Strict reference equality — same singleton object
    expect(db1).toBe(db2);
  });

  test('settings row count stays 9 after multiple initDatabase() calls', () => {
    initDatabase();
    initDatabase();
    const db = initDatabase();

    const count = db
      .prepare('SELECT COUNT(*) AS cnt FROM settings')
      .get().cnt;

    expect(count).toBe(9);
  });
});
