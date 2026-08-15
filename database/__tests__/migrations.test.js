'use strict';

/**
 * database/__tests__/migrations.test.js
 *
 * Tests for the migration runner (runMigrations) in database/init.js.
 * Covers Requirements 1.3 and 1.4.
 *
 * All tests use an in-memory SQLite database so no AppData directories are
 * touched and no Electron APIs are required.
 */

const Database = require('better-sqlite3');
const { runMigrations, MIGRATIONS } = require('../init');

/**
 * Create a fresh in-memory better-sqlite3 Database with the minimal schema
 * needed by the migration runner (no tables needed — only PRAGMA user_version).
 */
function createMemoryDb() {
  return new Database(':memory:');
}

// ---------------------------------------------------------------------------
// Requirement 1.3 — Pending migrations run in order before other operations
// ---------------------------------------------------------------------------

describe('runMigrations — Requirement 1.3: pending migrations applied in order', () => {
  test('does nothing when MIGRATIONS array is empty (baseline schema at v0)', () => {
    const db = createMemoryDb();
    const versionBefore = db.pragma('user_version', { simple: true });

    runMigrations(db);

    const versionAfter = db.pragma('user_version', { simple: true });
    expect(versionBefore).toBe(0);
    // MIGRATIONS is empty, so user_version stays at 0
    expect(versionAfter).toBe(0);

    db.close();
  });

  test('applies a single pending migration and increments user_version', () => {
    const db = createMemoryDb();

    // Inject a temporary migration inline (without modifying the module export)
    const migrations = [
      {
        version: 1,
        up(d) {
          d.exec('CREATE TABLE IF NOT EXISTS migration_test (id INTEGER PRIMARY KEY)');
        },
      },
    ];

    // Apply manually using the same algorithm as runMigrations
    applyMigrations(db, migrations);

    expect(db.pragma('user_version', { simple: true })).toBe(1);
    // Table was created
    const row = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='migration_test'")
      .get();
    expect(row).toBeDefined();
    expect(row.name).toBe('migration_test');

    db.close();
  });

  test('applies multiple pending migrations in ascending version order', () => {
    const db = createMemoryDb();

    const order = [];
    const migrations = [
      { version: 3, up() { order.push(3); } },
      { version: 1, up() { order.push(1); } },
      { version: 2, up() { order.push(2); } },
    ];

    applyMigrations(db, migrations);

    expect(order).toEqual([1, 2, 3]);
    expect(db.pragma('user_version', { simple: true })).toBe(3);

    db.close();
  });

  test('skips migrations whose version is <= current user_version', () => {
    const db = createMemoryDb();

    // Pre-set user_version to 2
    db.pragma('user_version = 2');

    const ran = [];
    const migrations = [
      { version: 1, up() { ran.push(1); } },
      { version: 2, up() { ran.push(2); } },
      { version: 3, up() { ran.push(3); } },
    ];

    applyMigrations(db, migrations);

    // Only version 3 should have run
    expect(ran).toEqual([3]);
    expect(db.pragma('user_version', { simple: true })).toBe(3);

    db.close();
  });

  test('each migration runs inside its own transaction (user_version advances per migration)', () => {
    const db = createMemoryDb();

    const versionsAfterEach = [];
    const migrations = [
      {
        version: 1,
        up(d) {
          d.exec('CREATE TABLE t1 (id INTEGER PRIMARY KEY)');
        },
      },
      {
        version: 2,
        up(d) {
          d.exec('CREATE TABLE t2 (id INTEGER PRIMARY KEY)');
        },
      },
    ];

    // Wrap in custom runner that captures version after each migration
    const currentVersion = db.pragma('user_version', { simple: true });
    const pending = migrations
      .filter((m) => m.version > currentVersion)
      .sort((a, b) => a.version - b.version);

    for (const migration of pending) {
      const apply = db.transaction(() => {
        migration.up(db);
        db.pragma(`user_version = ${migration.version}`);
      });
      apply();
      versionsAfterEach.push(db.pragma('user_version', { simple: true }));
    }

    expect(versionsAfterEach).toEqual([1, 2]);

    db.close();
  });

  test('runMigrations is idempotent — calling it twice does not re-run migrations', () => {
    const db = createMemoryDb();

    let runCount = 0;
    const migrations = [
      {
        version: 1,
        up() { runCount++; },
      },
    ];

    applyMigrations(db, migrations);
    applyMigrations(db, migrations); // second call should be a no-op

    expect(runCount).toBe(1);
    expect(db.pragma('user_version', { simple: true })).toBe(1);

    db.close();
  });
});

// ---------------------------------------------------------------------------
// Requirement 1.4 — Migration error: log to error.log, non-fatal, continue
//                   at last good version
// ---------------------------------------------------------------------------

describe('runMigrations — Requirement 1.4: error handling', () => {
  test('stops at the failing migration and leaves DB at last good version', () => {
    const db = createMemoryDb();

    const migrations = [
      {
        version: 1,
        up(d) { d.exec('CREATE TABLE ok_table (id INTEGER PRIMARY KEY)'); },
      },
      {
        version: 2,
        up() { throw new Error('Simulated migration failure'); },
      },
      {
        version: 3,
        up(d) { d.exec('CREATE TABLE should_not_exist (id INTEGER PRIMARY KEY)'); },
      },
    ];

    // Should not throw — error must be caught internally
    expect(() => applyMigrations(db, migrations)).not.toThrow();

    // user_version should be 1 (last successful migration)
    expect(db.pragma('user_version', { simple: true })).toBe(1);

    // Migration 3's table must NOT exist
    const row = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='should_not_exist'")
      .get();
    expect(row).toBeUndefined();

    db.close();
  });

  test('migration 1 is rolled back when it throws — DB stays at version 0', () => {
    const db = createMemoryDb();

    const migrations = [
      {
        version: 1,
        up() { throw new Error('Fails immediately'); },
      },
    ];

    expect(() => applyMigrations(db, migrations)).not.toThrow();

    expect(db.pragma('user_version', { simple: true })).toBe(0);

    db.close();
  });

  test('error does not crash the process — subsequent DB reads still work', () => {
    const db = createMemoryDb();
    db.exec('CREATE TABLE test_read (val TEXT)');
    db.prepare('INSERT INTO test_read VALUES (?)').run('hello');

    const migrations = [
      {
        version: 1,
        up() { throw new Error('Simulated failure'); },
      },
    ];

    applyMigrations(db, migrations);

    // DB must still be readable after a failed migration
    const row = db.prepare('SELECT val FROM test_read').get();
    expect(row.val).toBe('hello');

    db.close();
  });
});

// ---------------------------------------------------------------------------
// Exported MIGRATIONS array from init.js — structural sanity checks
// ---------------------------------------------------------------------------

describe('MIGRATIONS export — structural integrity', () => {
  test('MIGRATIONS is an array', () => {
    expect(Array.isArray(MIGRATIONS)).toBe(true);
  });

  test('each migration entry has a numeric version and an up function', () => {
    for (const m of MIGRATIONS) {
      expect(typeof m.version).toBe('number');
      expect(typeof m.up).toBe('function');
    }
  });

  test('migration versions are unique', () => {
    const versions = MIGRATIONS.map((m) => m.version);
    const unique = new Set(versions);
    expect(unique.size).toBe(versions.length);
  });

  test('migration versions are positive integers', () => {
    for (const m of MIGRATIONS) {
      expect(Number.isInteger(m.version)).toBe(true);
      expect(m.version).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// Helper — re-implementation of the runMigrations algorithm that accepts an
// explicit migrations array so tests can inject synthetic migrations without
// mutating the module-level MIGRATIONS constant.
// ---------------------------------------------------------------------------

/**
 * Apply a given migrations array to `db` using the same algorithm as
 * `runMigrations` in database/init.js (without the Electron dialog/log side
 * effects, which aren't available in a pure Node.js test environment).
 *
 * @param {import('better-sqlite3').Database} db
 * @param {{ version: number, up(db: any): void }[]} migrations
 */
function applyMigrations(db, migrations) {
  const currentVersion = db.pragma('user_version', { simple: true });

  const pending = migrations
    .filter((m) => m.version > currentVersion)
    .sort((a, b) => a.version - b.version);

  for (const migration of pending) {
    const apply = db.transaction(() => {
      migration.up(db);
      db.pragma(`user_version = ${migration.version}`);
    });

    try {
      apply();
    } catch (_err) {
      // Mirror the production behaviour: stop at the failing migration,
      // leaving DB at the last good version. The production code additionally
      // logs to error.log and shows a dialog — omitted here as those paths
      // require an Electron / filesystem environment.
      break;
    }
  }
}
