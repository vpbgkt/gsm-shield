'use strict';

/**
 * database/init.js
 *
 * Opens (or creates) the GSM Shield AV SQLite database, creates all five
 * tables via CREATE TABLE IF NOT EXISTS, seeds the settings table with
 * default key-value rows on first run, seeds the pre-built GSM tool
 * whitelist entries on first run, and applies any pending schema migrations
 * using the SQLite `user_version` PRAGMA.
 *
 * Works both inside Electron (uses app.getPath('appData')) and in plain
 * Node.js / Jest tests (falls back to os.homedir() + AppData/Roaming).
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const Database = require('better-sqlite3');
const WHITELIST_SEED_ENTRIES = require('../whitelist/seed-data');

/** Shared singleton connection — reused by all callers via getDb(). */
let _db = null;

/**
 * Resolve the directory that should hold the database file.
 * Electron provides app.getPath('appData'); outside Electron we derive it
 * from the OS home directory the same way Electron would on Windows.
 *
 * @returns {string} Absolute path to AppData/Roaming (or equivalent)
 */
function resolveAppDataDir() {
  try {
    // Running inside Electron main process
    const { app } = require('electron');
    if (app && typeof app.getPath === 'function') {
      return path.join(app.getPath('appData'), 'GSMShieldAV');
    }
  } catch (_) {
    // Not running in Electron — fall through to OS-based fallback
  }

  // Fallback: %APPDATA% env var (Windows) or homedir + AppData/Roaming
  const appData =
    process.env.APPDATA ||
    path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(appData, 'GSMShieldAV');
}

/**
 * Default settings rows seeded on first creation of the settings table.
 * Values are stored as TEXT; booleans are '0'/'1' strings.
 */
const SETTINGS_DEFAULTS = [
  { key: 'realtime_protection',   value: '1' },
  { key: 'auto_quarantine',       value: '1' },
  { key: 'start_with_windows',    value: '0' },
  { key: 'telemetry_enabled',     value: '1' },
  { key: 'last_sync_at',          value: '' },
  { key: 'first_run_complete',    value: '0' },
  { key: 'monitored_paths',       value: '[]' },
  { key: 'definition_version',    value: '' },
  { key: 'last_definition_update', value: '' },
];

/** DDL for all five tables (idempotent). */
const SCHEMA_SQL = `
-- Table 1: whitelist
CREATE TABLE IF NOT EXISTS whitelist (
  hash       TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  vendor     TEXT NOT NULL DEFAULT '',
  verified   INTEGER NOT NULL DEFAULT 0,
  source     TEXT NOT NULL CHECK(source IN ('bundled', 'user', 'cloud')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Table 2: quarantine
CREATE TABLE IF NOT EXISTS quarantine (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  original_path   TEXT NOT NULL,
  quarantine_path TEXT NOT NULL,
  threat_name     TEXT NOT NULL,
  file_hash       TEXT NOT NULL,
  detected_at     TEXT NOT NULL DEFAULT (datetime('now')),
  file_size       INTEGER NOT NULL DEFAULT 0
);

-- Table 3: scan_history
CREATE TABLE IF NOT EXISTS scan_history (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  mode          TEXT NOT NULL CHECK(mode IN ('quick', 'full', 'folder', 'file')),
  target_path   TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  ended_at      TEXT,
  files_scanned INTEGER NOT NULL DEFAULT 0,
  threats_found INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'running'
                CHECK(status IN ('running', 'complete', 'cancelled', 'error'))
);

-- Table 4: settings
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Table 5: telemetry
CREATE TABLE IF NOT EXISTS telemetry (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  payload    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  synced     INTEGER NOT NULL DEFAULT 0
);
`;

/**
 * Ordered list of schema migrations.
 *
 * Each entry has:
 *   - `version` {number} — The `user_version` value this migration brings the
 *     database TO. Migrations are run in ascending version order.
 *   - `up(db)` {function} — A function that receives the open Database instance
 *     and applies the schema change. It is called inside a transaction; do NOT
 *     start a nested transaction inside `up`.
 *
 * At v0 all tables are created by the base DDL above, so this array starts
 * empty. Append new migration objects here as the schema evolves.
 *
 * Example:
 *   {
 *     version: 1,
 *     up(db) {
 *       db.exec('ALTER TABLE whitelist ADD COLUMN notes TEXT NOT NULL DEFAULT ""');
 *     },
 *   }
 */
const MIGRATIONS = [
  // No schema changes needed at v0 — all tables are created by the base DDL.
];

/**
 * Resolve the absolute path to the application's AppData log file.
 *
 * @returns {string}
 */
function resolveErrorLogPath() {
  return path.join(resolveAppDataDir(), 'error.log');
}

/**
 * Append a timestamped error message to `AppData/GSMShieldAV/error.log`.
 *
 * @param {string} message
 */
function appendErrorLog(message) {
  try {
    const logPath = resolveErrorLogPath();
    // Ensure directory exists before writing
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const line = `[${new Date().toISOString()}] ${message}\n`;
    fs.appendFileSync(logPath, line, 'utf8');
  } catch (_) {
    // If we can't write the log there is nothing more we can do
  }
}

/**
 * Show a non-fatal error dialog to the user if running inside Electron.
 * Falls back silently when called outside an Electron context (e.g. tests).
 *
 * @param {string} title
 * @param {string} content
 */
function showErrorDialog(title, content) {
  try {
    const { dialog } = require('electron');
    if (dialog && typeof dialog.showErrorBox === 'function') {
      dialog.showErrorBox(title, content);
    }
  } catch (_) {
    // Not running inside Electron — skip the dialog
  }
}

/**
 * Apply all pending schema migrations against `db`.
 *
 * Algorithm:
 *   1. Read `PRAGMA user_version` to discover the current schema version.
 *   2. Filter `MIGRATIONS` to those whose `version` is greater than the
 *      current version, then sort them ascending.
 *   3. For each pending migration: wrap `up(db)` in a `better-sqlite3`
 *      transaction, execute it, and on success set
 *      `PRAGMA user_version = <migration.version>`.
 *   4. If any migration throws, log the error to `error.log`, show a
 *      non-fatal dialog, and stop — the database is left at the last
 *      successfully applied version.
 *
 * @param {import('better-sqlite3').Database} db
 */
function runMigrations(db) {
  const currentVersion = db.pragma('user_version', { simple: true });

  const pending = MIGRATIONS
    .filter((m) => m.version > currentVersion)
    .sort((a, b) => a.version - b.version);

  for (const migration of pending) {
    const applyMigration = db.transaction(() => {
      migration.up(db);
      // Increment user_version inside the same transaction so that a crash
      // mid-migration does not leave the PRAGMA ahead of the actual schema.
      db.pragma(`user_version = ${migration.version}`);
    });

    try {
      applyMigration();
    } catch (err) {
      const msg =
        `Migration to version ${migration.version} failed: ${err && err.message ? err.message : String(err)}`;
      appendErrorLog(msg);
      showErrorDialog('GSM Shield AV — Database Migration Error', msg);
      // Stop at the last good version; do not attempt subsequent migrations.
      break;
    }
  }
}

/**
 * Seed settings defaults only when the settings table is empty.
 *
 * @param {import('better-sqlite3').Database} db
 */
function seedSettingsDefaults(db) {
  const count = db.prepare('SELECT COUNT(*) AS cnt FROM settings').get().cnt;
  if (count > 0) return; // Already seeded — do not duplicate

  const insert = db.prepare(
    'INSERT INTO settings (key, value) VALUES (@key, @value)'
  );

  const seedAll = db.transaction((rows) => {
    for (const row of rows) {
      insert.run(row);
    }
  });

  seedAll(SETTINGS_DEFAULTS);
}

/**
 * Seed the pre-built GSM tool whitelist entries only when the table contains
 * no bundled rows. Uses INSERT OR IGNORE so re-running is always safe.
 *
 * The check is scoped to `source = 'bundled'` so that user-added or
 * cloud-synced entries present from a previous installation never prevent the
 * bundled entries from being inserted on a fresh database.
 *
 * All insertions are wrapped in a single transaction for atomicity — either
 * every entry lands or none do.
 *
 * @param {import('better-sqlite3').Database} db
 */
function seedWhitelistDefaults(db) {
  const { cnt } = db
    .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'bundled'")
    .get();

  if (cnt > 0) return; // Bundled entries already present — skip

  const insert = db.prepare(
    'INSERT OR IGNORE INTO whitelist (hash, name, vendor, verified, source) VALUES (?, ?, ?, ?, ?)'
  );

  const seedAll = db.transaction((entries) => {
    for (const entry of entries) {
      insert.run(entry.hash, entry.name, entry.vendor, entry.verified, entry.source);
    }
  });

  seedAll(WHITELIST_SEED_ENTRIES);
}

/**
 * Initialise the database.
 *
 * - Ensures the AppData/GSMShieldAV directory exists.
 * - Opens (or creates) `gsm-shield.db`.
 * - Creates all five tables via idempotent DDL.
 * - Seeds settings defaults if the settings table is empty.
 * - Stores the connection in the module-level singleton for `getDb()`.
 *
 * Safe to call multiple times — subsequent calls return the existing
 * connection without re-running schema creation.
 *
 * @returns {import('better-sqlite3').Database} The open database connection
 */
function initDatabase() {
  if (_db) return _db;

  const dbDir = resolveAppDataDir();

  // Ensure directory exists (recursive so intermediate dirs are created too)
  fs.mkdirSync(dbDir, { recursive: true });

  const dbPath = path.join(dbDir, 'gsm-shield.db');

  const db = new Database(dbPath, {
    // verbose: console.log,  // uncomment for SQL debug logging
  });

  // Improve write performance and robustness
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Create all tables
  db.exec(SCHEMA_SQL);

  // Seed defaults
  seedSettingsDefaults(db);

  // Seed pre-built GSM tool whitelist entries (only when no bundled entries exist)
  seedWhitelistDefaults(db);

  // Apply any pending schema migrations
  runMigrations(db);

  // Ensure the quarantine storage directory exists alongside the database
  ensureQuarantineDir();

  _db = db;
  return _db;
}

/**
 * Ensure the quarantine storage directory exists on disk.
 * Called after the database is initialised so the path is guaranteed to
 * be inside the same AppData/GSMShieldAV folder as the database file.
 */
function ensureQuarantineDir() {
  const quarantineDir = path.join(resolveAppDataDir(), 'quarantine');
  fs.mkdirSync(quarantineDir, { recursive: true });
}

/**
 * Return the already-initialised database connection.
 * Throws if `initDatabase()` has not been called yet.
 *
 * @returns {import('better-sqlite3').Database}
 */
function getDb() {
  if (!_db) {
    throw new Error(
      'Database has not been initialised. Call initDatabase() before getDb().'
    );
  }
  return _db;
}

/**
 * Close the database connection and reset the singleton.
 * Primarily used in tests to get a clean state between test runs.
 */
function closeDatabase() {
  if (_db) {
    _db.close();
    _db = null;
  }
}

module.exports = { initDatabase, getDb, closeDatabase, runMigrations, ensureQuarantineDir, MIGRATIONS };
