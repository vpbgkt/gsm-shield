'use strict';

/**
 * whitelist/db.js
 *
 * All SQLite CRUD operations for the `whitelist` table.
 * Uses the better-sqlite3 synchronous API via the shared database singleton.
 *
 * Supported sources: 'bundled' | 'user' | 'cloud'
 *
 * Exported functions:
 *   listEntries(query?)         → WhitelistEntry[]
 *   insertEntry(entry)          → void
 *   deleteEntry(hash)           → { success, forbidden? }
 *   entryExists(hash)           → boolean
 *   upsertCloudEntries(entries) → void
 *   countUserEntries()          → number
 */

const { getDb } = require('../database');

const VALID_SOURCES = ['bundled', 'user', 'cloud'];

/**
 * Return all whitelist rows.
 * When `query` is provided, filter rows where `name` or `vendor` contains
 * the query string (case-insensitive LIKE match).
 *
 * @param {string} [query] - Optional search term
 * @returns {Array<Object>} Array of whitelist row objects
 */
function listEntries(query) {
  const db = getDb();

  if (query !== undefined && query !== null && query !== '') {
    // Escape LIKE special characters (%, _, \) so the query is treated as a
    // literal substring and not a wildcard pattern.
    const escaped = query.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
    const stmt = db.prepare(
      `SELECT hash, name, vendor, verified, source, created_at
       FROM whitelist
       WHERE name   LIKE '%' || ? || '%' ESCAPE '\\'
          OR vendor LIKE '%' || ? || '%' ESCAPE '\\'`
    );
    return stmt.all(escaped, escaped);
  }

  return db.prepare(
    'SELECT hash, name, vendor, verified, source, created_at FROM whitelist'
  ).all();
}

/**
 * Insert a new whitelist entry.
 * Uses INSERT OR IGNORE so that duplicate hashes are silently skipped
 * (the caller can detect the no-op by checking `changes` if needed).
 *
 * @param {Object} entry
 * @param {string} entry.hash     - 64-char hex SHA-256 digest
 * @param {string} entry.name     - Human-readable tool name
 * @param {string} [entry.vendor] - Vendor / publisher name (default '')
 * @param {string} entry.source   - One of 'bundled' | 'user' | 'cloud'
 * @param {number} [entry.verified] - 1 = verified, 0 = unverified (default 0)
 * @throws {Error} If `source` is not one of the three allowed values
 */
function insertEntry({ hash, name, vendor = '', source, verified = 0 }) {
  if (!VALID_SOURCES.includes(source)) {
    throw new Error(
      `Invalid source "${source}". Must be one of: ${VALID_SOURCES.join(', ')}.`
    );
  }

  const db = getDb();
  db.prepare(
    `INSERT OR IGNORE INTO whitelist (hash, name, vendor, verified, source)
     VALUES (?, ?, ?, ?, ?)`
  ).run(hash, name, vendor, verified ? 1 : 0, source);
}

/**
 * Delete a whitelist entry — but only when its source is 'user'.
 * Pre-built ('bundled') and cloud-synced ('cloud') entries are protected.
 *
 * @param {string} hash - SHA-256 hex digest of the entry to remove
 * @returns {{ success: boolean, forbidden?: boolean }}
 *   - `{ success: true }` when the row was deleted
 *   - `{ success: false, forbidden: true }` when source ≠ 'user'
 *   - `{ success: false }` when no row with that hash exists
 */
function deleteEntry(hash) {
  const db = getDb();

  const row = db.prepare('SELECT source FROM whitelist WHERE hash = ?').get(hash);

  if (!row) {
    // No entry with this hash — nothing to delete
    return { success: false };
  }

  if (row.source !== 'user') {
    return { success: false, forbidden: true };
  }

  db.prepare('DELETE FROM whitelist WHERE hash = ?').run(hash);
  return { success: true };
}

/**
 * Check whether a hash is already present in the whitelist.
 *
 * @param {string} hash - SHA-256 hex digest
 * @returns {boolean}
 */
function entryExists(hash) {
  const db = getDb();
  const row = db.prepare('SELECT 1 FROM whitelist WHERE hash = ?').get(hash);
  return row !== undefined;
}

/**
 * Bulk upsert cloud-sourced entries using a single transaction.
 * Each entry in `entries` must have source !== 'user' — rows whose
 * source in the entries array is 'user' are silently skipped to
 * prevent cloud data from overwriting user-managed entries.
 *
 * Existing user-source rows in the database are never touched,
 * because INSERT OR REPLACE only fires when the primary key (hash)
 * matches — and we skip entries explicitly flagged as 'user'.
 *
 * @param {Array<Object>} entries - Array of entry objects with at minimum
 *   { hash, name, vendor, verified, source }
 */
function upsertCloudEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) return;

  const db = getDb();

  const upsert = db.prepare(
    `INSERT OR REPLACE INTO whitelist (hash, name, vendor, verified, source)
     VALUES (?, ?, ?, ?, ?)`
  );

  const runAll = db.transaction((rows) => {
    for (const entry of rows) {
      // Never allow this bulk operation to touch user-source entries
      if (entry.source === 'user') continue;

      // Also skip any entry that already exists with source='user' in the DB
      const existing = db
        .prepare('SELECT source FROM whitelist WHERE hash = ?')
        .get(entry.hash);
      if (existing && existing.source === 'user') continue;

      upsert.run(
        entry.hash,
        entry.name,
        entry.vendor || '',
        entry.verified ? 1 : 0,
        entry.source || 'cloud'
      );
    }
  });

  runAll(entries);
}

/**
 * Return the number of rows in the whitelist with source = 'user'.
 *
 * @returns {number}
 */
function countUserEntries() {
  const db = getDb();
  const row = db
    .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'user'")
    .get();
  return row.cnt;
}

module.exports = {
  listEntries,
  insertEntry,
  deleteEntry,
  entryExists,
  upsertCloudEntries,
  countUserEntries,
};
