'use strict';

/**
 * database/index.js
 *
 * Main entry point for the database layer.
 * Re-exports all public symbols from database/init.js so that the rest of
 * the application imports from this single path rather than reaching into
 * init.js directly.
 *
 *   const { initDatabase, getDb, closeDatabase, runMigrations } = require('./database');
 */

const {
  initDatabase,
  getDb,
  closeDatabase,
  runMigrations,
  ensureQuarantineDir,
  MIGRATIONS,
} = require('./init');

module.exports = {
  initDatabase,
  getDb,
  closeDatabase,
  runMigrations,
  ensureQuarantineDir,
  MIGRATIONS,
};
