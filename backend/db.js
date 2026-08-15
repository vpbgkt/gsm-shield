/**
 * backend/db.js
 *
 * Exports a pg Pool connected via DATABASE_URL environment variable.
 * Import `pool` wherever you need to query PostgreSQL.
 */

'use strict';

const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.warn(
    '[db] WARNING: DATABASE_URL is not set. ' +
    'Database queries will fail until a connection string is provided.'
  );
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Railway.app uses TLS by default; allow it without strict cert verification
  // in non-production environments when PGSSLMODE is not explicitly set.
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true }
    : process.env.DATABASE_URL && process.env.DATABASE_URL.includes('sslmode=disable')
      ? false
      : { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('[db] Unexpected error on idle PostgreSQL client:', err.message);
});

module.exports = { pool };
