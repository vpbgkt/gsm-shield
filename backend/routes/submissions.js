/**
 * backend/routes/submissions.js
 *
 * POST /submissions — accepts a community tool submission.
 *
 * Auth:    Authorization: Bearer <API_KEY> header required.
 *          Validates against process.env.API_KEY.
 *          Returns 401 if header is missing or the key does not match.
 *
 * Body:    { hash, name, vendor? }
 *   - hash:   required, exactly 64 lowercase hex chars
 *   - name:   required, non-empty string
 *   - vendor: optional string, defaults to ''
 *
 * Insert:
 *   INSERT INTO submissions (hash, name, vendor, status)
 *   VALUES ($1, $2, $3, 'pending')
 *   RETURNING id, hash, name, vendor, status, submitted_at
 *
 * Success:         201 — { success: true, submission: <row> }
 * Missing/bad auth: 401 — { error: 'Unauthorized' }
 * Invalid hash:    400 — { error: 'invalid_hash' }
 * Missing name:    400 — { error: 'name_required' }
 * Duplicate hash:  409 — { error: 'duplicate_hash' }
 * DB error:        500 — { error: 'Database error' }
 *
 * Requirements: 24.3, 25.4
 */

'use strict';

const { Router } = require('express');
const { pool }   = require('../db');

const router = Router();

// Regex for a valid SHA-256 hex digest: exactly 64 lowercase hex characters
const HASH_RE = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// POST /submissions
// ---------------------------------------------------------------------------

router.post('/', async (req, res) => {
  // --- Authentication ---
  const authHeader = req.headers['authorization'] || '';
  const token      = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)   // trim the "Bearer " prefix
    : null;

  if (!token || token !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // --- Body validation ---
  const { hash, name, vendor = '' } = req.body || {};

  // hash: required, must be exactly 64 lowercase hex chars
  if (!hash || !HASH_RE.test(hash)) {
    return res.status(400).json({ error: 'invalid_hash' });
  }

  // name: required, non-empty string
  if (!name || typeof name !== 'string' || name.trim() === '') {
    return res.status(400).json({ error: 'name_required' });
  }

  // --- Database insert ---
  const sql = `
    INSERT INTO submissions (hash, name, vendor, status)
    VALUES ($1, $2, $3, 'pending')
    RETURNING id, hash, name, vendor, status, submitted_at
  `;

  try {
    const result = await pool.query(sql, [hash, name, typeof vendor === 'string' ? vendor : '']);
    return res.status(201).json({ success: true, submission: result.rows[0] });
  } catch (err) {
    // PostgreSQL unique constraint violation error code: 23505
    if (err.code === '23505') {
      return res.status(409).json({ error: 'duplicate_hash' });
    }
    console.error('[submissions] Database error on POST /submissions:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

module.exports = router;
