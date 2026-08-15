/**
 * backend/routes/whitelist.js
 *
 * GET /whitelist — returns all verified entries from cloud_whitelist.
 *
 * Auth:    Authorization: Bearer <API_KEY> header required.
 *          Validates against process.env.API_KEY.
 *          Returns 401 if header is missing or the key does not match.
 *
 * Query:   SELECT hash, name, vendor, verified, source
 *          FROM cloud_whitelist
 *          WHERE status = 'verified'
 *          ORDER BY name
 *
 * Success: 200 — JSON array of { hash, name, vendor, verified, source }
 * DB error: 500 — { error: 'Database error' }
 *
 * Requirements: 24.1, 24.2, 25.1
 */

'use strict';

const { Router } = require('express');
const { pool }   = require('../db');

const router = Router();

// ---------------------------------------------------------------------------
// GET /whitelist
// ---------------------------------------------------------------------------

router.get('/', async (req, res) => {
  // --- Authentication ---
  const authHeader = req.headers['authorization'] || '';
  const token      = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)   // trim the "Bearer " prefix
    : null;

  if (!token || token !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // --- Database query ---
  const sql = `
    SELECT hash, name, vendor, verified, source
    FROM cloud_whitelist
    WHERE status = $1
    ORDER BY name
  `;

  try {
    const result = await pool.query(sql, ['verified']);
    return res.status(200).json(result.rows);
  } catch (err) {
    console.error('[whitelist] Database error on GET /whitelist:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

module.exports = router;
