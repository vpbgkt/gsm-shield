/**
 * backend/server.js
 *
 * GSM Shield AV — Express application entry point.
 *
 * Responsibilities:
 *   - Create and configure the Express app
 *   - Mount global middleware (JSON body parser, CORS)
 *   - Mount route modules for /whitelist and /submissions
 *   - Provide a /health check endpoint
 *   - Handle 404 (not found) responses
 *   - Handle global errors (log + 500 JSON response)
 *   - Export `app` for testing and start the HTTP server when run directly
 *
 * Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 25.1, 25.4
 */

'use strict';

const express = require('express');
const cors    = require('cors');

// ---------------------------------------------------------------------------
// CORS configuration
// ---------------------------------------------------------------------------

/**
 * In development (NODE_ENV !== 'production') all origins are allowed.
 * In production, only origins listed in the ALLOWED_ORIGINS environment
 * variable (comma-separated) are permitted.
 *
 * Example: ALLOWED_ORIGINS=https://app.gsmshield.io,https://admin.gsmshield.io
 */
function buildCorsOptions() {
  if (process.env.NODE_ENV !== 'production') {
    return { origin: true }; // reflect any origin in dev
  }

  const raw = process.env.ALLOWED_ORIGINS || '';
  const allowed = raw
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  if (allowed.length === 0) {
    console.warn(
      '[server] WARNING: NODE_ENV=production but ALLOWED_ORIGINS is not set. ' +
      'All cross-origin requests will be blocked.'
    );
    return { origin: false };
  }

  return {
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. server-to-server, curl)
      if (!origin || allowed.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: origin '${origin}' is not allowed`));
      }
    },
  };
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();

// Parse incoming JSON bodies
app.use(express.json());

// Apply CORS middleware
app.use(cors(buildCorsOptions()));

// ---------------------------------------------------------------------------
// Health-check route
// ---------------------------------------------------------------------------

/**
 * GET /health
 * Used by Railway.app health checks and uptime monitors.
 * Returns: { status: 'ok', timestamp: <ISO string> }
 */
app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// Feature routes
// ---------------------------------------------------------------------------

// GET /whitelist  — returns verified cloud_whitelist entries (task 16.2)
app.use('/whitelist', require('./routes/whitelist'));

// POST /submissions — accepts community tool submissions (task 16.3)
app.use('/submissions', require('./routes/submissions'));

// ---------------------------------------------------------------------------
// 404 handler — must come after all routes
// ---------------------------------------------------------------------------

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ---------------------------------------------------------------------------
// Global error handler — must be defined with 4 parameters
// ---------------------------------------------------------------------------

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start listening when this file is run directly (not required as a module)
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[server] GSM Shield AV backend listening on port ${PORT}`);
    console.log(`[server] NODE_ENV=${process.env.NODE_ENV || 'development'}`);
  });
}

// Export app so tests can require it without side-effects
module.exports = app;
