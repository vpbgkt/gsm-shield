/**
 * backend/__tests__/routes.edge.test.js
 *
 * Edge-case integration tests for the GSM Shield AV Express backend.
 * Uses supertest to drive HTTP requests and mocks the DB pool so no
 * real PostgreSQL connection is required.
 *
 * Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 25.1, 25.4
 */

'use strict';

// Mock the DB module before requiring app so routes get the mock pool
jest.mock('../db', () => ({ pool: { query: jest.fn() } }));

const request = require('supertest');
const app     = require('../server');
const { pool } = require('../db');

const VALID_HASH = 'a'.repeat(64); // 64 lowercase hex chars — valid SHA-256

beforeEach(() => {
  // Reset all mock state between tests
  jest.clearAllMocks();
  // Set API key env var so auth passes
  process.env.API_KEY = 'test-key';
});

// ---------------------------------------------------------------------------
// Helper: auth header with the test key
// ---------------------------------------------------------------------------
function authHeader() {
  return { Authorization: 'Bearer test-key' };
}

// ===========================================================================
// GET /whitelist
// ===========================================================================

describe('GET /whitelist', () => {
  it('1. returns 200 with empty array when DB has no rows', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });

    const res = await request(app)
      .get('/whitelist')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it('2. returns 500 with Database error when DB throws', async () => {
    pool.query.mockRejectedValueOnce(new Error('connection refused'));

    const res = await request(app)
      .get('/whitelist')
      .set(authHeader());

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Database error' });
  });
});

// ===========================================================================
// GET /health
// ===========================================================================

describe('GET /health', () => {
  it('3. returns 200 with status ok and a timestamp string', async () => {
    const res = await request(app).get('/health');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(typeof res.body.timestamp).toBe('string');
    // Confirm it is a valid ISO-8601 date string
    expect(isNaN(Date.parse(res.body.timestamp))).toBe(false);
  });
});

// ===========================================================================
// GET /unknown (404 handler)
// ===========================================================================

describe('Unknown route', () => {
  it('4. returns 404 with Not found for an unrecognised path', async () => {
    const res = await request(app).get('/unknown');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not found' });
  });
});

// ===========================================================================
// POST /submissions
// ===========================================================================

describe('POST /submissions', () => {
  it('5. returns 409 duplicate_hash when DB raises unique-constraint violation (23505)', async () => {
    const pgError = Object.assign(new Error('duplicate key'), { code: '23505' });
    pool.query.mockRejectedValueOnce(pgError);

    const res = await request(app)
      .post('/submissions')
      .set(authHeader())
      .send({ hash: VALID_HASH, name: 'TestTool' });

    expect(res.status).toBe(409);
    expect(res.body).toEqual({ error: 'duplicate_hash' });
  });

  it('6. returns 500 Database error when DB throws a generic error', async () => {
    pool.query.mockRejectedValueOnce(new Error('generic db failure'));

    const res = await request(app)
      .post('/submissions')
      .set(authHeader())
      .send({ hash: VALID_HASH, name: 'TestTool' });

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Database error' });
  });

  it('7. returns 400 invalid_hash when no body is sent', async () => {
    const res = await request(app)
      .post('/submissions')
      .set(authHeader())
      .set('Content-Type', 'application/json')
      .send('{}');

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_hash' });
  });

  it('8. returns 400 invalid_hash when hash is uppercase (64 chars but not lowercase hex)', async () => {
    const res = await request(app)
      .post('/submissions')
      .set(authHeader())
      .send({ hash: 'A'.repeat(64), name: 'TestTool' });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_hash' });
  });

  it('9. returns 400 invalid_hash when hash is 63 chars (too short)', async () => {
    const res = await request(app)
      .post('/submissions')
      .set(authHeader())
      .send({ hash: 'a'.repeat(63), name: 'TestTool' });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_hash' });
  });

  it('10. returns 201 with success:true for a valid hash, name, and vendor', async () => {
    const fakeRow = {
      id: 1,
      hash: VALID_HASH,
      name: 'TestTool',
      vendor: 'Acme',
      status: 'pending',
      submitted_at: new Date().toISOString(),
    };
    pool.query.mockResolvedValueOnce({ rows: [fakeRow] });

    const res = await request(app)
      .post('/submissions')
      .set(authHeader())
      .send({ hash: VALID_HASH, name: 'TestTool', vendor: 'Acme' });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ success: true });
  });
});
