/**
 * backend/__tests__/routes.property.test.js
 *
 * Property-based tests for GSM Shield AV backend routes.
 *
 * Property 17 — Validates: Requirements 24.1
 *   Any GET /whitelist without a valid `Authorization: Bearer test-key` → 401.
 *   A valid key → NOT 401.
 *
 * Property 18 — Validates: Requirements 24.3
 *   POST /submissions with valid auth + arbitrary hash string → 400 `{error:'invalid_hash'}`
 *   iff hash is NOT exactly 64 lowercase hex chars.
 *   A valid 64-char lowercase hex hash → NOT 400/invalid_hash.
 *
 * Property 19 — Validates: Requirements 25.4
 *   POST /submissions with valid auth + valid hash + arbitrary name → 400 `{error:'name_required'}`
 *   iff name is empty/blank. Non-empty name → NOT 400/name_required.
 */

'use strict';

// Mock the database module before requiring the server so no real DB connection
// is attempted during tests.
jest.mock('../db', () => ({ pool: { query: jest.fn() } }));

const fc      = require('fast-check');
const request = require('supertest');
const app     = require('../server');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A valid 64-char lowercase hex string (SHA-256 digest shape). */
const validHash = 'a'.repeat(64);

/** Build auth header for the current API_KEY. */
const bearerHeader = (key) => `Bearer ${key}`;

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  // Set the API key the routes validate against.
  process.env.API_KEY = 'test-key';

  // Default DB mock: return a well-formed row so the happy path succeeds.
  require('../db').pool.query.mockResolvedValue({
    rows: [
      {
        id: 1,
        hash: validHash,
        name: 'T',
        vendor: '',
        status: 'pending',
        submitted_at: new Date().toISOString(),
      },
    ],
  });
});

// ---------------------------------------------------------------------------
// Property 17 — GET /whitelist authentication
// ---------------------------------------------------------------------------

describe('Property 17: GET /whitelist authentication', () => {
  /**
   * For ANY string token that is NOT equal to the API key, the response
   * status must be 401.
   */
  test('invalid / missing token → 401', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string(), async (token) => {
        // Skip the one value that would make auth pass.
        fc.pre(token !== 'test-key');

        const res = await request(app)
          .get('/whitelist')
          .set('Authorization', bearerHeader(token));

        expect(res.status).toBe(401);
      }),
      { numRuns: 100 }
    );
  });

  /**
   * The correct Bearer token must NOT return 401.
   */
  test('valid token → NOT 401', async () => {
    const res = await request(app)
      .get('/whitelist')
      .set('Authorization', `Bearer test-key`);

    expect(res.status).not.toBe(401);
  });

  /**
   * A request with no Authorization header must return 401.
   */
  test('no Authorization header → 401', async () => {
    const res = await request(app).get('/whitelist');
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Property 18 — POST /submissions hash validation
// ---------------------------------------------------------------------------

describe('Property 18: POST /submissions hash validation', () => {
  const VALID_HASH_RE = /^[0-9a-f]{64}$/;

  /**
   * For any string hash that does NOT match the 64-char lowercase hex pattern,
   * the route must respond with 400 { error: 'invalid_hash' }.
   */
  test('non-valid hash → 400 invalid_hash', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string(), async (hash) => {
        fc.pre(!VALID_HASH_RE.test(hash));

        const res = await request(app)
          .post('/submissions')
          .set('Authorization', `Bearer test-key`)
          .send({ hash, name: 'SomeTool' });

        expect(res.status).toBe(400);
        expect(res.body).toEqual({ error: 'invalid_hash' });
      }),
      { numRuns: 100 }
    );
  });

  /**
   * A valid 64-char lowercase hex hash must NOT trigger 400 invalid_hash.
   */
  test('valid 64-char lowercase hex hash → NOT 400/invalid_hash', async () => {
    // Generate a proper 64-char lowercase hex string via fast-check.
    await fc.assert(
      fc.asyncProperty(
        fc.stringOf(fc.constantFrom(...'0123456789abcdef'.split('')), { minLength: 64, maxLength: 64 }),
        async (hash) => {
          const res = await request(app)
            .post('/submissions')
            .set('Authorization', `Bearer test-key`)
            .send({ hash, name: 'SomeTool' });

          // Must NOT be 400 with invalid_hash
          const isInvalidHash =
            res.status === 400 && res.body && res.body.error === 'invalid_hash';
          expect(isInvalidHash).toBe(false);
        }
      ),
      { numRuns: 100 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 19 — POST /submissions name validation
// ---------------------------------------------------------------------------

describe('Property 19: POST /submissions name validation', () => {
  /**
   * An empty or whitespace-only name with a valid hash → 400 { error: 'name_required' }.
   */
  test('empty/blank name → 400 name_required', async () => {
    // Use fast-check to generate whitespace-only strings (including empty string).
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.constant(''),
          fc.stringOf(fc.constantFrom(' ', '\t', '\n', '\r'), { minLength: 1, maxLength: 20 })
        ),
        async (name) => {
          const res = await request(app)
            .post('/submissions')
            .set('Authorization', `Bearer test-key`)
            .send({ hash: validHash, name });

          expect(res.status).toBe(400);
          expect(res.body).toEqual({ error: 'name_required' });
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * A name with at least one non-whitespace character must NOT trigger
   * 400 name_required.
   */
  test('non-empty name → NOT 400/name_required', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate a string that has at least one non-whitespace character.
        fc.string({ minLength: 1 }).filter((s) => s.trim().length > 0),
        async (name) => {
          const res = await request(app)
            .post('/submissions')
            .set('Authorization', `Bearer test-key`)
            .send({ hash: validHash, name });

          const isNameRequired =
            res.status === 400 && res.body && res.body.error === 'name_required';
          expect(isNameRequired).toBe(false);
        }
      ),
      { numRuns: 100 }
    );
  });
});
