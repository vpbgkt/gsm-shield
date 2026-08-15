'use strict';

/**
 * electron/ipc/__tests__/hash-validator.property.test.js
 *
 * Property-based tests for the isValidSHA256 hash validator.
 *
 * Property 8: SHA-256 hash validation
 *   isValidSHA256(input) returns true iff input is exactly 64 chars
 *   and all characters are lowercase hex digits [0-9a-f].
 *   All other inputs return false.
 *
 * Validates: Requirements 5.4
 */

const fc = require('fast-check');
const { isValidSHA256 } = require('../whitelist-handlers');

// ─── Targeted example checks ─────────────────────────────────────────────────

describe('isValidSHA256 — targeted examples', () => {
  it('accepts 64 lowercase hex "a" chars', () => {
    expect(isValidSHA256('a'.repeat(64))).toBe(true);
  });

  it('accepts "0123456789abcdef" repeated 4 times (64 chars)', () => {
    expect(isValidSHA256('0123456789abcdef'.repeat(4))).toBe(true);
  });

  it('rejects 64 uppercase "A" chars', () => {
    expect(isValidSHA256('A'.repeat(64))).toBe(false);
  });

  it('rejects 63-char string', () => {
    expect(isValidSHA256('a'.repeat(63))).toBe(false);
  });

  it('rejects 65-char string', () => {
    expect(isValidSHA256('a'.repeat(65))).toBe(false);
  });

  it('rejects empty string', () => {
    expect(isValidSHA256('')).toBe(false);
  });
});

// ─── Property 8: SHA-256 hash validation ────────────────────────────────────
// Validates: Requirements 5.4

describe('isValidSHA256 — Property 8: SHA-256 hash validation', () => {
  /**
   * **Validates: Requirements 5.4**
   *
   * For any arbitrary string input, isValidSHA256 returns true if and only if
   * the string is exactly 64 characters long and every character is a lowercase
   * hex digit [0-9a-f]. Any other input must return false.
   */
  it('returns true iff input is exactly 64 lowercase hex chars, false for all others', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const expected =
          input.length === 64 && /^[0-9a-f]{64}$/.test(input);
        return isValidSHA256(input) === expected;
      }),
      { numRuns: 500 }
    );
  });
});
