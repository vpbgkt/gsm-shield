'use strict';

/**
 * defender/ps-runner.property.test.js
 *
 * PRESERVATION property tests (Property 2 / design Property 3) — written BEFORE the fix.
 *
 * **METHODOLOGY**: Observation-first. These properties capture the CURRENT (unfixed)
 * behavior of `defender/ps-runner.js` so they PASS on unfixed code and act as a
 * regression guard: the ps-runner contract must remain unchanged after the fix.
 *
 * Preservation requirement 3.3 (bugfix.md):
 *   "WHEN a PowerShell setup step encounters an error THEN the ps-runner SHALL
 *    CONTINUE TO run without throwing, logging the error and allowing remaining
 *    steps to proceed."
 *
 * Observed contract on unfixed code:
 *   - For ANY script path, params, and exit code, runScript() ALWAYS resolves
 *     (never rejects/throws) to an object `{ exitCode, stdout, stderr }`.
 *   - The three fields are always present with the expected primitive types.
 *   - A script that `exit N` resolves with `exitCode === N`.
 *   - Invalid/empty/null script paths resolve to `{ exitCode: -1, ... }` with a
 *     non-empty stderr — never a throw.
 *
 * **Validates: Requirements 3.3**
 */

const { runScript } = require('./ps-runner');
const fs = require('fs');
const path = require('path');
const os = require('os');
const fc = require('fast-check');

describe('Preservation: ps-runner non-throwing contract (Requirement 3.3)', () => {
  let tempDir;
  const created = [];

  beforeAll(() => {
    tempDir = path.join(os.tmpdir(), `ps-runner-prop-${Date.now()}`);
    fs.mkdirSync(tempDir, { recursive: true });
  });

  afterAll(() => {
    created.forEach((p) => {
      try {
        if (fs.existsSync(p)) fs.unlinkSync(p);
      } catch (_) {
        /* ignore */
      }
    });
    try {
      if (fs.existsSync(tempDir)) fs.rmdirSync(tempDir);
    } catch (_) {
      /* ignore */
    }
  });

  /** Write a temp .ps1 that emits some output and exits with the given code. */
  function writeScript(exitCode, message) {
    const name = `gen-${Math.random().toString(36).slice(2)}.ps1`;
    const scriptPath = path.join(tempDir, name);
    // Message is embedded as a literal single-quoted PowerShell string; escape single quotes.
    const safeMsg = String(message).replace(/'/g, "''");
    const body = [
      `Write-Output '${safeMsg}'`,
      `exit ${exitCode}`,
    ].join('\n');
    fs.writeFileSync(scriptPath, body, 'utf8');
    created.push(scriptPath);
    return scriptPath;
  }

  /** Shape assertion shared by every case. */
  function assertResultShape(result) {
    expect(result).toBeDefined();
    expect(result).toHaveProperty('exitCode');
    expect(result).toHaveProperty('stdout');
    expect(result).toHaveProperty('stderr');
    expect(typeof result.exitCode).toBe('number');
    expect(typeof result.stdout).toBe('string');
    expect(typeof result.stderr).toBe('string');
  }

  it('PRESERVE 3.3: resolves without throwing for arbitrary exit codes and messages', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Exit codes across the realistic range (incl. the future tamper-blocked 2).
        fc.integer({ min: 0, max: 255 }),
        // Arbitrary output content (ASCII-safe to keep the generated script valid).
        fc.string({ maxLength: 40 }).filter((s) => !/[\r\n`]/.test(s)),
        async (exitCode, message) => {
          const scriptPath = writeScript(exitCode, message);

          // Must never throw — always resolves.
          const result = await runScript(scriptPath);

          assertResultShape(result);
          // Observed: exit N is faithfully propagated.
          expect(result.exitCode).toBe(exitCode);
        }
      ),
      { numRuns: 20 }
    );
  }, 120000);

  it('PRESERVE 3.3: resolves without throwing for arbitrary extra params', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.string({ maxLength: 12 }).filter((s) => !/[\r\n"`]/.test(s)),
          { maxLength: 4 }
        ),
        async (params) => {
          const scriptPath = writeScript(0, 'params-test');

          const result = await runScript(scriptPath, params);

          assertResultShape(result);
          // Passing arbitrary params never causes a throw; script still exits 0.
          expect(result.exitCode).toBe(0);
        }
      ),
      { numRuns: 15 }
    );
  }, 120000);

  it('PRESERVE 3.3: resolves (never throws) for invalid / non-string script paths', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.constant(''),
          fc.constant(null),
          fc.constant(undefined),
          fc.integer(),
          fc.boolean(),
          fc.constant({})
        ),
        async (badPath) => {
          // Must resolve, not reject.
          const result = await runScript(badPath);

          assertResultShape(result);
          // Observed baseline: invalid path → exitCode -1 with a non-empty stderr.
          expect(result.exitCode).toBe(-1);
          expect(result.stderr.length).toBeGreaterThan(0);
        }
      ),
      { numRuns: 20 }
    );
  }, 30000);

  it('PRESERVE 3.3: resolves (never throws) for non-existent script files', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 20 }).filter((s) => !/[\r\n"'`<>:|?*]/.test(s)),
        async (name) => {
          const missing = path.join(tempDir, `missing-${name}.ps1`);

          const result = await runScript(missing);

          assertResultShape(result);
          // Observed: a missing file resolves with a non-zero exit code.
          expect(result.exitCode).not.toBe(0);
        }
      ),
      { numRuns: 15 }
    );
  }, 60000);
});
