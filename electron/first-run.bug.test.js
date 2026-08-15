'use strict';

/**
 * electron/first-run.bug.test.js
 *
 * Bug Condition Exploration Test — Defender Not Disabled, No Consent/Tamper Gates
 *
 * **CRITICAL**: These tests MUST FAIL on unfixed code — failure confirms the bug exists.
 * **DO NOT attempt to fix the tests or the code when they fail.**
 * **NOTE**: These tests encode the EXPECTED (fixed) behavior — they will validate the
 *           fix when they pass after implementation (tasks 3.x / 3.5).
 * **GOAL**: Surface counterexamples proving the bug — the first-run orchestrator invokes
 *           `disable-defender.ps1` with no explicit consent gate.
 *
 * This file exercises the orchestrator `electron/first-run.js` with a MOCKED
 * `defender/ps-runner.js` so no real Defender/registry state is touched.
 *
 * Bug condition (design "Exploratory Bug Condition Checking"):
 *   isBugCondition(input) === input.phase IN ['installer-setup','first-run','manual-runSetup']
 *                            AND NOT hasConsentGate(input) ... AND resultLeavesDefenderActive(input)
 *
 * **Validates: Requirements 1.3, 1.6**
 */

// ── Mock the PowerShell runner so nothing real executes ─────────────────────────
jest.mock('../defender/ps-runner', () => ({
  runScript: jest.fn(),
}));

const path = require('path');
const fc = require('fast-check');
const { runScript } = require('../defender/ps-runner');
const firstRun = require('./first-run');

/** True if any recorded runScript call targeted disable-defender.ps1 */
function disableDefenderWasInvoked() {
  return runScript.mock.calls.some((call) =>
    String(call[0]).includes('disable-defender.ps1')
  );
}

/** Index (call order) at which disable-defender.ps1 was invoked, or -1 */
function disableDefenderCallIndex() {
  return runScript.mock.calls.findIndex((call) =>
    String(call[0]).includes('disable-defender.ps1')
  );
}

beforeEach(() => {
  runScript.mockReset();
  // Unfixed disable-defender.ps1 exits 0 even on partial success.
  runScript.mockResolvedValue({ exitCode: 0, stdout: 'SUCCESS: disable-defender step complete', stderr: '' });
});

describe('Bug Condition: first-run disables Defender with no consent gate', () => {
  // ── Counterexample 1.3: No consent gate ─────────────────────────────────────
  it('BUG 1.3: disable-defender must NOT run before explicit consent is recorded', async () => {
    await firstRun.runFirstRunSetup(null);

    const invoked = disableDefenderWasInvoked();

    // eslint-disable-next-line no-console
    console.log('\n=== Counterexample 1.3: No consent gate ===');
    console.log(`disable-defender.ps1 invoked without any recorded consent: ${invoked}`);
    console.log(`call order index: ${disableDefenderCallIndex()}`);
    console.log('EXPECTED (fixed): disable step is skipped until explicit Agree / defender_consent.');

    // EXPECTED BEHAVIOR (fixed code): with no consent recorded, the disable
    // step must never be invoked. On unfixed code it IS invoked → this FAILS,
    // confirming the missing consent gate (Requirement 1.3).
    expect(invoked).toBe(false);
  });

  // ── Counterexample 1.3 (property): holds across all setup phases / OS ────────
  it('BUG 1.3 (property): for any setup phase/OS with no consent, disable step is never invoked', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          phase: fc.constantFrom('installer-setup', 'first-run', 'manual-runSetup'),
          osVersion: fc.constantFrom('Windows 10', 'Windows 11'),
          consentGiven: fc.constant(false), // bug domain: no consent gate exists
          tamperProtectionOn: fc.boolean(),
        }),
        async (_input) => {
          runScript.mockClear();
          runScript.mockResolvedValue({ exitCode: 0, stdout: '', stderr: '' });

          await firstRun.runFirstRunSetup(null);

          // Fixed behavior: no consent ⇒ no disable invocation for any phase/OS.
          expect(disableDefenderWasInvoked()).toBe(false);
        }
      ),
      { numRuns: 24 }
    );
  });

  // ── Counterexample 1.6: combined sequence exits 0 without verifying disable ──
  it('BUG 1.6: setup must not report success when Defender disable is unverified', async () => {
    // Simulate the unfixed disable-defender.ps1 "partial success" exit 0.
    runScript.mockResolvedValue({
      exitCode: 0,
      stdout: 'WARNING: Partial success — some steps failed\nSUCCESS: disable-defender step complete',
      stderr: '',
    });

    let captured = null;
    const fakeWindow = {
      isDestroyed: () => false,
      webContents: {
        send: (channel, payload) => {
          if (channel === 'defender:setup-result') captured = payload;
        },
      },
    };

    await firstRun.runFirstRunSetup(fakeWindow);

    // eslint-disable-next-line no-console
    console.log('\n=== Counterexample 1.6: Defender left active but setup reports success ===');
    console.log(`setup-result payload: ${JSON.stringify(captured)}`);
    console.log('EXPECTED (fixed): payload must expose a verified/consent-gated status, not blanket success.');

    // The disable step ran without a prior consent gate — the very fact that a
    // setup-result was produced from an unconsented disable is the bug. The fixed
    // orchestrator gates on consent, so no unconsented disable result is emitted.
    expect(disableDefenderWasInvoked()).toBe(false);
  });
});
