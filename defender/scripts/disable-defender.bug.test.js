'use strict';

/**
 * defender/scripts/disable-defender.bug.test.js
 *
 * Bug Condition Exploration Test — disable-defender.ps1 logic (dry-run / static analysis)
 *
 * **CRITICAL**: These tests MUST FAIL on unfixed code — failure confirms the bug exists.
 * **DO NOT attempt to fix the tests or the code when they fail.**
 * **NOTE**: These tests encode the EXPECTED (fixed) behavior — they will validate the
 *           fix when they pass after implementation (tasks 3.1 / 3.2 / 3.5).
 *
 * WHY STATIC ANALYSIS (not real execution): running `disable-defender.ps1` mutates the
 * host's real Windows Defender state and requires SYSTEM/TrustedInstaller elevation. Per
 * the design "Testing Strategy", the privileged registry writes are covered by manual/VM
 * integration checks; the CI-safe check here is a logic/dry-run analysis of the script's
 * disable path. Each assertion encodes an Expected Behavior from the design, so it fails
 * on the current (unfixed) script and passes once the fix lands.
 *
 * Bug condition (design isBugCondition):
 *   disablesWinDefendAsPlainAdmin OR reliesOnSetMpPreferenceOnly OR writesDisableAntiSpyware
 *   OR (tamperProtectionOn AND NOT blocksOnTamper) → resultLeavesDefenderActive
 *
 * **Validates: Requirements 1.1, 1.2, 1.4, 1.5, 1.6**
 */

const fs = require('fs');
const path = require('path');
const fc = require('fast-check');

const SCRIPT_PATH = path.join(__dirname, 'disable-defender.ps1');
const SCRIPT = fs.readFileSync(SCRIPT_PATH, 'utf8');

/** The block that permanently disables the WinDefend service (Step 3 region). */
function winDefendDisableRegion(content) {
  const start = content.search(/Step 3[\s\S]*?Disabling Defender services/i);
  return start === -1 ? content : content.slice(start);
}

describe('Bug Condition: disable-defender.ps1 disable path (dry-run/static logic)', () => {
  // ── Counterexample 1.5: deprecated DisableAntiSpyware policy is written ──────
  it('BUG 1.5: disable path must NOT write or depend on DisableAntiSpyware', () => {
    const writesDisableAntiSpyware = /DisableAntiSpyware/.test(SCRIPT);

    // eslint-disable-next-line no-console
    console.log('\n=== Counterexample 1.5: DisableAntiSpyware written ===');
    console.log(`Script writes DisableAntiSpyware: ${writesDisableAntiSpyware}`);
    console.log('EXPECTED (fixed): the deprecated (ignored since Win10 2004) policy is removed.');

    // Fixed code removes this write. Unfixed contains it → FAILS.
    expect(writesDisableAntiSpyware).toBe(false);
  });

  // ── Counterexample 1.4: Tamper Protection only warned, not blocked ───────────
  it('BUG 1.4: Tamper Protection must gate/block the disable with a distinct exit code', () => {
    const continuesOnTamper = /Continuing anyway/i.test(SCRIPT);
    // Fixed code exits with a distinct "tamper-blocked" code (design: 2).
    const hasTamperBlockedExit = /IsTamperProtected[\s\S]*?exit\s+2\b/i.test(SCRIPT) || /tamper-blocked/i.test(SCRIPT);

    // eslint-disable-next-line no-console
    console.log('\n=== Counterexample 1.4: Tamper Protection not blocked ===');
    console.log(`Script warns then continues on Tamper Protection: ${continuesOnTamper}`);
    console.log(`Script has a distinct tamper-blocked exit gate: ${hasTamperBlockedExit}`);
    console.log('EXPECTED (fixed): tamper ON → print settings path and exit 2 without disabling.');

    // Fixed code blocks on tamper and does not "continue anyway".
    expect(continuesOnTamper).toBe(false);
    expect(hasTamperBlockedExit).toBe(true);
  });

  // ── Counterexample 1.1/1.2: WinDefend disabled as plain Admin, not elevated ──
  it('BUG 1.1/1.2: WinDefend Start=4 must be set via SYSTEM/TrustedInstaller elevation', () => {
    const region = winDefendDisableRegion(SCRIPT);
    const elevatesToSystem =
      /NT AUTHORITY\\SYSTEM/i.test(region) ||
      /Register-ScheduledTask/i.test(region) ||
      /TrustedInstaller/i.test(region) ||
      /takeown/i.test(region) ||
      /New-ScheduledTask/i.test(region);

    // eslint-disable-next-line no-console
    console.log('\n=== Counterexample 1.1/1.2: WinDefend disabled as plain Administrator ===');
    console.log(`Disable region elevates to SYSTEM/TrustedInstaller: ${elevatesToSystem}`);
    console.log('EXPECTED (fixed): elevate Admin → SYSTEM/TrustedInstaller, take ownership, set Start=4.');

    // Unfixed uses a plain `Set-ItemProperty ... WinDefend Start 4` (Access Denied) → FAILS.
    expect(elevatesToSystem).toBe(true);
  });

  // ── Counterexample 1.1/1.2/1.6: no verification that Start actually became 4 ─
  it('BUG 1.1/1.2/1.6: disable must verify WinDefend Start=4 (read-back) before success', () => {
    // Fixed code re-reads Start and compares to 4 after attempting the disable.
    const verifiesStart =
      /Get-ItemProperty[\s\S]*?Start[\s\S]*?(-eq\s*4|-eq\s*"?4"?)/i.test(SCRIPT) ||
      /Start[\s\S]{0,120}-eq\s*4/i.test(SCRIPT);

    // eslint-disable-next-line no-console
    console.log('\n=== Counterexample 1.1/1.2/1.6: Start=4 not verified ===');
    console.log(`Script verifies WinDefend Start == 4 after disable: ${verifiesStart}`);
    console.log('EXPECTED (fixed): read back Start and confirm it equals 4 before reporting success.');

    // Unfixed sets Start without any read-back verification → FAILS.
    expect(verifiesStart).toBe(true);
  });

  // ── Counterexample 1.6: exit 0 on mere partial success masks Defender-active ─
  it('BUG 1.6: success (exit 0) must not be returned on unverified/partial disable', () => {
    const masksPartialSuccessAsExit0 = /Exit 0 even on partial success/i.test(SCRIPT);

    // eslint-disable-next-line no-console
    console.log('\n=== Counterexample 1.6: exit 0 on partial success ===');
    console.log(`Script returns exit 0 on partial success (masks failure): ${masksPartialSuccessAsExit0}`);
    console.log('EXPECTED (fixed): exit 0 only when WinDefend Start=4 verified and tamper was off.');

    // Unfixed contains the "Exit 0 even on partial success" branch → FAILS.
    expect(masksPartialSuccessAsExit0).toBe(false);
  });

  // ── Property: across the setup input domain the bug condition holds ──────────
  it('BUG (property): for every in-scope setup phase/OS the unfixed disable path is buggy', () => {
    // The script content is fixed, so isBugCondition is deterministic across the
    // generated input domain; the property documents that the bug applies to ALL
    // in-scope phases and both OS versions.
    const writesDisableAntiSpyware = /DisableAntiSpyware/.test(SCRIPT);
    const continuesOnTamper = /Continuing anyway/i.test(SCRIPT);
    const region = winDefendDisableRegion(SCRIPT);
    const disablesAsPlainAdmin =
      !/NT AUTHORITY\\SYSTEM|Register-ScheduledTask|TrustedInstaller|takeown|New-ScheduledTask/i.test(region);

    fc.assert(
      fc.property(
        fc.record({
          phase: fc.constantFrom('installer-setup', 'first-run', 'manual-runSetup'),
          osVersion: fc.constantFrom('Windows 10', 'Windows 11'),
          consentGiven: fc.boolean(),
          tamperProtectionOn: fc.boolean(),
        }),
        (input) => {
          const inScope = ['installer-setup', 'first-run', 'manual-runSetup'].includes(input.phase);
          const isBugCondition =
            inScope &&
            (disablesAsPlainAdmin ||
              writesDisableAntiSpyware ||
              (input.tamperProtectionOn && continuesOnTamper));

          // EXPECTED (fixed): the bug condition never holds. On unfixed code it
          // holds for every in-scope input → property FAILS.
          expect(isBugCondition).toBe(false);
        }
      ),
      { numRuns: 24 }
    );
  });
});
