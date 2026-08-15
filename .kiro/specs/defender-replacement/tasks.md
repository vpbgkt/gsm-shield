# Implementation Plan

## Overview

This plan follows the exploratory bugfix workflow for the `defender-replacement` bug: Windows Defender is never effectively disabled after installing GSM Shield AV. Tests are written BEFORE the fix — a **Property 1: Bug Condition** exploration test (must FAIL on unfixed code) and **Property 2: Preservation** tests (must PASS on unfixed code) — then the fix is applied across `disable-defender.ps1`, `electron/first-run.js`, and the renderer, and both test sets are re-run to confirm the bug is fixed with no regressions.

## Tasks

- [x] 1. Write bug condition exploration tests
  - **Property 1: Bug Condition** - Defender Not Disabled, No Consent/Tamper Gates
  - **CRITICAL**: These tests MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the tests or the code when they fail**
  - **NOTE**: These tests encode the expected behavior - they will validate the fix when they pass after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists (root-cause confirmation from design "Exploratory Bug Condition Checking")
  - **Scoped PBT Approach**: For deterministic bugs, scope the property to the concrete failing cases below so they reproduce reliably. Use `fast-check` (`fc.asyncProperty`) where an input domain applies (e.g. varied `phase`, `osVersion`), and concrete cases where the bug is deterministic.
  - Create `electron/first-run.bug.test.js` (mock `defender/ps-runner.js`) and, where needed, a PowerShell dry-run/logic test alongside `defender/scripts/disable-defender.ps1`.
  - Encode `isBugCondition(input)` from design: `input.phase IN ['installer-setup','first-run','manual-runSetup']` AND the disable does not survive / no gates. Assertions should match the Expected Behavior in design (Property 1 and Property 2 of the design).
  - Test cases (assert against UNFIXED code):
    - **No consent gate (1.3)**: Drive `runFirstRunSetup` with a mocked ps-runner and assert the disable step (`disable-defender.ps1`) is invoked WITHOUT any prior explicit Agree / recorded `defender_consent`. Expected on fixed code: disable never runs before consent.
    - **Tamper not blocked (1.4)**: Simulate `IsTamperProtected = $true` and assert the unfixed script only warns and continues (does not exit with a distinct tamper-blocked code). Expected on fixed code: blocks with tamper-blocked exit.
    - **WinDefend Start not disabled (1.1, 1.2)**: Assert the unfixed disable path sets `WinDefend Start=4` as plain Administrator (no SYSTEM/TrustedInstaller elevation) so `Start` is not verified as `4` / write reports Access Denied, and relies on `Set-MpPreference` alone. Expected on fixed code: `Start=4` verified via SYSTEM/TrustedInstaller.
    - **DisableAntiSpyware present (1.5, edge)**: Assert the unfixed `disable-defender.ps1` writes `DisableAntiSpyware = 1`. Expected on fixed code: not written or depended upon.
    - **Defender left active (1.6)**: Assert that the combined unfixed sequence result leaves Defender as the active AV (exit-semantics / verification absent).
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests FAIL (this is correct - it proves the bug exists)
  - Document counterexamples found to understand root cause (e.g. "disable step invoked with no consent recorded", "IsTamperProtected=true path continues instead of blocking", "WinDefend Start != 4 after disable", "DisableAntiSpyware=1 written")
  - Mark task complete when tests are written, run, and failures are documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Restore, WSC, ps-runner, and First-Run Bookkeeping Unchanged
  - **IMPORTANT**: Follow observation-first methodology - run UNFIXED code first, record actual outputs, then assert them
  - Encode the non-bug domain from design Property 3: `NOT isBugCondition(input)` — uninstall/restore, WSC registration, arbitrary ps-runner invocations, and already-completed first-run launches.
  - Observe behavior on UNFIXED code and capture it:
    - **ps-runner non-throwing (3.3)**: Observe that arbitrary script paths, params, and exit codes resolve to `{ exitCode, stdout, stderr }` without throwing. Extend/keep `defender/ps-runner.test.js` coverage.
    - **First-run skip (3.5)**: Observe that with `first_run_complete = '1'` the disable/consent steps are skipped on subsequent launches.
    - **defender:runSetup re-trigger (3.4)**: Observe that the IPC handler re-runs setup and that `first_run_complete='1'` is set and `defender:setup-result` is pushed.
    - **Restore/WSC unchanged (3.1, 3.2)**: Observe `restore-defender.ps1` restore outputs and best-effort `register-wsc.ps1` WSC registration outputs.
  - Write property-based tests (`fast-check`) capturing the observed behavior across the input domain:
    - Generate arbitrary script paths, params, and exit codes and assert ps-runner always resolves without throwing.
    - Generate arbitrary settings states (`first_run_complete`, `defender_consent`) and assert disable steps only run when NOT complete AND consent is given (skip otherwise).
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 3. Fix for Defender not being disabled/replaced (consent, elevation, tamper gate, deprecated policy)

  - [x] 3.1 Gate the disable path on Tamper Protection and remove the deprecated policy in `disable-defender.ps1`
    - Change the Tamper Protection check from a warning to a gate: if `Get-MpComputerStatus -IsTamperProtected` is `$true`, print the exact settings path (`Settings > Windows Security > Virus & threat protection > Virus & threat protection settings > Tamper Protection > Off`) and exit with a distinct non-zero code (e.g. `2` = "tamper-blocked") without attempting further disable steps.
    - Delete Step 1a (the `DisableAntiSpyware = 1` write) and any dependence on it; keep only the real-time/behavior/IOAV controls that still take effect.
    - _Bug_Condition: isBugCondition(input) — writesDisableAntiSpyware(input) OR (input.tamperProtectionOn AND NOT blocksOnTamper(input))_
    - _Expected_Behavior: expectedBehavior — no `DisableAntiSpyware` write; tamper-on blocks with settings path and tamper-blocked code_
    - _Preservation: Property 3 — restore, WSC, ps-runner, first-run bookkeeping unchanged_
    - _Requirements: 2.4, 2.5_

  - [x] 3.2 Elevate the `WinDefend` service disable to SYSTEM/TrustedInstaller in `disable-defender.ps1`
    - Replace the plain-Administrator `Set-ItemProperty ... WinDefend Start 4` with a SYSTEM/TrustedInstaller-elevated operation: register a one-shot scheduled task running as `NT AUTHORITY\SYSTEM` that takes ownership of `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`, grants write access, and sets `Start=4`; then verify `Start` is `4` after the task completes. Apply the same elevation to the other Defender service keys already listed.
    - Keep the `Set-MpPreference` real-time/behavior/IOAV changes (Step 2) AND ensure the permanent service disable succeeds so the disable survives auto-re-enable across reboots.
    - Fix exit semantics: return `0` only when `WinDefend Start=4` is verified and Tamper Protection was off; return the tamper-blocked code when gated; return non-zero when the critical service disable could not be verified.
    - _Bug_Condition: isBugCondition(input) — disablesWinDefendAsPlainAdmin(input) OR reliesOnSetMpPreferenceOnly(input) → resultLeavesDefenderActive_
    - _Expected_Behavior: expectedBehavior — elevate to SYSTEM/TrustedInstaller, `Start=4` verified, MpPreference applied, Defender inactive + GSM Shield active across reboots_
    - _Preservation: Property 3 — restore, WSC, ps-runner, first-run bookkeeping unchanged_
    - _Requirements: 2.1, 2.2, 2.6_

  - [x] 3.3 Add a consent gate and handle tamper-blocked result in `electron/first-run.js`
    - Before running `disable-defender.ps1`, require explicit user Agree. Persist consent (e.g. a `defender_consent` setting) and only proceed with disable steps when consent is present. Expose an IPC path so the renderer can present the consent dialog and report the decision. If consent is not given, skip disable steps and do not mark the disable as done.
    - When `disable-defender` returns the tamper-blocked code, include a clear, retryable status in the `defender:setup-result` payload (not a generic failure), and keep `defender:runSetup` able to re-run after the user turns Tamper Protection off.
    - Preserve bookkeeping: continue to set `first_run_complete = '1'`, push `defender:setup-result`, and keep the `defender:runSetup` handler and skip-on-subsequent-launch behavior intact.
    - _Bug_Condition: isBugCondition(input) — NOT hasConsentGate(input)_
    - _Expected_Behavior: expectedBehavior — no disable step until explicit Agree; tamper-blocked surfaced as retryable_
    - _Preservation: Property 3 — first-run bookkeeping (`first_run_complete`, `defender:setup-result`, `defender:runSetup`) and skip-on-complete unchanged_
    - _Requirements: 2.3, 2.4, 3.4, 3.5_

  - [x] 3.4 Add consent dialog and Tamper Protection guidance UI in `renderer/`
    - Add the in-app consent dialog explaining that Windows Defender will be disabled and requiring the user to click Agree before any disable step.
    - Add a Tamper Protection instruction/retry view driven by the `defender:setup-result` status, showing the exact Windows Security settings path and a retry action.
    - _Bug_Condition: isBugCondition(input) — NOT hasConsentGate(input) OR (input.tamperProtectionOn AND NOT blocksOnTamper(input))_
    - _Expected_Behavior: expectedBehavior — consent dialog gates disable; tamper guidance shown with retry_
    - _Preservation: Property 3 — no change to non-setup UI flows_
    - _Requirements: 2.3, 2.4_

  - [x] 3.5 Verify bug condition exploration tests now pass
    - **Property 1: Expected Behavior** - Defender Permanently Disabled and Replaced with Consent/Tamper Gates
    - **IMPORTANT**: Re-run the SAME tests from task 1 - do NOT write new tests
    - The tests from task 1 encode the expected behavior; when they pass, they confirm the expected behavior is satisfied
    - Run the bug condition exploration tests from step 1
    - **EXPECTED OUTCOME**: Tests PASS (confirms bug is fixed): disable runs only after consent, tamper is blocked with guidance, `WinDefend Start=4` verified via SYSTEM/TrustedInstaller, no `DisableAntiSpyware` write, Defender left inactive
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [x] 3.6 Verify preservation tests still pass
    - **Property 2: Preservation** - Restore, WSC, ps-runner, and First-Run Bookkeeping Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run the preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions): full Defender restore on uninstall, best-effort WSC registration, non-throwing ps-runner, and first-run bookkeeping/skip behavior unchanged
    - Confirm all tests still pass after the fix (no regressions)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 4. Checkpoint - Ensure all tests pass
  - Run the full test suite (Jest logic/orchestration tests with mocked ps-runner/registry) and confirm both bug condition and preservation tests pass.
  - Note the manual/VM integration checks that cannot be safely automated (privileged registry writes, reboot survival, uninstall restore) per design "Integration Tests" and record them for manual validation on Windows 10 and Windows 11.
  - Ensure all tests pass, ask the user if questions arise.

## Task Dependency Graph

```json
{
  "waves": [
    { "wave": 1, "tasks": ["1", "2"], "dependsOn": [] },
    { "wave": 2, "tasks": ["3.1", "3.2"], "dependsOn": ["1", "2"] },
    { "wave": 3, "tasks": ["3.3"], "dependsOn": ["3.1", "3.2"] },
    { "wave": 4, "tasks": ["3.4"], "dependsOn": ["3.3"] },
    { "wave": 5, "tasks": ["3.5", "3.6"], "dependsOn": ["3.4"] },
    { "wave": 6, "tasks": ["4"], "dependsOn": ["3.5", "3.6"] }
  ]
}
```

- Tasks 1 and 2 are independent and must be completed BEFORE task 3 (tests-first).
- Sub-tasks 3.1–3.4 implement the fix; 3.1 and 3.2 (both `disable-defender.ps1`) land together; 3.3 depends on the tamper-blocked exit code from 3.1; 3.4 depends on the IPC/consent surface from 3.3.
- 3.5 re-runs task 1 tests; 3.6 re-runs task 2 tests; both must pass before task 4.

## Notes

- Framework: Jest + `fast-check` (matches existing `defender/*.test.js` and `__tests__/*.property.test.js`).
- Privileged operations (SYSTEM/TrustedInstaller registry writes, reboot survival, real uninstall restore) mutate host Defender state and cannot be safely automated; they are covered by manual/VM integration checks noted in task 4.
- Do NOT attempt to fix failing exploration tests in task 1 — their failure confirms the bug exists and they validate the fix once they pass in 3.5.
- Out of scope: true Microsoft-certified AV registration (MVI membership, PPL/ELAM signing).
