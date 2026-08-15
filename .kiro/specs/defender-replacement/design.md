# Defender Replacement Bugfix Design

## Overview

After installing GSM Shield AV, Windows Defender stays the active antivirus and GSM Shield AV never becomes the active real-time scanner. The current first-run flow (`electron/first-run.js` → `defender/ps-runner.js` → `defender/scripts/disable-defender.ps1` + `register-wsc.ps1`) attempts to disable Defender while running as a plain Administrator, with no consent gate and only a warning about Tamper Protection. The critical `WinDefend` service disable (`Start=4`) is rejected with Access Denied because that registry key is owned by TrustedInstaller, and turning off real-time protection through `Set-MpPreference` alone does not survive because Windows re-enables it when no registered AV exists.

The fix implements the **technician workflow**: with explicit in-app consent and proper elevation (Administrator → SYSTEM/TrustedInstaller via a scheduled task), the flow permanently disables the `WinDefend` service and applies `Set-MpPreference` changes, detects and blocks on Tamper Protection, stops relying on the deprecated `DisableAntiSpyware` policy value, and lets GSM Shield AV's ClamAV-based monitor act as the active real-time scanner. Uninstall must still fully restore Defender, and best-effort WSC provider registration is retained. True Microsoft-certified AV registration (MVI membership, PPL/ELAM signing) remains out of scope.

The strategy is targeted and minimal: it changes the elevation mechanism and step ordering inside the disable path, adds a consent gate and a Tamper Protection gate to the orchestrator, and removes the deprecated policy write — while leaving the restore path, WSC registration, ps-runner error semantics, and first-run bookkeeping intact.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug — a first-run/setup disable attempt where the user has consented, Tamper Protection is off, but the flow fails to permanently disable Defender (Access Denied on `WinDefend Start=4`, `Set-MpPreference` gets auto-reverted, and/or the deprecated `DisableAntiSpyware` path is used), leaving Defender active.
- **Property (P)**: The desired behavior for buggy inputs — with consent given and Tamper Protection off, the setup elevates to SYSTEM/TrustedInstaller, permanently disables `WinDefend` (`Start=4`), applies `Set-MpPreference` real-time/behavior/IOAV changes, avoids `DisableAntiSpyware`, and leaves GSM Shield AV as the active real-time scanner across reboots.
- **Preservation**: Existing behaviors that must remain unchanged — full Defender restore on uninstall, best-effort WSC provider registration, non-throwing ps-runner semantics, first-run bookkeeping (`first_run_complete`, `defender:setup-result`, `defender:runSetup`), and the skip-on-subsequent-launch behavior.
- **disable-defender.ps1**: The script in `defender/scripts/` that disables Windows Defender features (policies, MpPreference, services, tasks, notifications, tray icon).
- **restore-defender.ps1**: The script in `defender/scripts/` that reverses `disable-defender.ps1` and removes WSC registration on uninstall.
- **register-wsc.ps1**: The script in `defender/scripts/` that performs best-effort registry-based WSC provider registration for GSM Shield AV.
- **ps-runner.js**: The Node module (`defender/ps-runner.js`) that spawns PowerShell with `-ExecutionPolicy Bypass -NonInteractive -File` and resolves `{ exitCode, stdout, stderr }` without ever throwing.
- **first-run.js**: The orchestrator (`electron/first-run.js`) that gates on `first_run_complete`, runs the setup steps via ps-runner, marks completion, and pushes `defender:setup-result`.
- **WinDefend service**: The Microsoft Defender Antivirus service whose `Start` registry value under `HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend` is owned by TrustedInstaller and must be `4` (Disabled) for the disable to survive.
- **Tamper Protection**: The Windows Security feature that silently reverts Defender configuration changes while enabled; reported by `Get-MpComputerStatus -IsTamperProtected`.
- **SYSTEM/TrustedInstaller elevation**: Running a step under the SYSTEM account (e.g. via a one-shot scheduled task registered to run as `NT AUTHORITY\SYSTEM`), then taking ownership of the TrustedInstaller-protected service key so `Start=4` writes succeed.
- **Consent gate**: An in-app dialog shown before any disable step that requires the user to explicitly Agree.

## Bug Details

### Bug Condition

The bug manifests during installer or first-run/setup execution when the flow attempts to disable Windows Defender. Even when the user would agree and Tamper Protection is off, the disable does not survive because: (a) the permanent `WinDefend` service disable (`Start=4`) is written as a plain Administrator against a TrustedInstaller-owned key and fails with Access Denied; (b) `Set-MpPreference -DisableRealtimeMonitoring $true` alone gets auto-reverted by Windows because no registered AV exists and the service is still enabled; and/or (c) the flow relies on the deprecated `DisableAntiSpyware` policy value. In addition, the flow performs disable steps without an explicit consent gate and only warns about (rather than blocks on) Tamper Protection.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type SetupInvocation
         { phase, consentGiven, tamperProtectionOn, osVersion }
  OUTPUT: boolean

  // Only the disable/setup path is in scope
  RETURN input.phase IN ['installer-setup', 'first-run', 'manual-runSetup']
         AND (
              // permanent service disable attempted without SYSTEM/TrustedInstaller elevation
              disablesWinDefendAsPlainAdmin(input)          // → Access Denied, Start stays != 4
           OR reliesOnSetMpPreferenceOnly(input)            // → real-time auto-re-enabled
           OR writesDisableAntiSpyware(input)               // → ignored value + tamper detection
           OR NOT hasConsentGate(input)                     // → disable runs without explicit Agree
           OR (input.tamperProtectionOn AND NOT blocksOnTamper(input)) // → changes silently reverted
         )
         AND resultLeavesDefenderActive(input)              // Defender remains the active AV
END FUNCTION
```

### Examples

- **Windows 11, consent implied, Tamper off**: `disable-defender.ps1` runs as Administrator; `Set-ItemProperty WinDefend Start 4` returns Access Denied; after reboot `WinDefend` is still running and Defender is the active AV. Expected: `Start=4` succeeds via SYSTEM/TrustedInstaller and Defender stays inactive.
- **Windows 10, real-time only**: `Set-MpPreference -DisableRealtimeMonitoring $true` succeeds momentarily, but because `WinDefend` is enabled and no registered AV exists, Windows re-enables real-time protection minutes later. Expected: service permanently disabled so the change survives.
- **Tamper Protection ON**: Setup logs `WARNING: Tamper Protection is ENABLED` and continues; every change is silently reverted and Defender remains active with no clear user guidance. Expected: setup detects Tamper Protection, blocks the disable step, shows the exact settings path, and lets the user retry.
- **Deprecated policy write**: Setup writes `DisableAntiSpyware = 1`, which Windows 2004+ ignores and which can trip `Trojan:Win32/MpTamperSrvDisableAV`. Expected: the flow does not write or depend on `DisableAntiSpyware`.
- **Edge case — no consent**: User closes the app before agreeing; disable steps must not have run. Expected: nothing is disabled until explicit Agree.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Uninstall via `restore-defender.ps1` must continue to fully restore Windows Defender: re-enable the `WinDefend` service, real-time monitoring, scheduled tasks, notifications, and the tray icon (Requirement 3.1).
- Setup must continue to perform best-effort WSC provider registration via `register-wsc.ps1` so GSM Shield AV may appear in the Windows Security Center provider list (Requirement 3.2).
- `ps-runner.js` must continue to run without throwing on any error, returning `{ exitCode, stdout, stderr }` and letting the orchestrator log and proceed (Requirement 3.3).
- First-run completion bookkeeping must continue: mark `first_run_complete = '1'`, push the `defender:setup-result` IPC summary, and support manual re-triggering via `defender:runSetup` (Requirement 3.4).
- Once the user has agreed and completed first-run setup, subsequent launches must continue to skip the consent dialog and disable steps (Requirement 3.5).

**Scope:**
All inputs that do NOT match the disable/setup bug condition should be completely unaffected by this fix. This includes:
- The uninstall/restore path and its registry/service/task/notification reversals.
- WSC registration behavior and its idempotent-cleanup logic.
- ps-runner spawn flags and non-throwing contract for arbitrary scripts.
- First-run gating for already-completed installs and the `defender:runSetup` re-trigger channel.

**Note:** The actual expected correct behavior for buggy inputs is defined in the Correctness Properties section (Property 1). This section focuses on what must NOT change.

## Hypothesized Root Cause

Based on the bug description and the current implementation, the most likely issues are:

1. **Insufficient privilege for TrustedInstaller-owned key**: `disable-defender.ps1` Step 3 runs `Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend -Name Start -Value 4` as a plain Administrator. The `WinDefend` key is owned by TrustedInstaller, so the write fails with Access Denied and the service is never permanently disabled.
   - Administrator is not the same as SYSTEM/TrustedInstaller for these protected keys.
   - The failure is counted as a "failed step" but setup exits 0 on partial success, masking the problem.

2. **Reliance on `Set-MpPreference` alone**: Real-time protection toggled via `Set-MpPreference` does not persist when no registered AV exists and `WinDefend` is still enabled; Windows auto-re-enables it. The service disable and the preference change must both succeed for the disable to survive.

3. **No consent gate**: `first-run.js` calls the disable step unconditionally when `first_run_complete !== '1'`, with no explicit user Agree step before Defender is touched.

4. **Tamper Protection only warned about**: `disable-defender.ps1` reads `IsTamperProtected` but only logs a warning and continues; it neither blocks the disable step nor guides the user, so changes are silently reverted.

5. **Deprecated `DisableAntiSpyware` policy**: Step 1a writes `DisableAntiSpyware = 1`, ignored since Windows 10 2004 and associated with `Trojan:Win32/MpTamperSrvDisableAV` detection — ineffective and risky.

## Correctness Properties

Property 1: Bug Condition - Defender Permanently Disabled and Replaced

_For any_ setup invocation where the bug condition holds (isBugCondition returns true) — that is, a disable/setup run with consent given and Tamper Protection off — the fixed flow SHALL elevate from Administrator to SYSTEM/TrustedInstaller, take ownership of the `WinDefend` service key and set `Start=4` successfully, apply `Set-MpPreference` real-time/behavior/IOAV changes, complete without writing or depending on the `DisableAntiSpyware` policy value, and leave Windows Defender inactive with GSM Shield AV's ClamAV-based monitor as the active real-time scanner across reboots on both Windows 10 and Windows 11.

**Validates: Requirements 2.1, 2.2, 2.5, 2.6**

Property 2: Bug Condition - Consent and Tamper Protection Gates

_For any_ setup invocation, the fixed flow SHALL NOT perform any Defender-disable step until the user has explicitly agreed via an in-app consent dialog; and _for any_ invocation where Tamper Protection is enabled, the flow SHALL detect it, present step-by-step instructions with the exact Windows Security settings path, block the disable step, and allow retry after the user turns Tamper Protection off.

**Validates: Requirements 2.3, 2.4**

Property 3: Preservation - Restore, WSC, ps-runner, and First-Run Bookkeeping Unchanged

_For any_ input where the bug condition does NOT hold (isBugCondition returns false) — including uninstall/restore, WSC registration, arbitrary ps-runner invocations, and already-completed first-run launches — the fixed code SHALL produce the same result as the original code, preserving full Defender restore on uninstall, best-effort WSC provider registration, non-throwing ps-runner semantics, `first_run_complete`/`defender:setup-result`/`defender:runSetup` bookkeeping, and skip-on-subsequent-launch behavior.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `defender/scripts/disable-defender.ps1`

**Function/Section**: Tamper Protection check, Step 1 (policies), Step 3 (services)

**Specific Changes**:
1. **Block on Tamper Protection**: Change the Tamper Protection check from a warning to a gate. If `Get-MpComputerStatus -IsTamperProtected` is `$true`, print the exact settings path (`Settings > Windows Security > Virus & threat protection > Virus & threat protection settings > Tamper Protection > Off`) and exit with a distinct non-zero code (e.g. `2` = "tamper-blocked") without attempting further disable steps, so the orchestrator can surface a retry.
2. **Remove `DisableAntiSpyware`**: Delete Step 1a (the `DisableAntiSpyware = 1` write) and any dependence on it. Keep only the real-time/behavior/IOAV controls that still take effect.
3. **Elevate for the `WinDefend` service disable**: Replace the plain-Administrator `Set-ItemProperty ... WinDefend Start 4` with a SYSTEM/TrustedInstaller-elevated operation. Register a one-shot scheduled task that runs as `NT AUTHORITY\SYSTEM`, which takes ownership of `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`, grants write access, and sets `Start=4`; then verify `Start` is `4` after the task completes. Apply the same elevation approach to the other Defender service keys already listed.
4. **Combine service disable with MpPreference**: Keep the `Set-MpPreference` real-time/behavior/IOAV changes (Step 2) AND ensure the permanent service disable succeeds, so the disable survives auto-re-enable.
5. **Accurate exit semantics**: Return `0` only when the `WinDefend` service disable is verified (`Start=4`) and Tamper Protection was off; return the tamper-blocked code when gated; return non-zero when the critical service disable could not be verified, so `first-run.js` reflects real status.

**File**: `electron/first-run.js`

**Function**: `runFirstRunSetup`, `register`

**Specific Changes**:
6. **Add a consent gate**: Before running `disable-defender.ps1`, require an explicit user Agree. Persist consent (e.g. a `defender_consent` setting) and only proceed with disable steps when consent is present. Expose an IPC path so the renderer can present the consent dialog and report the decision. If consent is not given, skip disable steps and do not mark the disable as done.
7. **Handle the tamper-blocked result**: When `disable-defender` returns the tamper-blocked code, include a clear, retryable status in the `defender:setup-result` payload (do not treat it as a generic failure), and keep `defender:runSetup` able to re-run after the user turns Tamper Protection off.
8. **Preserve bookkeeping**: Continue to set `first_run_complete = '1'`, push `defender:setup-result`, and keep the `defender:runSetup` handler and skip-on-subsequent-launch behavior intact.

**File**: `renderer/` (Settings / first-run UI)

**Specific Changes**:
9. **Consent dialog + Tamper guidance UI**: Add the in-app consent dialog (explaining Defender will be disabled, requiring Agree) and a Tamper Protection instruction/retry view driven by the `defender:setup-result` status.

**Unchanged**: `defender/scripts/restore-defender.ps1`, `defender/scripts/register-wsc.ps1`, and `defender/ps-runner.js` remain behaviorally unchanged (restore, WSC registration, and non-throwing spawn semantics are preserved).

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior. Because the disable operations mutate the host's real Defender state and require SYSTEM/TrustedInstaller elevation, tests split into (a) logic/orchestration tests that mock `ps-runner`/registry access and run in CI, and (b) manual/VM integration checks for the actual privileged registry writes, which cannot be safely automated on developer machines.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Run `disable-defender.ps1` (unfixed) and inspect results, and drive `first-run.js` with a mocked ps-runner to observe the absence of a consent gate and tamper block. Assert the counterexamples on the UNFIXED code.

**Test Cases**:
1. **WinDefend Start Access Denied**: Run the unfixed disable step and assert `Set-ItemProperty WinDefend Start 4` reports Access Denied / `Start` is not `4` afterward (will fail on unfixed code once the fix lands).
2. **Real-time auto-re-enable**: With only `Set-MpPreference` applied and `WinDefend` enabled, observe real-time protection re-enabling (manual/VM).
3. **No consent gate**: Drive `runFirstRunSetup` with a mocked ps-runner and assert the disable step is invoked without any prior Agree (demonstrates missing gate).
4. **Tamper not blocked**: Simulate `IsTamperProtected = $true` and assert the unfixed script only warns and continues rather than blocking.
5. **DisableAntiSpyware present** (edge): Assert the unfixed script writes `DisableAntiSpyware = 1`.

**Expected Counterexamples**:
- `WinDefend` `Start` remains `!= 4` after the disable step (Access Denied).
- Disable step runs with no consent recorded.
- Tamper Protection enabled path continues instead of blocking.
- Possible causes: plain-Administrator privilege, `Set-MpPreference`-only reliance, missing gate, deprecated policy write.

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := runFirstRunSetup_fixed(input)   // consent given, tamper off
  ASSERT consentRequiredBeforeDisable(result)
  ASSERT winDefendStartEquals(result, 4)             // via SYSTEM/TrustedInstaller
  ASSERT setMpPreferenceApplied(result)
  ASSERT NOT wroteDisableAntiSpyware(result)
  ASSERT defenderInactiveAndGsmActive(result)
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT restoreDefender_original(input)  = restoreDefender_fixed(input)
  ASSERT registerWsc_original(input)      = registerWsc_fixed(input)
  ASSERT psRunner_original(input)         = psRunner_fixed(input)
  ASSERT firstRunBookkeeping_original(input) = firstRunBookkeeping_fixed(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain (arbitrary script paths, params, exit codes; varied setting states).
- It catches edge cases that manual unit tests might miss.
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs.

**Test Plan**: Observe ps-runner and first-run bookkeeping behavior on UNFIXED code first (arbitrary scripts, exit codes, already-complete first-run, `defender:runSetup`), then write property-based tests capturing that behavior and confirm it is unchanged after the fix.

**Test Cases**:
1. **ps-runner non-throwing**: Observe that arbitrary scripts/exit codes resolve to `{ exitCode, stdout, stderr }` without throwing on unfixed code, then verify this continues after fix.
2. **First-run skip**: Observe that with `first_run_complete = '1'` the disable/consent steps are skipped, then verify this continues after fix.
3. **defender:runSetup re-trigger**: Observe the IPC handler re-runs setup, then verify this continues after fix.
4. **Restore/WSC unchanged**: Observe restore and WSC registration outputs on unfixed code, then verify they are unchanged after fix.

### Unit Tests

- `first-run.js`: consent gate prevents disable step until Agree is recorded; tamper-blocked exit code produces a retryable `defender:setup-result` status; `first_run_complete` set and IPC pushed; skip-on-complete path.
- `disable-defender.ps1` logic (mocked/dry-run): Tamper-on returns tamper-blocked code and prints the settings path; no `DisableAntiSpyware` write; exit code reflects verified `WinDefend Start=4`.
- ps-runner: existing non-throwing tests continue to pass unchanged.

### Property-Based Tests

- Generate arbitrary script paths, params, and exit codes and verify ps-runner always resolves without throwing (preservation).
- Generate arbitrary settings states (`first_run_complete`, `defender_consent`) and verify the orchestrator only runs disable steps when not complete AND consent is given.
- Generate varied `defender:setup-result` step outcomes and verify the payload summary classification (success / failure / tamper-blocked) is consistent.

### Integration Tests

- **VM/manual**: Full first-run on Windows 10 and Windows 11 with Tamper Protection off and consent given — verify `WinDefend Start=4` persists across reboot and GSM Shield AV monitor is the active real-time scanner.
- **VM/manual**: First-run with Tamper Protection on — verify the disable step is blocked, instructions shown, and retry succeeds after turning Tamper Protection off.
- **VM/manual**: Uninstall after a successful disable — verify `restore-defender.ps1` fully re-enables Defender (service, real-time, tasks, notifications, tray) and removes WSC registration.
