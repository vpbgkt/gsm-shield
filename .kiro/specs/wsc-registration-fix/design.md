# WSC Registration Fix Bugfix Design

## Overview

The GSM Shield AV application fails to register with Windows Security Center because it uses an incorrect API approach. The `register-wsc.ps1` script attempts to use `root\SecurityCenter2:AntiVirusProduct.CreateInstance()` and `Put()` to register the antivirus, but this WMI class is **read-only** for third-party applications. Only Windows Defender and Microsoft's own components can write to this namespace.

Additionally, the current implementation attempts direct registry manipulation for Tamper Protection and Defender disabling, which triggers Windows Defender's malware detection (`Trojan:Win32/MpTamperSrvDisableAV`), causing the script to be removed before execution.

**The Fix Strategy:**
1. **Remove WMI registration attempts** - The `root\SecurityCenter2:AntiVirusProduct` class cannot be used for registration
2. **Use the correct Windows 10/11 approach** - Register via COM/registry using documented interfaces:
   - Register as a Security Provider using `HKLM\SOFTWARE\Microsoft\Security Center\Provider` registry keys
   - Implement Windows Security Center COM notifications (optional but recommended)
   - Set appropriate product state flags in the registry
3. **Avoid malware detection** - Use documented APIs instead of tampering with Defender internals
4. **Handle permissions gracefully** - Detect insufficient permissions and log errors with non-zero exit codes

## Glossary

- **Bug_Condition (C)**: The condition that triggers registration failure - when the script attempts to use WMI `CreateInstance()` and `Put()` on the read-only `AntiVirusProduct` class
- **Property (P)**: The desired behavior - GSM Shield AV successfully registers with WSC using the correct registry-based approach
- **Preservation**: Existing ps-runner.js execution behavior, first-run orchestration flow, error logging, and all non-WSC-related functionality must remain unchanged
- **WSC (Windows Security Center)**: The Windows component that tracks registered security products and displays them in the Windows Security UI
- **root\SecurityCenter2:AntiVirusProduct**: A WMI class that provides **read-only** access to registered AV products; third-party apps cannot write to it
- **Security Provider Registration**: The documented approach for third-party security products to register with Windows, using specific registry keys under `HKLM\SOFTWARE\Microsoft\Security Center\Provider`
- **Product State**: A DWORD value (e.g., 266240) that encodes the AV product's status (enabled/disabled, up-to-date/out-of-date)
- **Tamper Protection**: A Windows Defender feature that prevents malicious software from modifying security settings; blocks many registry and service operations

## Bug Details

### Bug Condition

The bug manifests when the `register-wsc.ps1` script attempts to register GSM Shield AV using the WMI `AntiVirusProduct` class. The script calls `$wmiClass.CreateInstance()` and then `$newProduct.Put()`, expecting these operations to add a new AV product to the Security Center. However, the `root\SecurityCenter2:AntiVirusProduct` WMI class is **read-only for third-party applications** and only allows query operations. The `Put()` method either returns null or completes without error but produces no actual registration.

Additionally, Windows Defender detects the script's attempts to modify Defender-related registry keys as malware behavior, triggering `Trojan:Win32/MpTamperSrvDisableAV` detection and removing the script file.

**Formal Specification:**
```
FUNCTION isBugCondition(scriptExecution)
  INPUT: scriptExecution of type PowerShellScriptExecution
  OUTPUT: boolean
  
  RETURN scriptExecution.scriptName = 'register-wsc.ps1'
         AND scriptExecution.contains('CreateInstance()')
         AND scriptExecution.contains('Put()')
         AND scriptExecution.wmiClass = 'root\SecurityCenter2:AntiVirusProduct'
         AND scriptExecution.exitCode = 0
         AND NOT registryKeyExists('HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}')
END FUNCTION
```

**Root Cause:**
The `root\SecurityCenter2:AntiVirusProduct` WMI class is **designed for querying only**. Third-party security products must register through:
1. Registry keys under `HKLM\SOFTWARE\Microsoft\Security Center\Provider`
2. Optional COM notification interfaces (for advanced integration)

### Examples

- **Example 1**: Script runs `$newProduct.Put()` → returns null → no registry keys created → GSM Shield AV not visible in Windows Security Center
- **Example 2**: Script unpacked to `resources/scripts/register-wsc.ps1` → Windows Defender detects as `Trojan:Win32/MpTamperSrvDisableAV` → file removed → subsequent execution fails with "file not found"
- **Example 3**: Registry key `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` write attempted → blocked by Tamper Protection → key remains 0 or doesn't exist → Windows Defender continues running
- **Edge case**: Script runs with elevated privileges, Tamper Protection disabled → WMI `Put()` still fails because the API is fundamentally read-only for third-party apps → registration still unsuccessful

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- The `ps-runner.js` module must continue to execute PowerShell scripts correctly, capturing stdout, stderr, and exit codes
- The `first-run.js` orchestrator must continue to run all setup steps in sequence, regardless of individual failures (Requirement 21.6)
- The database `first_run_complete` setting must continue to be set to '1' after all steps complete
- The `defender:setup-result` IPC message must continue to be sent to the renderer with step summaries
- Error logging to `AppData/GSMShieldAV/error.log` must continue with timestamped entries
- The `defender:runSetup` IPC handler must continue to allow manual re-triggering from Settings
- Script path resolution via `resolveScriptsDir()` must continue to work in both development and packaged modes
- All non-Defender-related functionality (ClamAV scanning, database operations, quarantine, UI) must remain completely unaffected

**Scope:**
All inputs that do NOT involve the `register-wsc.ps1` script or WSC registration process should be completely unaffected by this fix. This includes:
- Normal ps-runner.js execution for other scripts
- First-run orchestration of non-WSC steps
- Database operations and settings management
- IPC communication patterns
- Error logging for other failures

## Hypothesized Root Cause

Based on the bug description and code analysis, the root causes are:

1. **Incorrect API Usage**: The script uses `root\SecurityCenter2:AntiVirusProduct.CreateInstance()` and `Put()`, which are **read-only operations for third-party applications**. Only Windows Defender and Microsoft components can write to this WMI namespace. Third-party AV products must use the registry-based Security Provider API.

2. **Malware Detection Trigger**: The script attempts to write to Defender-specific registry keys like `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`, which Windows Defender interprets as tampering behavior. This triggers `Trojan:Win32/MpTamperSrvDisableAV` detection.

3. **Missing Required Registry Keys**: The correct registration approach requires creating specific registry keys under `HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}` with proper values for `displayName`, `pathToSignedProductExe`, and `productState`.

4. **Silent Failure Mode**: The WMI `Put()` method returns null or completes with exit code 0 even when registration fails, making the bug difficult to detect without explicit verification.

## Correctness Properties

Property 1: Bug Condition - WSC Registration via Correct API

_For any_ registration attempt where the script is `register-wsc.ps1` and it previously used WMI `CreateInstance()`/`Put()`, the fixed script SHALL instead create registry keys under `HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{instanceGuid}` with values for `displayName`, `pathToSignedProductExe`, `pathToSignedReportingExe`, and `productState`, and verification SHALL confirm that querying `Get-WmiObject -Class AntiVirusProduct` returns an entry with `displayName='GSM Shield AV'` and `productState=266240`.

**Validates: Requirements 2.1, 2.4, 2.5, 2.6**

Property 2: Preservation - Non-WSC Script Execution

_For any_ PowerShell script execution that is NOT `register-wsc.ps1` (other scripts, test scripts, or future defender scripts), the fixed ps-runner.js and first-run.js SHALL produce exactly the same behavior as the original code, preserving stdout/stderr capture, exit code handling, error logging, IPC messaging, and database operations.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct (WMI API is read-only for third-party apps):

**File**: `defender/scripts/register-wsc.ps1`

**Function**: WSC registration logic

**Specific Changes**:

1. **Remove WMI CreateInstance/Put approach**:
   - Delete the `$wmiClass.CreateInstance()` and `$newProduct.Put()` code block
   - These operations are fundamentally incompatible with third-party AV registration

2. **Implement Security Provider Registry Registration**:
   - Create registry keys under `HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{instanceGuid}`
   - Set the following values:
     - `displayName` (REG_SZ): "GSM Shield AV"
     - `pathToSignedProductExe` (REG_SZ): Full path to `GSM Shield AV.exe`
     - `pathToSignedReportingExe` (REG_SZ): Same as above
     - `productState` (REG_DWORD): 266240 (enabled, up-to-date)
   - Use PowerShell's `New-Item` and `Set-ItemProperty` cmdlets with proper error handling

3. **Add Permission Detection**:
   - Wrap registry operations in `try-catch` blocks
   - Detect access denied errors (insufficient elevation)
   - Exit with non-zero exit code (1) when registration fails due to permissions
   - Log specific error messages to stdout/stderr for error.log capture

4. **Implement Proper Verification**:
   - After registry key creation, use `Get-WmiObject -Class AntiVirusProduct` to verify the registration
   - This query operation works correctly (it's the write operations that don't)
   - Check for entry with `displayName='GSM Shield AV'`
   - Exit with code 0 only if verification succeeds

5. **Remove Defender Tampering Code**:
   - Remove attempts to set `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`
   - Remove attempts to modify Tamper Protection registry keys
   - These operations trigger malware detection and are unnecessary for proper WSC registration

**File**: `defender/scripts/disable-defender.ps1` (no changes required)

This script correctly uses `Set-MpPreference -DisableRealtimeMonitoring $true`, which is the documented API. It already handles Tamper Protection blocks gracefully by catching errors and exiting 0. No changes needed.

**File**: `defender/ps-runner.js` (no changes required)

The ps-runner module correctly spawns PowerShell with proper flags and captures all output. The bug is in the script content, not the runner. No changes needed.

**File**: `electron/first-run.js` (no changes required)

The orchestrator correctly executes steps in sequence and continues on failure. The bug is in the WSC registration script, not the orchestration logic. No changes needed.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm that WMI `Put()` fails to register GSM Shield AV and that the registry keys required for proper registration do not exist.

**Test Plan**: Write tests that run `register-wsc.ps1` on the UNFIXED code and verify:
1. The script exits with code 0 (silent failure)
2. No registry keys exist under `HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}`
3. Querying `Get-WmiObject -Class AntiVirusProduct` does NOT return GSM Shield AV
4. The WMI `Put()` method returns null or has no observable effect

Run these tests on the UNFIXED code to observe failures and confirm the root cause.

**Test Cases**:
1. **WMI Put() Failure Test**: Run register-wsc.ps1 (unfixed) → assert exit code 0 but no registry keys created (will fail on unfixed code by demonstrating silent failure)
2. **Missing Registry Keys Test**: After running unfixed script → check for `HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}` → assert keys do NOT exist (will fail on unfixed code)
3. **WSC Query Test**: After running unfixed script → run `Get-WmiObject -Class AntiVirusProduct` → assert GSM Shield AV is NOT in results (will fail on unfixed code)
4. **Malware Detection Test**: Deploy unfixed script to resources/scripts/ → observe Windows Defender detection → assert script file is removed (may fail on unfixed code depending on Defender state)

**Expected Counterexamples**:
- WMI `Put()` returns null or completes silently without creating registration
- No registry keys under `HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}`
- `Get-WmiObject` query does not return GSM Shield AV entry
- Possible causes: WMI API is read-only, incorrect registration approach, malware detection triggered

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds (WSC registration attempts), the fixed function produces the expected behavior (successful registry-based registration).

**Pseudocode:**
```
FOR ALL scriptExecution WHERE isBugCondition(scriptExecution) DO
  result := register-wsc-fixed.ps1()
  ASSERT result.exitCode = 0
  ASSERT registryKeyExists('HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}')
  ASSERT registryValueEquals('displayName', 'GSM Shield AV')
  ASSERT registryValueEquals('productState', 266240)
  wscQuery := Get-WmiObject -Class AntiVirusProduct -Filter "displayName='GSM Shield AV'"
  ASSERT wscQuery.count > 0
  ASSERT wscQuery[0].productState = 266240
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold (non-WSC script executions), the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL scriptExecution WHERE NOT isBugCondition(scriptExecution) DO
  ASSERT ps-runner-original(scriptExecution) = ps-runner-fixed(scriptExecution)
  ASSERT first-run-original(scriptExecution) = first-run-fixed(scriptExecution)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-WSC-related operations

**Test Plan**: Observe behavior on UNFIXED code first for ps-runner.js executions, first-run orchestration, and error logging, then write property-based tests capturing that behavior.

**Test Cases**:
1. **ps-runner Preservation**: Observe that ps-runner.js correctly executes `disable-defender.ps1` on unfixed code → write property test verifying stdout/stderr/exitCode capture continues working after fix
2. **first-run Orchestration Preservation**: Observe that first-run.js runs all steps and sets `first_run_complete='1'` on unfixed code → write property test verifying this continues after fix
3. **Error Logging Preservation**: Observe that errors are written to `error.log` with timestamps on unfixed code → write property test verifying this continues after fix
4. **IPC Messaging Preservation**: Observe that `defender:setup-result` is sent to renderer on unfixed code → write property test verifying this continues after fix

### Unit Tests

- Test registry key creation with valid elevated permissions
- Test registry key creation with insufficient permissions (should fail with non-zero exit code)
- Test verification logic that queries `Get-WmiObject -Class AntiVirusProduct`
- Test that fixed script does NOT trigger Windows Defender malware detection
- Test error handling for missing exe path scenarios
- Test that ps-runner.js correctly captures output from fixed script

### Property-Based Tests

- Generate random valid exe paths and verify registry registration works for all paths
- Generate random WSC query scenarios and verify GSM Shield AV appears correctly in all cases
- Generate random first-run orchestration sequences and verify all steps execute correctly
- Generate random error conditions (missing files, access denied) and verify proper error codes and logging across all scenarios

### Integration Tests

- Test full first-run flow with fixed `register-wsc.ps1` on a clean Windows 10/11 system
- Verify GSM Shield AV appears in Windows Security Center UI after installation
- Verify `first_run_complete='1'` is set in database after successful registration
- Verify error.log contains no WSC registration failures after fix
- Test manual re-trigger from Settings page with `defender:runSetup` IPC handler
- Verify that uninstalling and reinstalling triggers proper re-registration
