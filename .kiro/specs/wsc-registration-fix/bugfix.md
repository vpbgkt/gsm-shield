# Bugfix Requirements Document

## Introduction

The GSM Shield AV application fails to register with the Windows Security Center (WSC) after installation, even when Tamper Protection and Real-time Protection are manually disabled by the user. The current implementation attempts to use the WMI `root\SecurityCenter2:AntiVirusProduct` class to register the antivirus, but this API is read-only and cannot be used to register third-party AV products. Additionally, Windows Defender detects the registration script (`register-wsc.ps1`) as malware (`Trojan:Win32/MpTamperSrvDisableAV`) and removes it.

This bug prevents GSM Shield AV from meeting Requirement 21, which mandates that GSM Shield AV appears as the registered antivirus in Windows Security Center, with Windows Defender disabled and appropriate registry keys set.

The impact is critical: users cannot verify that GSM Shield AV is protecting their system, and Windows may continue running Defender alongside GSM Shield AV, causing resource conflicts and user confusion.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the `register-wsc.ps1` script attempts to create a new `AntiVirusProduct` instance using `$wmiClass.CreateInstance()` and call `$newProduct.Put()` THEN the system silently fails to register GSM Shield AV (Put() returns null or has no effect)

1.2 WHEN the `register-wsc.ps1` script is unpacked to the `resources/scripts/` directory THEN the system detects it as `Trojan:Win32/MpTamperSrvDisableAV` and removes the script file

1.3 WHEN the `disable-defender.ps1` script attempts to set registry keys `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` to 1 THEN the system does not create or modify this registry key (it remains 0 or doesn't exist)

1.4 WHEN the WSC registration completes with exit code 0 THEN the system does not create the `HKLM\SOFTWARE\Microsoft\Security Center\Svc\ProductState` registry entry with value 266240

1.5 WHEN the user checks Windows Security Center after installation THEN the system does not show GSM Shield AV as the registered antivirus

1.6 WHEN the scripts run with `-ExecutionPolicy Bypass -NonInteractive` flags THEN the system returns exit code 0 but produces no actual registry or WSC changes

### Expected Behavior (Correct)

2.1 WHEN the WSC registration process runs THEN the system SHALL successfully register GSM Shield AV with Windows Security Center using an alternative approach that avoids WMI `AntiVirusProduct` instantiation

2.2 WHEN the WSC registration completes successfully THEN the system SHALL create the registry key `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection` with value 0 to disable Tamper Protection programmatically

2.3 WHEN Windows Defender is disabled THEN the system SHALL set the registry key `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` to 1

2.4 WHEN the WSC registration is verified THEN the system SHALL query `Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct` and find an entry with `displayName='GSM Shield AV'` and `productState=266240`

2.5 WHEN the registration scripts are unpacked THEN the system SHALL NOT trigger Windows Defender malware detection and SHALL preserve all script files

2.6 WHEN the WSC registration fails due to insufficient permissions THEN the system SHALL return a non-zero exit code and log the specific error to `error.log`

### Unchanged Behavior (Regression Prevention)

3.1 WHEN the `ps-runner.js` executes PowerShell scripts with valid paths THEN the system SHALL CONTINUE TO capture stdout, stderr, and exit codes correctly

3.2 WHEN the `first-run.js` orchestrator runs multiple setup steps THEN the system SHALL CONTINUE TO execute all steps regardless of individual failures (Requirement 21.6)

3.3 WHEN the `first-run.js` orchestrator completes THEN the system SHALL CONTINUE TO set `first_run_complete='1'` in the database and send `defender:setup-result` IPC message to the renderer

3.4 WHEN the `disable-defender.ps1` script encounters Tamper Protection blocking Set-MpPreference THEN the system SHALL CONTINUE TO log an informational message and exit with code 0

3.5 WHEN the user manually re-triggers setup from the Settings page THEN the system SHALL CONTINUE TO invoke the `defender:runSetup` IPC handler and re-run the setup sequence

3.6 WHEN any setup step fails THEN the system SHALL CONTINUE TO append timestamped error details to `AppData/GSMShieldAV/error.log`

3.7 WHEN the scripts are called during unit tests or development mode THEN the system SHALL CONTINUE TO resolve script paths correctly using the fallback logic in `resolveScriptsDir()`

3.8 WHEN ClamAV scanning, database initialization, and quarantine directory creation run THEN the system SHALL CONTINUE TO work correctly (these components are unaffected by this bug)
