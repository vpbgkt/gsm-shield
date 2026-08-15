# Bugfix Requirements Document

## Introduction

After installing GSM Shield AV, Windows Defender remains the active antivirus and is never disabled or replaced. As a result, GSM Shield AV does not become the active real-time protection software on either Windows 10 or Windows 11. This defeats the core promise of the product: that installing it hands real-time protection over to GSM Shield AV.

The root causes, established through prior investigation, are:

- The `disable-defender.ps1` script sets `WinDefend` service `Start=4` while running as a plain Administrator. That registry key is owned by TrustedInstaller and is protected, so the write returns Access Denied and the service stays enabled.
- Turning off real-time protection with `Set-MpPreference` alone does not stick — when no *registered* AV exists, Windows automatically re-enables real-time protection. Without a permanently disabled `WinDefend` service, Defender comes back.
- There is no first-run consent gate: Defender-disable is attempted without the user explicitly agreeing.
- Tamper Protection is only warned about; the flow does not detect it, guide the user to turn it off, or block the disable step until it is off. When Tamper Protection is on, changes are silently reverted.
- The script relies on the `DisableAntiSpyware` group-policy value, which Windows has ignored since Windows 10 version 2004 (2020) and which can trigger a `Trojan:Win32/MpTamperSrvDisableAV` detection.

True Windows Security Center "registered/certified AV" replacement (via Microsoft Virus Initiative membership and PPL/ELAM code-signing certificates) is out of scope — no code-signing certificate is available. The fix therefore implements the "technician workflow": with explicit user consent and proper elevation, disable Defender's active protection (real-time via `Set-MpPreference` plus a permanent `WinDefend` service disable performed by elevating from Administrator to SYSTEM/TrustedInstaller) so GSM Shield AV's own ClamAV-based monitor can act as the active real-time scanner. Uninstall must fully restore Windows Defender, and best-effort WSC provider registration is retained.

## Bug Analysis

### Current Behavior (Defect)

After installation and first run, Windows Defender is not effectively disabled and GSM Shield AV does not become the active real-time scanner.

1.1 WHEN the installer or first-run setup attempts to permanently disable Defender by setting the `WinDefend` service `Start` value to `4` while running as a plain Administrator THEN the system fails the write with Access Denied because the service registry key is owned by TrustedInstaller, leaving the `WinDefend` service enabled.

1.2 WHEN real-time protection is turned off only via `Set-MpPreference -DisableRealtimeMonitoring $true` and the `WinDefend` service remains enabled THEN the system automatically re-enables Defender real-time protection because no registered AV exists, so the disable does not survive.

1.3 WHEN first-run setup begins THEN the system attempts to disable Windows Defender without presenting a consent dialog or requiring the user to explicitly agree beforehand.

1.4 WHEN Tamper Protection is enabled at install or first run THEN the system only logs a warning and continues, without blocking the disable step or guiding the user to turn Tamper Protection off, so the Defender changes are silently reverted.

1.5 WHEN the disable step runs THEN the system writes the `DisableAntiSpyware` group-policy value, which Windows (version 2004+) ignores and which can trigger a `Trojan:Win32/MpTamperSrvDisableAV` detection.

1.6 WHEN the full disable sequence completes on either Windows 10 or Windows 11 THEN the system leaves Windows Defender as the active antivirus and GSM Shield AV is not the active real-time protection software.

### Expected Behavior (Correct)

The fixed flow disables Defender permanently with proper elevation and explicit consent, and makes GSM Shield AV the active real-time scanner.

2.1 WHEN the setup needs to permanently disable the `WinDefend` service THEN the system SHALL elevate from Administrator to SYSTEM/TrustedInstaller (for example via a scheduled task running as SYSTEM), take ownership of the service registry key, and set `Start=4` successfully.

2.2 WHEN real-time protection is disabled THEN the system SHALL both apply `Set-MpPreference` changes (real-time, behavior, IOAV) and permanently disable the `WinDefend` service so that real-time protection stays off and does not get auto-re-enabled across reboots.

2.3 WHEN the application runs for the first time THEN the system SHALL display an in-app consent dialog explaining that Windows Defender will be disabled and SHALL require the user to click Agree before performing any disable step.

2.4 WHEN Tamper Protection is enabled at install or first run THEN the system SHALL detect it, display clear step-by-step instructions including the exact Windows Security settings path, block the disable step until the user turns Tamper Protection off, and allow the user to retry afterward.

2.5 WHEN the disable step runs THEN the system SHALL NOT rely on or write the `DisableAntiSpyware` group-policy value, avoiding the ignored setting and the associated tamper detection.

2.6 WHEN the full disable sequence completes with consent given and Tamper Protection off, on either Windows 10 or Windows 11 THEN the system SHALL leave Windows Defender inactive and GSM Shield AV's ClamAV-based monitor as the active real-time protection software.

### Unchanged Behavior (Regression Prevention)

Existing behaviors outside the bug condition must be preserved.

3.1 WHEN the application is uninstalled THEN the system SHALL CONTINUE TO fully restore Windows Defender, including re-enabling the `WinDefend` service, real-time monitoring, scheduled tasks, notifications, and the tray icon.

3.2 WHEN setup runs THEN the system SHALL CONTINUE TO perform best-effort WSC provider registration so GSM Shield AV may appear in the Windows Security Center provider list where possible.

3.3 WHEN a PowerShell setup step encounters an error THEN the ps-runner SHALL CONTINUE TO run without throwing, logging the error and allowing remaining steps to proceed.

3.4 WHEN first-run setup completes THEN the system SHALL CONTINUE TO mark `first_run_complete = '1'`, push the `defender:setup-result` IPC summary to the renderer, and support manual re-triggering via the `defender:runSetup` IPC channel.

3.5 WHEN the user has already agreed and completed first-run setup THEN the system SHALL CONTINUE TO skip the consent dialog and disable steps on subsequent launches.
