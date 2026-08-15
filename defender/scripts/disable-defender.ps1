# disable-defender.ps1
# Comprehensively disables Windows Defender to allow GSM Shield AV to serve
# as the primary antivirus on this machine.
#
# This script uses multiple layers of disabling to ensure Defender does not
# interfere with GSM Shield AV's real-time protection:
#   1. Group Policy registry keys (real-time, behavior, IOAV, cloud protection)
#   2. MpPreference cmdlets (real-time, behavior, IOAV, cloud protection)
#   3. Defender service startup type set to Disabled
#   4. Scheduled tasks for Defender disabled
#
# PREREQUISITES:
#   - Must run as Administrator
#   - Tamper Protection MUST be turned off BEFORE running this script.
#     If Tamper Protection is ON, this script GATES: it prints the exact settings
#     path and exits with code 2 (tamper-blocked) without attempting any disable
#     steps, so the caller can guide the user to turn it off and retry.
#
# EXIT CODES:
#   0 = WinDefend Start=4 verified (permanent disable succeeded) and Tamper was off
#   1 = fatal error (e.g. not Administrator) OR critical WinDefend disable unverified
#   2 = tamper-blocked (Tamper Protection is ON; no disable steps attempted)
#
# Requirements: 21.1
# Called by:
#   - Inno Setup installer [Run] section during installation
#   - ps-runner.js via first-run.js on first app launch
#   - ps-runner.js via defender:runSetup IPC from Settings page

$ErrorActionPreference = "Continue"
$exitCode = 0
$successCount = 0
$failCount = 0

# Distinct exit code the orchestrator uses to surface a retryable "turn Tamper
# Protection off" state (see EXIT CODES in the header).
$TAMPER_BLOCKED_EXIT = 2

# Tracks whether the CRITICAL WinDefend service was verifiably set to Start=4.
# Success (exit 0) is ONLY returned when this is $true (and Tamper Protection was
# off). A plain-Administrator write to the WinDefend service key returns Access
# Denied because the key is owned by TrustedInstaller, so we elevate to SYSTEM.
$winDefendDisableVerified = $false

# -- Helper: run a command in the NT AUTHORITY\SYSTEM context ------------------
# The Defender service keys under HKLM\SYSTEM\CurrentControlSet\Services are owned
# by TrustedInstaller; a normal Administrator cannot change `Start` (Access Denied).
# We register a one-shot scheduled task that runs as NT AUTHORITY\SYSTEM, execute
# it, wait for completion, then remove it. Running as SYSTEM lets us take ownership
# of the key and grant write access before setting the value.
function Invoke-AsSystem {
    param(
        [Parameter(Mandatory = $true)] [string] $Command
    )

    $taskName = "GSMShield_DisableDefender_$([guid]::NewGuid().ToString('N'))"
    $encoded  = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))

    $action    = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount -RunLevel Highest
    $task      = New-ScheduledTask -Action $action -Principal $principal

    $registered = $false
    try {
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
        $registered = $true
    } catch {
        Write-Host "WARNING: Failed to register scheduled task '$taskName': $($_.Exception.Message)"
        return $false
    }

    try {
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

        # Wait for the one-shot task to finish (timeout increased to 90s).
        # LastTaskResult 267009 = task is currently running.
        $waitedMs = 0
        do {
            Start-Sleep -Milliseconds 500
            $waitedMs += 500
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        } while ($info -and $info.LastTaskResult -eq 267009 -and $waitedMs -lt 90000)

        # Check LastRunResult for success (0 = S_OK, 267009 = still running means timeout)
        $lastResult = if ($info) { $info.LastTaskResult } else { -1 }
        if ($lastResult -eq 267009) {
            Write-Host "WARNING: Scheduled task timed out after 90s (still running)"
            return $false
        } elseif ($lastResult -ne 0) {
            Write-Host "WARNING: Scheduled task completed with non-zero result: $lastResult"
            # Non-zero doesn't always mean failure for our purposes; continue and let
            # the caller verify the actual registry value.
        }
        return $true
    } catch {
        Write-Host "WARNING: Failed to start scheduled task '$taskName': $($_.Exception.Message)"
        return $false
    } finally {
        if ($registered) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

# -- Helper: disable a Defender service key via SYSTEM/TrustedInstaller --------
# Takes ownership of the service key, grants SYSTEM full control, sets Start=4,
# then (for the critical WinDefend service) verifies the value read-back equals 4.
function Set-DefenderServiceDisabled {
    param(
        [Parameter(Mandatory = $true)] [string] $ServiceName
    )

    $regPsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (-not (Test-Path $regPsPath)) {
        Write-Host "INFO: Service registry key not found: $ServiceName (may not be installed)"
        return $null
    }

    # Command executed in the SYSTEM context: take ownership of the TrustedInstaller-owned
    # key, grant SYSTEM FullControl, then set the service startup type to Disabled (Start=4).
    $systemCommand = @"
`$ErrorActionPreference = 'Stop'
`$sub = 'SYSTEM\CurrentControlSet\Services\$ServiceName'
`$sid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, `$null)
try {
    `$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
    `$acl = `$k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
    `$acl.SetOwner(`$sid)
    `$k.SetAccessControl(`$acl)
    `$k.Close()
} catch { }
try {
    `$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
    `$acl = `$k.GetAccessControl()
    `$rule = New-Object System.Security.AccessControl.RegistryAccessRule(`$sid, 'FullControl', 'ContainerInherit', 'None', 'Allow')
    `$acl.SetAccessRule(`$rule)
    `$k.SetAccessControl(`$acl)
    `$k.Close()
} catch { }
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName' -Name 'Start' -Value 4 -Type DWord -Force
"@

    # Primary approach: run as SYSTEM via scheduled task
    $taskSucceeded = Invoke-AsSystem -Command $systemCommand

    # Read-back verification after SYSTEM approach
    $startValue = (Get-ItemProperty -Path $regPsPath -Name "Start" -ErrorAction SilentlyContinue).Start

    # FALLBACK: If scheduled task approach failed or Start != 4, try direct
    # takeown + icacls + reg add from the current admin context.
    # Since the app already runs elevated (requireAdministrator manifest), this
    # may succeed on systems where the Task Scheduler is unavailable or busy.
    if ($startValue -ne 4) {
        Write-Host "INFO: Scheduled task approach did not verify Start=4 for $ServiceName - trying direct fallback"

        $regNativePath = "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName"
        try {
            # Take ownership from TrustedInstaller to Administrators
            $takeownResult = & takeown /f "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName" /r /d y 2>&1
            Write-Host "INFO: takeown output: $($takeownResult | Select-Object -First 2)"
        } catch {
            Write-Host "WARNING: takeown failed: $($_.Exception.Message)"
        }

        try {
            # Grant Administrators full control
            $icaclsResult = & icacls "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName" /grant Administrators:F /t 2>&1
            Write-Host "INFO: icacls output: $($icaclsResult | Select-Object -First 2)"
        } catch {
            Write-Host "WARNING: icacls failed: $($_.Exception.Message)"
        }

        try {
            # Use reg.exe to set the value directly (bypasses PS provider ACL issues)
            & reg add "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName" /v Start /t REG_DWORD /d 4 /f 2>&1 | Out-Null
            Write-Host "INFO: reg add command executed for $ServiceName"
        } catch {
            Write-Host "WARNING: reg add failed: $($_.Exception.Message)"
        }

        # Also attempt via .NET registry API with TakeOwnership rights
        try {
            $sub = "SYSTEM\CurrentControlSet\Services\$ServiceName"
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier(
                [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
            # Take ownership
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $sub,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::TakeOwnership)
            if ($k) {
                $acl = $k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
                $acl.SetOwner($adminSid)
                $k.SetAccessControl($acl)
                $k.Close()
            }
            # Grant full control
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $sub,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($k) {
                $acl = $k.GetAccessControl()
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $adminSid, 'FullControl', 'ContainerInherit', 'None', 'Allow')
                $acl.SetAccessRule($rule)
                $k.SetAccessControl($acl)
                $k.Close()
            }
            # Write Start=4
            Set-ItemProperty -Path $regPsPath -Name "Start" -Value 4 -Type DWord -Force
            Write-Host "INFO: .NET registry fallback executed for $ServiceName"
        } catch {
            Write-Host "WARNING: .NET registry fallback failed for $ServiceName`: $($_.Exception.Message)"
        }

        # Final read-back after fallback
        $startValue = (Get-ItemProperty -Path $regPsPath -Name "Start" -ErrorAction SilentlyContinue).Start
    }

    return $startValue
}

Write-Host "=========================================="
Write-Host "  GSM Shield AV - Disable Windows Defender"
Write-Host "=========================================="
Write-Host ""

# -- Check for Administrator privileges ---------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges"
    exit 1
}

Write-Host "INFO: Running with Administrator privileges"

# -- Check Tamper Protection status (GATE) ------------------------------------
# Tamper Protection silently reverts every Defender change while it is ON. Rather
# than warn and continue, block here: print the exact settings path and exit with
# a distinct tamper-blocked code so the caller can prompt the user and retry.
try {
    $tamperProtection = Get-MpComputerStatus -ErrorAction Stop | Select-Object -ExpandProperty IsTamperProtected
    if ($tamperProtection) {
        Write-Host "TAMPER-BLOCKED: Tamper Protection is ENABLED"
        Write-Host "TAMPER-BLOCKED: Disable steps were NOT attempted (they would be silently reverted)."
        Write-Host "TAMPER-BLOCKED: Turn Tamper Protection off, then retry:"
        Write-Host "TAMPER-BLOCKED:   Settings > Windows Security > Virus & threat protection > Virus & threat protection settings > Tamper Protection > Off"
        exit $TAMPER_BLOCKED_EXIT
    } else {
        Write-Host "INFO: Tamper Protection is disabled - all changes should apply"
    }
} catch {
    Write-Host "INFO: Could not check Tamper Protection status: $($_.Exception.Message)"
    Write-Host "INFO: Continuing with disabling steps..."
}

Write-Host ""

# ==============================================================================
# STEP 1: Group Policy Registry Keys
# These are the most reliable method when Tamper Protection is off.
# They persist across reboots and are respected by Defender.
# ==============================================================================
Write-Host "--- Step 1: Setting Group Policy registry keys ---"

# 1a. DisableRealtimeMonitoring - Disable real-time protection via policy
try {
    $realtimePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    if (-not (Test-Path $realtimePath)) {
        New-Item -Path $realtimePath -Force | Out-Null
    }
    Set-ItemProperty -Path $realtimePath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
    Write-Host "SUCCESS: Set Policy DisableRealtimeMonitoring = 1"
    $successCount++
} catch {
    Write-Host "FAILED: Policy DisableRealtimeMonitoring: $($_.Exception.Message)"
    $failCount++
}

# 1b. DisableBehaviorMonitoring - Disable behavior monitoring via policy
try {
    $realtimePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    Set-ItemProperty -Path $realtimePath -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
    Write-Host "SUCCESS: Set Policy DisableBehaviorMonitoring = 1"
    $successCount++
} catch {
    Write-Host "FAILED: Policy DisableBehaviorMonitoring: $($_.Exception.Message)"
    $failCount++
}

# 1c. DisableOnAccessProtection - Disable on-access file scanning via policy
try {
    Set-ItemProperty -Path $realtimePath -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force
    Write-Host "SUCCESS: Set Policy DisableOnAccessProtection = 1"
    $successCount++
} catch {
    Write-Host "FAILED: Policy DisableOnAccessProtection: $($_.Exception.Message)"
    $failCount++
}

# 1d. DisableIOAVProtection - Disable scanning of downloaded files via policy
try {
    Set-ItemProperty -Path $realtimePath -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force
    Write-Host "SUCCESS: Set Policy DisableIOAVProtection = 1"
    $successCount++
} catch {
    Write-Host "FAILED: Policy DisableIOAVProtection: $($_.Exception.Message)"
    $failCount++
}

# 1e. Disable Defender cloud-based protection (SpyNet) via policy
try {
    $spynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    if (-not (Test-Path $spynetPath)) {
        New-Item -Path $spynetPath -Force | Out-Null
    }
    Set-ItemProperty -Path $spynetPath -Name "SpynetReporting" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $spynetPath -Name "SubmitSamplesConsent" -Value 2 -Type DWord -Force
    Write-Host "SUCCESS: Disabled cloud-based protection (SpyNet)"
    $successCount++
} catch {
    Write-Host "FAILED: SpyNet policy: $($_.Exception.Message)"
    $failCount++
}

Write-Host ""

# ==============================================================================
# STEP 2: MpPreference Cmdlets
# Direct Defender preference changes - immediate effect but may be reverted
# by Tamper Protection if it's enabled.
# ==============================================================================
Write-Host "--- Step 2: Setting MpPreference values ---"

# 2a. Disable real-time monitoring
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-Host "SUCCESS: MpPreference DisableRealtimeMonitoring = True"
    $successCount++
} catch {
    Write-Host "FAILED: MpPreference DisableRealtimeMonitoring: $($_.Exception.Message)"
    $failCount++
}

# 2b. Disable behavior monitoring
try {
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
    Write-Host "SUCCESS: MpPreference DisableBehaviorMonitoring = True"
    $successCount++
} catch {
    Write-Host "FAILED: MpPreference DisableBehaviorMonitoring: $($_.Exception.Message)"
    $failCount++
}

# 2c. Disable IOAV protection (scanning downloaded files)
try {
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
    Write-Host "SUCCESS: MpPreference DisableIOAVProtection = True"
    $successCount++
} catch {
    Write-Host "FAILED: MpPreference DisableIOAVProtection: $($_.Exception.Message)"
    $failCount++
}

# 2d. Disable script scanning
try {
    Set-MpPreference -DisableScriptScanning $true -ErrorAction Stop
    Write-Host "SUCCESS: MpPreference DisableScriptScanning = True"
    $successCount++
} catch {
    Write-Host "FAILED: MpPreference DisableScriptScanning: $($_.Exception.Message)"
    $failCount++
}

# 2e. Disable cloud-based protection
try {
    Set-MpPreference -MAPSReporting 0 -ErrorAction Stop
    Write-Host "SUCCESS: MpPreference MAPSReporting = 0 (Disabled)"
    $successCount++
} catch {
    Write-Host "FAILED: MpPreference MAPSReporting: $($_.Exception.Message)"
    $failCount++
}

# 2f. Disable automatic sample submission
try {
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop
    Write-Host "SUCCESS: MpPreference SubmitSamplesConsent = 2 (Never send)"
    $successCount++
} catch {
    Write-Host "FAILED: MpPreference SubmitSamplesConsent: $($_.Exception.Message)"
    $failCount++
}

Write-Host ""

# ==============================================================================
# STEP 3: Disable Defender Services (SYSTEM/TrustedInstaller elevation)
# Change startup type to Disabled (Start=4) so Defender doesn't restart after
# reboot. The service keys are owned by TrustedInstaller, so a plain-Administrator
# write returns Access Denied and Defender is silently re-enabled on next boot.
# Each key is disabled from the NT AUTHORITY\SYSTEM context (one-shot scheduled
# task) which takes ownership, grants write access, and sets Start=4. The critical
# WinDefend value is then verified via read-back before we report success.
# ==============================================================================
Write-Host "--- Step 3: Disabling Defender services (elevated to SYSTEM) ---"

$defenderServices = @(
    @{ Name = "WinDefend";     Desc = "Microsoft Defender Antivirus Service" },
    @{ Name = "WdNisSvc";      Desc = "Microsoft Defender Network Inspection Service" },
    @{ Name = "WdNisDrv";      Desc = "Microsoft Defender Network Inspection Driver" },
    @{ Name = "WdFilter";      Desc = "Microsoft Defender Mini-Filter Driver" },
    @{ Name = "WdBoot";        Desc = "Microsoft Defender Boot Driver" }
)

foreach ($svc in $defenderServices) {
    # Stop the service (best effort - it may be protected while running)
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            Write-Host "SUCCESS: Stopped service $($svc.Name) ($($svc.Desc))"
        }
    } catch {
        Write-Host "INFO: Could not stop $($svc.Name): $($_.Exception.Message)"
    }

    # Disable the service startup via the SYSTEM/TrustedInstaller elevated path.
    try {
        $startValue = Set-DefenderServiceDisabled -ServiceName $svc.Name
        if ($null -eq $startValue) {
            # Key not present (service not installed) - nothing to disable.
            continue
        }

        if ($startValue -eq 4) {
            Write-Host "SUCCESS: Disabled service startup (verified Start=4): $($svc.Name)"
            $successCount++
            if ($svc.Name -eq "WinDefend") {
                $winDefendDisableVerified = $true
            }
        } else {
            Write-Host "FAILED: Could not verify Start=4 for $($svc.Name) (Start=$startValue)"
            $failCount++
        }
    } catch {
        Write-Host "FAILED: Disable service $($svc.Name): $($_.Exception.Message)"
        $failCount++
    }
}

Write-Host ""

# ==============================================================================
# STEP 4: Disable Defender Scheduled Tasks
# Prevent Defender from re-enabling itself via scheduled maintenance tasks.
# ==============================================================================
Write-Host "--- Step 4: Disabling Defender scheduled tasks ---"

$defenderTasks = @(
    "Windows Defender Cache Maintenance",
    "Windows Defender Cleanup",
    "Windows Defender Scheduled Scan",
    "Windows Defender Verification"
)

foreach ($taskName in $defenderTasks) {
    try {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
            Write-Host "SUCCESS: Disabled scheduled task: $taskName"
            $successCount++
        } else {
            Write-Host "INFO: Scheduled task not found: $taskName"
        }
    } catch {
        Write-Host "FAILED: Disable task '$taskName': $($_.Exception.Message)"
        $failCount++
    }
}

Write-Host ""

# ==============================================================================
# STEP 5: Disable Windows Security Center notifications for Defender
# Suppress the "No antivirus provider found" warnings in the tray
# ==============================================================================
Write-Host "--- Step 5: Suppressing Defender notifications ---"

try {
    $notifyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"
    if (-not (Test-Path $notifyPath)) {
        New-Item -Path $notifyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $notifyPath -Name "DisableNotifications" -Value 1 -Type DWord -Force
    Write-Host "SUCCESS: Disabled Windows Security Center notifications"
    $successCount++
} catch {
    Write-Host "FAILED: Disable notifications: $($_.Exception.Message)"
    $failCount++
}

# Suppress "action required" notifications
try {
    $enhancedNotifyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"
    Set-ItemProperty -Path $enhancedNotifyPath -Name "DisableEnhancedNotifications" -Value 1 -Type DWord -Force
    Write-Host "SUCCESS: Disabled enhanced notifications"
    $successCount++
} catch {
    Write-Host "FAILED: Disable enhanced notifications: $($_.Exception.Message)"
    $failCount++
}

Write-Host ""

# ==============================================================================
# STEP 6: Disable Defender tray icon
# Remove the Defender shield icon from the system tray
# ==============================================================================
Write-Host "--- Step 6: Disabling Defender system tray icon ---"

try {
    $trayPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray"
    if (-not (Test-Path $trayPath)) {
        New-Item -Path $trayPath -Force | Out-Null
    }
    Set-ItemProperty -Path $trayPath -Name "HideSystray" -Value 1 -Type DWord -Force
    Write-Host "SUCCESS: Hidden Defender system tray icon"
    $successCount++
} catch {
    Write-Host "FAILED: Hide systray: $($_.Exception.Message)"
    $failCount++
}

Write-Host ""

# ==============================================================================
# SUMMARY
# ==============================================================================
Write-Host "=========================================="
Write-Host "  RESULTS"
Write-Host "=========================================="
Write-Host "  Successful steps: $successCount"
Write-Host "  Failed steps:     $failCount"
Write-Host "  WinDefend Start=4 verified: $winDefendDisableVerified"
Write-Host ""

# Exit semantics (Requirements 2.1, 2.2, 2.6):
#   - Tamper-blocked (code 2) is handled and returned earlier, before any step.
#   - Success (0) is returned ONLY when the CRITICAL WinDefend service was
#     verifiably disabled (Start=4 read-back) - this is what makes the disable
#     survive auto-re-enable across reboots. The MpPreference/policy changes alone
#     leave Defender able to re-activate, so they do NOT qualify as success.
#   - Otherwise return non-zero: the critical service disable could not be verified.
if ($winDefendDisableVerified) {
    Write-Host "SUCCESS: WinDefend permanently disabled (Start=4 verified via SYSTEM/TrustedInstaller)"
    if ($failCount -gt 0) {
        Write-Host "INFO: $failCount non-critical step(s) failed but the WinDefend disable is verified"
    }
    Write-Host "INFO: A restart may be required for all changes to take full effect"
    $exitCode = 0
} else {
    Write-Host "ERROR: Critical WinDefend service disable could not be verified (Start != 4)"
    Write-Host "ERROR: Defender may re-enable itself on reboot - the disable did not take effect"
    Write-Host "ERROR: Ensure Tamper Protection is off and re-run this script"
    $exitCode = 1
}

Write-Host ""
Write-Host "SUCCESS: disable-defender step complete"
exit $exitCode
