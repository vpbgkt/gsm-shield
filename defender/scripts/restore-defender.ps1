# restore-defender.ps1
# Reverses all changes made by disable-defender.ps1 and removes
# GSM Shield AV's WSC registration, fully restoring Windows Defender.
#
# Called by the Inno Setup uninstaller with -ExecutionPolicy Bypass -NonInteractive.
#
# This script reverses:
#   1. Group Policy registry keys (removes DisableAntiSpyware, etc.)
#   2. MpPreference settings (re-enables real-time, behavior, IOAV, cloud)
#   3. Defender service startup types (set back to Automatic)
#   4. Defender scheduled tasks (re-enabled)
#   5. Notifications and tray icon (re-enabled)
#   6. WSC Provider registry keys (removed)
#
# Requirements: 21.5

$ErrorActionPreference = "Continue"
$exitCode = 0

# ── Fixed product GUID — must match register-wsc.ps1 ────────────────────────
$PRODUCT_GUID = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
$PRODUCT_KEY_NAME = "Av_$PRODUCT_GUID"
$PRODUCT_DISPLAY_NAME = "GSM Shield AV"

Write-Host "=========================================="
Write-Host "  GSM Shield AV — Restore Windows Defender"
Write-Host "=========================================="
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1: Remove Group Policy Registry Keys
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "--- Step 1: Removing Group Policy registry keys ---"

# 1a. Remove DisableAntiSpyware
try {
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "DisableAntiSpyware" -Force -ErrorAction SilentlyContinue
        Write-Host "SUCCESS: Removed DisableAntiSpyware policy"
    }
} catch {
    Write-Host "INFO: Could not remove DisableAntiSpyware: $($_.Exception.Message)"
}

# 1b. Remove Real-Time Protection policies
try {
    $realtimePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    if (Test-Path $realtimePath) {
        Remove-Item -Path $realtimePath -Recurse -Force -ErrorAction Stop
        Write-Host "SUCCESS: Removed Real-Time Protection policy keys"
    }
} catch {
    Write-Host "INFO: Could not remove Real-Time Protection policies: $($_.Exception.Message)"
}

# 1c. Remove SpyNet/MAPS policies
try {
    $spynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    if (Test-Path $spynetPath) {
        Remove-Item -Path $spynetPath -Recurse -Force -ErrorAction Stop
        Write-Host "SUCCESS: Removed SpyNet policy keys"
    }
} catch {
    Write-Host "INFO: Could not remove SpyNet policies: $($_.Exception.Message)"
}

# 1d. Remove the entire Windows Defender policy key if it's empty
try {
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (Test-Path $policyPath) {
        $subKeys = Get-ChildItem -Path $policyPath -ErrorAction SilentlyContinue
        $properties = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
        # Only remove if we left it empty (don't remove other vendors' policies)
        if ($null -eq $subKeys -or $subKeys.Count -eq 0) {
            # Check if there are any remaining values
            $propNames = ($properties.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') }).Name
            if ($null -eq $propNames -or $propNames.Count -eq 0) {
                Remove-Item -Path $policyPath -Force -ErrorAction SilentlyContinue
                Write-Host "INFO: Cleaned up empty Windows Defender policy key"
            }
        }
    }
} catch {
    Write-Host "INFO: Policy key cleanup: $($_.Exception.Message)"
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2: Re-enable Defender via MpPreference
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "--- Step 2: Re-enabling Defender via MpPreference ---"

try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "SUCCESS: Re-enabled real-time monitoring"
} catch {
    Write-Host "INFO: Could not re-enable real-time monitoring: $($_.Exception.Message)"
}

try {
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
    Write-Host "SUCCESS: Re-enabled behavior monitoring"
} catch {
    Write-Host "INFO: Could not re-enable behavior monitoring: $($_.Exception.Message)"
}

try {
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
    Write-Host "SUCCESS: Re-enabled IOAV protection"
} catch {
    Write-Host "INFO: Could not re-enable IOAV protection: $($_.Exception.Message)"
}

try {
    Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
    Write-Host "SUCCESS: Re-enabled script scanning"
} catch {
    Write-Host "INFO: Could not re-enable script scanning: $($_.Exception.Message)"
}

try {
    Set-MpPreference -MAPSReporting 2 -ErrorAction Stop
    Write-Host "SUCCESS: Re-enabled cloud-based protection (MAPS)"
} catch {
    Write-Host "INFO: Could not re-enable MAPS: $($_.Exception.Message)"
}

try {
    Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction Stop
    Write-Host "SUCCESS: Re-enabled automatic sample submission"
} catch {
    Write-Host "INFO: Could not re-enable sample submission: $($_.Exception.Message)"
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: Re-enable Defender Services
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "--- Step 3: Re-enabling Defender services ---"

$defenderServices = @(
    @{ Name = "WinDefend";  Start = 2; Desc = "Microsoft Defender Antivirus Service" },
    @{ Name = "WdNisSvc";   Start = 3; Desc = "Microsoft Defender Network Inspection Service" },
    @{ Name = "WdNisDrv";   Start = 3; Desc = "Microsoft Defender Network Inspection Driver" },
    @{ Name = "WdFilter";   Start = 0; Desc = "Microsoft Defender Mini-Filter Driver" },
    @{ Name = "WdBoot";     Start = 0; Desc = "Microsoft Defender Boot Driver" }
)

foreach ($svc in $defenderServices) {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "Start" -Value $svc.Start -Type DWord -Force
            Write-Host "SUCCESS: Re-enabled service: $($svc.Name) (Start=$($svc.Start))"
        }
    } catch {
        Write-Host "INFO: Could not re-enable $($svc.Name): $($_.Exception.Message)"
    }
}

# Try to start the main Defender service
try {
    Start-Service -Name "WinDefend" -ErrorAction Stop
    Write-Host "SUCCESS: Started WinDefend service"
} catch {
    Write-Host "INFO: Could not start WinDefend (will start on next reboot): $($_.Exception.Message)"
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: Re-enable Defender Scheduled Tasks
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "--- Step 4: Re-enabling Defender scheduled tasks ---"

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
            Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
            Write-Host "SUCCESS: Re-enabled scheduled task: $taskName"
        }
    } catch {
        Write-Host "INFO: Could not re-enable task '$taskName': $($_.Exception.Message)"
    }
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: Re-enable Notifications and Tray Icon
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "--- Step 5: Re-enabling notifications and tray icon ---"

try {
    $notifyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"
    if (Test-Path $notifyPath) {
        Remove-Item -Path $notifyPath -Recurse -Force -ErrorAction Stop
        Write-Host "SUCCESS: Restored notifications"
    }
} catch {
    Write-Host "INFO: Could not restore notifications: $($_.Exception.Message)"
}

try {
    $trayPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray"
    if (Test-Path $trayPath) {
        Remove-Item -Path $trayPath -Recurse -Force -ErrorAction Stop
        Write-Host "SUCCESS: Restored system tray icon"
    }
} catch {
    Write-Host "INFO: Could not restore tray icon: $($_.Exception.Message)"
}

# Clean up Security Center policy key if empty
try {
    $secCenterPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center"
    if (Test-Path $secCenterPolicyPath) {
        $remaining = Get-ChildItem -Path $secCenterPolicyPath -ErrorAction SilentlyContinue
        if ($null -eq $remaining -or $remaining.Count -eq 0) {
            Remove-Item -Path $secCenterPolicyPath -Force -ErrorAction SilentlyContinue
            Write-Host "INFO: Cleaned up empty Security Center policy key"
        }
    }
} catch {
    Write-Host "INFO: Security Center policy cleanup: $($_.Exception.Message)"
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6: Remove WSC Provider Registry Keys
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "--- Step 6: Removing WSC registration ---"

try {
    $providerKeyPath = "SOFTWARE\Microsoft\Security Center\Provider"
    $hklm = [Microsoft.Win32.Registry]::LocalMachine
    $providerKey = $hklm.OpenSubKey($providerKeyPath, $true)

    if ($null -ne $providerKey) {
        $removedCount = 0
        $subKeys = $providerKey.GetSubKeyNames()

        foreach ($subKeyName in $subKeys) {
            $shouldRemove = $false

            # Always remove our fixed-GUID key
            if ($subKeyName -eq $PRODUCT_KEY_NAME) {
                $shouldRemove = $true
            }
            # Also remove any other Av_* key with our display name (stale duplicates)
            elseif ($subKeyName -like "Av_*") {
                try {
                    $subKey = $providerKey.OpenSubKey($subKeyName, $false)
                    if ($null -ne $subKey) {
                        $displayName = $subKey.GetValue("displayName")
                        $subKey.Close()
                        if ($displayName -eq $PRODUCT_DISPLAY_NAME) {
                            $shouldRemove = $true
                        }
                    }
                } catch {
                    Write-Host "WARNING: Could not inspect key '$subKeyName': $($_.Exception.Message)"
                }
            }

            if ($shouldRemove) {
                try {
                    $providerKey.DeleteSubKeyTree($subKeyName, $false)
                    Write-Host "SUCCESS: Removed WSC registration key: $subKeyName"
                    $removedCount++
                } catch {
                    Write-Host "ERROR: Failed to remove key '$subKeyName': $($_.Exception.Message)"
                    $exitCode = 1
                }
            }
        }

        $providerKey.Close()

        if ($removedCount -eq 0) {
            Write-Host "INFO: No GSM Shield AV WSC registration found (already clean)"
        } else {
            Write-Host "SUCCESS: Removed $removedCount GSM Shield AV registration(s)"
        }
    } else {
        Write-Host "INFO: Security Center Provider key not found (nothing to clean up)"
    }
} catch {
    Write-Host "ERROR: Failed to clean WSC registration: $_"
    $exitCode = 1
}

Write-Host ""
Write-Host "=========================================="
Write-Host "  RESTORE COMPLETE"
Write-Host "=========================================="
Write-Host "INFO: Windows Defender should re-enable on next reboot"
Write-Host "INFO: If Defender doesn't restart automatically, reboot the machine"
Write-Host ""
Write-Host "SUCCESS: restore-defender step complete"
exit $exitCode
