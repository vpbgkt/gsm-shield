# enforce-defender-disabled.ps1
# Lightweight watchdog: ensures Windows Defender stays disabled.
#
# Designed to be run repeatedly by a scheduled task ("GSMShield_DefenderWatchdog")
# that runs as NT AUTHORITY\SYSTEM at startup and on a recurring interval. Windows
# Update and Defender platform updates can silently reset the WinDefend service
# start type back to Automatic; this script detects that and re-applies Start=4.
#
# It is intentionally fast and idempotent:
#   - If WinDefend is already Start=4, it logs and exits 0 without further work.
#   - Otherwise it re-applies the critical service disable + real-time policy.
#
# Running context: expected to run as SYSTEM (via the watchdog task) or as an
# elevated Administrator. When running as SYSTEM it can write the
# TrustedInstaller-owned service keys directly after taking ownership.
#
# EXIT CODES:
#   0 = Defender is (or was made) disabled
#   1 = could not enforce the disable (e.g. not elevated)
#
# Requirements: 2.6 (disable survives auto-re-enable)

$ErrorActionPreference = "Continue"

$logDir = Join-Path $env:ProgramData 'GSMShieldAV'
try { if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null } } catch { }
$logFile = Join-Path $logDir 'defender-watchdog.log'
function WLog($m) {
    $line = "[" + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + "] " + $m
    try { Add-Content -Path $logFile -Value $line -Encoding ascii } catch { }
}

# Services that must remain disabled (Start=4). WdFilter/WdBoot are drivers.
$services = 'WinDefend','WdNisSvc','WdNisDrv','WdFilter','WdBoot'

function Get-StartValue($name) {
    try { return (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name Start -ErrorAction Stop).Start } catch { return $null }
}

function Set-ServiceDisabled($name) {
    $regPs = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (-not (Test-Path $regPs)) { return $null }
    # Take ownership + grant Administrators full control, then set Start=4.
    try { & takeown /f "HKLM\SYSTEM\CurrentControlSet\Services\$name" /d y 2>&1 | Out-Null } catch { }
    try { & icacls "HKLM\SYSTEM\CurrentControlSet\Services\$name" /grant Administrators:F 2>&1 | Out-Null } catch { }
    try { & reg add "HKLM\SYSTEM\CurrentControlSet\Services\$name" /v Start /t REG_DWORD /d 4 /f 2>&1 | Out-Null } catch { }
    # .NET fallback (works when running as SYSTEM)
    try {
        $sub = "SYSTEM\CurrentControlSet\Services\$name"
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        if ($k) { $acl = $k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None); $acl.SetOwner($adminSid); $k.SetAccessControl($acl); $k.Close() }
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($k) { $acl = $k.GetAccessControl(); $rule = New-Object System.Security.AccessControl.RegistryAccessRule($adminSid, 'FullControl', 'ContainerInherit', 'None', 'Allow'); $acl.SetAccessRule($rule); $k.SetAccessControl($acl); $k.Close() }
        Set-ItemProperty -Path $regPs -Name 'Start' -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch { }
    return (Get-StartValue $name)
}

# -- Fast path: already disabled? ---------------------------------------------
$winStart = Get-StartValue 'WinDefend'
if ($winStart -eq 4) {
    WLog "OK: WinDefend already Start=4 (no action)."
    exit 0
}

WLog "DRIFT DETECTED: WinDefend Start=$winStart (expected 4). Re-applying disable."

# Re-apply the real-time protection policy (cheap, always safe)
try {
    $rt = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    if (-not (Test-Path $rt)) { New-Item -Path $rt -Force | Out-Null }
    Set-ItemProperty -Path $rt -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
} catch { WLog "WARN: could not set real-time policy: $($_.Exception.Message)" }

# Re-apply the service disable for each service
$allDisabled = $true
foreach ($s in $services) {
    $v = Set-ServiceDisabled $s
    if ($null -eq $v) { continue }   # service not installed
    if ($v -eq 4) { WLog "SUCCESS: $s Start=4" } else { WLog "FAILED: $s Start=$v"; if ($s -eq 'WinDefend') { $allDisabled = $false } }
}

if ($allDisabled) { WLog "DONE: Defender disable re-enforced."; exit 0 } else { WLog "ERROR: could not verify WinDefend Start=4 (not elevated?)."; exit 1 }
