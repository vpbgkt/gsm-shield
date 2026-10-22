<#
.SYNOPSIS
  Read-only evidence collection for an Expiro investigation (see research/INVESTIGATION_CHECKLIST.md).

.DESCRIPTION
  Collects, without changing anything on the system:
    - OS / clock / privilege context
    - Defender status, threat catalogue and full detection history (ISO timestamps, one row per resource)
    - Defender operational events (detections, remediation, real-time/tamper changes)
    - Service Control Manager events (7040 start-type changes, 7045 installs, 7034 crashes)
    - All services with start type, binary path and signature status
    - Running processes (paths visible to the current account) with signature status
    - Non-Microsoft scheduled tasks, Run/RunOnce keys, startup folders, Startup shell-folder values
    - Published Expiro IOCs: %APPDATA%\<16 hex>.bin, %SystemRoot%\System32\gazt_mx_dis
    - Optional structural PE sweep (Expiro-StructScan.ps1) with -Sweep
  Run once as a standard user and once elevated: elevation adds the Defender quarantine list and
  folders a standard user cannot read. Output: a timestamped folder of CSV/TXT files.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Collect-ExpiroEvidence.ps1 -OutDir D:\evidence -Sweep -SweepRoots C:\,D:\
#>
param(
  [string]$OutDir = (Join-Path $PWD ("expiro-evidence-{0:yyyyMMdd-HHmmss}" -f (Get-Date))),
  [switch]$Sweep,
  [string[]]$SweepRoots = @('C:\')
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$iso = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd HH:mm:ss') } }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function Save {
  param([Parameter(Position = 0)][string]$name, [Parameter(Position = 1, ValueFromPipeline = $true)]$data)
  begin { $all = New-Object System.Collections.Generic.List[object] }
  process { foreach ($d in @($data)) { if ($null -ne $d) { $all.Add($d) } } }
  end { $all | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $OutDir $name) }
}
function Note($text) { Add-Content -Encoding UTF8 (Join-Path $OutDir 'summary.txt') $text; Write-Host $text }

$os = Get-CimInstance Win32_OperatingSystem
Note ("Collected {0} by {1} elevated={2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'), [Security.Principal.WindowsIdentity]::GetCurrent().Name, $admin)
Note ("OS {0} {1} InstallDate={2} LastBoot={3}" -f $os.Caption, $os.Version, (& $iso $os.InstallDate), (& $iso $os.LastBootUpTime))
Note "NOTE: if InstallDate or detection times are later than 'now', the clock was wrong during setup; order events by boot sessions, not wall time."

# Defender
try {
  $st = Get-MpComputerStatus
  $st | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AMEngineVersion, AMProductVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, FullScanEndTime | Format-List | Out-File -Encoding utf8 (Join-Path $OutDir 'defender_status.txt')
  $names = @{}; Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = $_.ThreatName }
  $rows = foreach ($d in Get-MpThreatDetection) { foreach ($r in @($d.Resources)) { $kind, $path = ($r -split ':_', 2)
      [pscustomobject]@{ ThreatName = $names[[string]$d.ThreatID]; Initial = & $iso $d.InitialDetectionTime; LastChange = & $iso $d.LastThreatStatusChangeTime; Process = $d.ProcessName
        StatusID = $d.ThreatStatusID; ErrorCode = ('0x{0:X8}' -f $d.ThreatStatusErrorCode); ExecStatus = $d.CurrentThreatExecutionStatusID; Kind = $kind; Path = $path } } }
  Save 'defender_detections.csv' $rows
  Note ("Defender detections: {0} resource rows; threat names: {1}" -f @($rows).Count, (($rows | Group-Object ThreatName | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '))
  Note "ThreatStatusID: 1 Detected, 2 Cleaned, 3 Quarantined, 4 Removed, 102 Quarantine/CleanFailed (docs disagree), 103 RemoveFailed, 106 Abandoned (MpClient.h)."
} catch { Note "Defender query failed: $_" }
if ($admin) {
  try { & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Restore -ListAll 2>&1 | Out-File -Encoding utf8 (Join-Path $OutDir 'defender_quarantine_list.txt') } catch { Note "Quarantine list failed: $_" }
}
try {
  Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1006, 1007, 1008, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012 } -ErrorAction Stop |
    Select-Object @{ n = 'Time'; e = { & $iso $_.TimeCreated } }, Id, @{ n = 'Message'; e = { ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(600, ($_.Message -replace '\s+', ' ').Length)) } } |
    Save 'defender_events.csv'
} catch { Note "Defender event log: $_" }

# SCM events
try {
  Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7040, 7045, 7034, 7031, 7000, 7009 } -ErrorAction Stop |
    Select-Object @{ n = 'Time'; e = { & $iso $_.TimeCreated } }, Id, @{ n = 'Message'; e = { $_.Message -replace '\s+', ' ' } } | Save 'scm_events.csv'
  $esc = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7040 } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'to auto start' }
  Note ("SCM 7040 'changed ... to auto start' events: {0}" -f @($esc).Count)
} catch { Note "SCM log: $_" }

# Services
function ImgPath($pn) { if (-not $pn) { return $null }; $pn = [Environment]::ExpandEnvironmentVariables($pn); if ($pn -match '^"([^"]+)"') { return $matches[1] }; if ($pn -match '^(.+?\.exe)') { return $matches[1] }; $pn }
$svc = foreach ($s in Get-CimInstance Win32_Service) { $img = ImgPath $s.PathName; $sig = 'n/a'
  if ($img -and (Test-Path -LiteralPath $img)) { $sig = (Get-AuthenticodeSignature -LiteralPath $img).Status } elseif ($img) { $sig = 'MISSING' }
  [pscustomobject]@{ Name = $s.Name; State = $s.State; StartMode = $s.StartMode; Account = $s.StartName; Signature = $sig; Image = $img } }
Save 'services.csv' $svc
Note ("Services with non-Valid binaries: {0}" -f (($svc | Where-Object { $_.Signature -notin 'Valid', 'n/a' } | ForEach-Object { "$($_.Name)[$($_.StartMode)/$($_.Signature)]" }) -join ', '))

# Processes
$seen = @{}
$procs = foreach ($p in Get-CimInstance Win32_Process) { $e = $p.ExecutablePath; $sig = ''
  if ($e) { if (-not $seen.ContainsKey($e)) { $seen[$e] = (Get-AuthenticodeSignature -LiteralPath $e -ErrorAction SilentlyContinue).Status }; $sig = $seen[$e] }
  [pscustomobject]@{ PID = $p.ProcessId; PPID = $p.ParentProcessId; Name = $p.Name; Created = & $iso $p.CreationDate; Signature = $sig; Path = $e } }
Save 'processes.csv' $procs

# Persistence
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } | ForEach-Object {
  [pscustomobject]@{ Path = $_.TaskPath; Name = $_.TaskName; State = $_.State; Actions = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ') } } | Save 'scheduled_tasks_non_microsoft.csv'
$run = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {
  $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value } } } }
Save 'run_keys.csv' $run
$sf = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') {
  $v = Get-ItemProperty $k -ErrorAction SilentlyContinue; [pscustomobject]@{ Key = $k; Startup = $v.Startup; CommonStartup = $v.'Common Startup' } }
Save 'startup_shell_folders.csv' $sf
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, @{ n = 'Written'; e = { & $iso $_.LastWriteTime } } | Save 'startup_folders.csv'

# IOCs
$ioc = @()
Get-ChildItem $env:APPDATA, $env:LOCALAPPDATA -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-f]{16}\.bin$' } | ForEach-Object {
  $ioc += [pscustomobject]@{ Indicator = 'AppData <16hex>.bin (Seqrite/Quick Heal: encrypted stolen browser data)'; Path = $_.FullName; Detail = "size=$($_.Length) created=$(& $iso $_.CreationTime) sha256=$((Get-FileHash $_.FullName -Algorithm SHA256).Hash)" } }
if (Test-Path "$env:SystemRoot\System32\gazt_mx_dis") { $ioc += [pscustomobject]@{ Indicator = 'gazt_mx_dis marker (Stop Malvertising)'; Path = "$env:SystemRoot\System32\gazt_mx_dis"; Detail = '' } }
Save 'iocs.csv' $ioc
Note ("IOC hits: {0}" -f @($ioc).Count)

if ($Sweep) {
  $scan = Join-Path $PSScriptRoot 'Expiro-StructScan.ps1'
  & $scan -Roots $SweepRoots -OutCsv (Join-Path $OutDir 'structural_sweep.csv') | Select-Object -Last 3 | ForEach-Object { Note $_ }
}
Note "Done. Output: $OutDir"
