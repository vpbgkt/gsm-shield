<#
.SYNOPSIS
  Repair Windows system files that Expiro infected (or another antivirus deleted), using DISM and SFC.

.DESCRIPTION
  Run as administrator after Expiro-Remover.ps1 -Mode Remediate.
    1. DISM /Online /Cleanup-Image /RestoreHealth   (repairs the component store from Windows Update,
                                                      or from -Source <install.wim> of verified media)
    2. sfc /scannow                                  (restores System32 files from the repaired store)
    3. Re-checks the files listed with -Check (default: infected protected files from the last
       Remediate state.json, if given) for the Expiro layout and Authenticode signature.
    4. Lists services whose registry keys are missing for well-known Windows service binaries
       (SFC restores files, not service registrations; those need an in-place upgrade).
  Writes log.txt and a DONE marker in -ReportDir. Changes nothing else.
#>
param(
  [string]$ReportDir = (Join-Path $env:ProgramData ("ExpiroRemover\reports\{0:yyyyMMdd-HHmmss}-repair" -f (Get-Date))),
  [string]$StateFile,
  [string[]]$Check = @(),
  [string]$Source
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $ReportDir | Out-Null
function Log([string]$m) { $l = "{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $l; Add-Content -Encoding UTF8 (Join-Path $ReportDir 'log.txt') $l }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Log 'Must run as administrator.'; exit 1 }
if ($StateFile -and (Test-Path $StateFile)) { $Check += @((Get-Content $StateFile -Raw | ConvertFrom-Json).protectedLeftInPlace) }
$Check = $Check | Where-Object { $_ } | Sort-Object -Unique

Log 'DISM RestoreHealth started (can take 10-30 minutes)'
$dismArgs = @('/Online', '/Cleanup-Image', '/RestoreHealth')
if ($Source) { $dismArgs += @("/Source:$Source", '/LimitAccess') }
& "$env:SystemRoot\System32\Dism.exe" @dismArgs 2>&1 | Out-File -Encoding utf8 (Join-Path $ReportDir 'dism.txt')
Log "DISM exit code $LASTEXITCODE (0 = success; see dism.txt)"

Log 'sfc /scannow started'
& "$env:SystemRoot\System32\sfc.exe" /scannow 2>&1 | ForEach-Object { $_ -replace "`0", '' } | Out-File -Encoding utf8 (Join-Path $ReportDir 'sfc.txt')
Log "SFC exit code $LASTEXITCODE (see sfc.txt and %windir%\Logs\CBS\CBS.log)"

foreach ($f in $Check) {
  if (-not (Test-Path -LiteralPath $f)) { Log "check: $f MISSING"; continue }
  $sig = (Get-AuthenticodeSignature -LiteralPath $f).Status
  $b = [IO.File]::ReadAllBytes($f); $pe = [BitConverter]::ToInt32($b, 0x3C); $ns = [BitConverter]::ToUInt16($b, $pe + 6); $opt = [BitConverter]::ToUInt16($b, $pe + 20)
  $last = $pe + 24 + $opt + ($ns - 1) * 40; $chars = [BitConverter]::ToUInt32($b, $last + 36); $name = [Text.Encoding]::ASCII.GetString($b, $last, 8).TrimEnd([char]0)
  $exec = ($chars -band 0x20000000) -ne 0
  Log ("check: {0} signature={1} lastSection={2} executable={3} -> {4}" -f $f, $sig, $name, $exec, $(if ($sig -eq 'Valid' -and -not $exec) { 'REPAIRED' } else { 'STILL INFECTED/UNVERIFIED' }))
}

$expected = @{ sppsvc = 'sppsvc.exe'; COMSysApp = 'dllhost.exe'; PerfHost = 'perfhost.exe'; midisrv = 'MidiSrv.exe'; SensorDataService = 'SensorDataService.exe'; perceptionsimulation = 'PerceptionSimulationService.exe'; ReFsDedupSvc = 'ReFsDedupSvc.exe'; WMPNetworkSvc = 'wmpnetwk.exe' }
foreach ($k in $expected.Keys) {
  if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$k")) { Log "service registration missing: $k ($($expected[$k])) - restore with an in-place upgrade (setup.exe from verified Windows media, keep files and apps)" }
}
Log 'Repair finished.'
New-Item -ItemType File -Force (Join-Path $ReportDir 'DONE') | Out-Null
