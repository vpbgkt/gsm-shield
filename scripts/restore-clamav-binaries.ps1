<#
.SYNOPSIS
  Restore assets/clamav/*.exe from the official ClamAV 1.5.4 release and verify them.

.DESCRIPTION
  Downloads clamav-1.5.4.win.x64.zip from the official GitHub release, checks its SHA-256
  against the release digest, extracts the five executables GSM Shield launches directly
  from the zip in memory, writes them to assets/clamav, and verifies each against
  assets/clamav/clamav-binaries.sha256.json. Needs neither Git nor Node.

  Run it only after the machine is free of Expiro: on an infected machine any newly
  written .exe can be re-infected within seconds (see research/EXPIRO_INCIDENT_2026-10-22.md).
#>
param([string]$RepoRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
$url = 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip'
$zipSha = '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'
$assets = Join-Path $RepoRoot 'assets\clamav'
$manifest = Get-Content (Join-Path $assets 'clamav-binaries.sha256.json') -Raw | ConvertFrom-Json
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("clamav-restore-" + [guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
  $zip = Join-Path $tmp 'clamav.zip'
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
  $h = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($h -ne $zipSha) { throw "Downloaded zip SHA-256 $h does not match the release digest $zipSha" }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $z = [IO.Compression.ZipFile]::OpenRead($zip)
  $sha = [Security.Cryptography.SHA256]::Create()
  $ok = $true
  foreach ($name in $manifest.files.PSObject.Properties.Name) {
    $entry = $z.Entries | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $entry) { throw "$name not found in zip" }
    $ms = New-Object IO.MemoryStream; $s = $entry.Open(); $s.CopyTo($ms); $s.Dispose(); $bytes = $ms.ToArray()
    $expected = $manifest.files.$name
    $actual = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLower()
    if ($actual -ne $expected) { throw "$name in zip has $actual, manifest expects $expected" }
    [IO.File]::WriteAllBytes((Join-Path $assets $name), $bytes)
    $disk = (Get-FileHash (Join-Path $assets $name) -Algorithm SHA256).Hash.ToLower()
    $good = $disk -eq $expected; if (-not $good) { $ok = $false }
    '{0,-14} {1}' -f $name, $(if ($good) { 'OK' } else { "MISMATCH on disk ($disk)" })
  }
  $z.Dispose()
  Start-Sleep -Seconds 10
  foreach ($name in $manifest.files.PSObject.Properties.Name) {
    $disk = (Get-FileHash (Join-Path $assets $name) -Algorithm SHA256).Hash.ToLower()
    if ($disk -ne $manifest.files.$name) { $ok = $false; "$name CHANGED within 10 seconds of writing: an active infector is running. Stop and follow research/DISINFECTION_PROCEDURE.md." }
  }
  if ($ok) { 'All ClamAV executables restored and verified.' } else { exit 2 }
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
