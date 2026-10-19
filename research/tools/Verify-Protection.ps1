#!/usr/bin/env pwsh
# GSM Shield AV Protection Verification Script

Write-Host "`n========================================"  -ForegroundColor Cyan
Write-Host "GSM Shield AV Protection Verification" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check 1: Is GSM Shield AV running?
Write-Host "[1/4] Checking GSM Shield AV process..." -ForegroundColor Yellow
$gsmProcesses = Get-Process | Where-Object {$_.ProcessName -like "*GSM*Shield*" -or $_.ProcessName -like "*GSM Shield AV*"}

if ($gsmProcesses) {
    $totalMemory = ($gsmProcesses | Measure-Object -Property WorkingSet64 -Sum).Sum / 1MB
    Write-Host "  SUCCESS: GSM Shield AV is RUNNING" -ForegroundColor Green
    Write-Host "    Processes: $($gsmProcesses.Count)" -ForegroundColor Gray
    Write-Host "    Memory: $([math]::Round($totalMemory, 2)) MB" -ForegroundColor Gray
    Write-Host "    PIDs: $($gsmProcesses.Id -join ', ')" -ForegroundColor Gray
} else {
    Write-Host "  FAIL: GSM Shield AV is NOT RUNNING" -ForegroundColor Red
    Write-Host "    Please start from: dist\win-unpacked\GSM Shield AV.exe" -ForegroundColor Yellow
    exit 1
}

# Check 2: Is Windows Defender disabled?
Write-Host "`n[2/4] Checking Windows Defender status..." -ForegroundColor Yellow
try {
    $defenderPrefs = Get-MpPreference -ErrorAction Stop
    if ($defenderPrefs.DisableRealtimeMonitoring) {
        Write-Host "  SUCCESS: Windows Defender is DISABLED (as configured)" -ForegroundColor Green
    } else {
        Write-Host "  INFO: Windows Defender is ENABLED" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  INFO: Cannot check Defender status" -ForegroundColor Yellow
}

# Check 3: Is detection threshold updated?
Write-Host "`n[3/4] Checking detection threshold..." -ForegroundColor Yellow
$detectorPath = Join-Path $PSScriptRoot "..\..\engine\expiro-detector.js"
$detectorContent = Get-Content $detectorPath -Raw

if ($detectorContent -match "detectionThreshold:\s*60") {
    Write-Host "  SUCCESS: Detection threshold is 60% (optimized)" -ForegroundColor Green
} elseif ($detectorContent -match "detectionThreshold:\s*50") {
    Write-Host "  WARNING: Detection threshold is 50% (may have false positives)" -ForegroundColor Yellow
} else {
    Write-Host "  INFO: Detection threshold unknown" -ForegroundColor Yellow
}

# Check 4: Database status
Write-Host "`n[4/4] Checking database..." -ForegroundColor Yellow
$dbPath = Join-Path $env:APPDATA "GSMShieldAV\gsm-shield.db"

if (Test-Path $dbPath) {
    $dbSize = (Get-Item $dbPath).Length / 1KB
    Write-Host "  SUCCESS: Database exists" -ForegroundColor Green
    Write-Host "    Path: $dbPath" -ForegroundColor Gray
    Write-Host "    Size: $([math]::Round($dbSize, 2)) KB" -ForegroundColor Gray
} else {
    Write-Host "  INFO: Database not found (may be first run)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Protection Status Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$quarantineCount = (Get-ChildItem "C:\GSMShield\Quarantine\" -File -ErrorAction SilentlyContinue | Measure-Object).Count
$quarantineSize = (Get-ChildItem "C:\GSMShield\Quarantine\" -File -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB

Write-Host "Quarantined Files: $quarantineCount files ($([math]::Round($quarantineSize, 2)) GB)" -ForegroundColor Cyan
Write-Host "Protection Status: " -NoNewline
if ($gsmProcesses) {
    Write-Host "ACTIVE" -ForegroundColor Green
} else {
    Write-Host "INACTIVE" -ForegroundColor Red
}

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Open GSM Shield AV interface (should be open)" -ForegroundColor Gray
Write-Host "  2. Enable Expiro Protection in Settings" -ForegroundColor Gray
Write-Host "  3. Run: .\Full-System-Expiro-Scan.ps1 -ScanOnly" -ForegroundColor Gray
Write-Host "  4. Download clean Git and Node.js installers via Firefox" -ForegroundColor Gray
Write-Host ""
