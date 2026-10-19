#!/usr/bin/env pwsh
# Check and enable GSM Shield AV protection settings by reading SQLite database

$dbPath = Join-Path $env:APPDATA "GSMShieldAV\gsm-shield.db"

Write-Host "`n=== GSM Shield AV Protection Check ===" -ForegroundColor Cyan
Write-Host "Database: $dbPath`n" -ForegroundColor Gray

if (-not (Test-Path $dbPath)) {
    Write-Host "ERROR: Database not found" -ForegroundColor Red
    Write-Host "GSM Shield AV may not have been started yet.`n" -ForegroundColor Yellow
    exit 1
}

# Read database as text (SQLite stores strings as plain text in many cases)
$content = Get-Content $dbPath -Raw -Encoding UTF8

Write-Host "Searching for protection settings in database..." -ForegroundColor Yellow

# Check for realtime_protection
if ($content -match "realtime_protection") {
    Write-Host "  Found: realtime_protection" -ForegroundColor Green
    
    # Try to find the value (usually stored as '0' or '1' nearby)
    if ($content -match "realtime_protection.{0,50}1") {
        Write-Host "    Status: ENABLED (value = 1)" -ForegroundColor Green
    } else {
        Write-Host "    Status: DISABLED (value = 0 or not set)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  realtime_protection: NOT FOUND" -ForegroundColor Red
}

# Check for auto_quarantine
if ($content -match "auto_quarantine") {
    Write-Host "  Found: auto_quarantine" -ForegroundColor Green
    
    if ($content -match "auto_quarantine.{0,50}1") {
        Write-Host "    Status: ENABLED (value = 1)" -ForegroundColor Green
    } else {
        Write-Host "    Status: DISABLED (value = 0 or not set)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  auto_quarantine: NOT FOUND" -ForegroundColor Red
}

# Check for monitored_paths
if ($content -match "monitored_paths") {
    Write-Host "  Found: monitored_paths" -ForegroundColor Green
} else {
    Write-Host "  monitored_paths: NOT FOUND" -ForegroundColor Red
}

Write-Host "`nRecommendation:" -ForegroundColor Cyan
Write-Host "  1. Open GSM Shield AV interface" -ForegroundColor Gray
Write-Host "  2. Go to Settings page" -ForegroundColor Gray
Write-Host "  3. Toggle 'Real-Time Protection' to ON (blue)" -ForegroundColor Gray
Write-Host "  4. Toggle 'Auto-Quarantine' to ON (blue)" -ForegroundColor Gray
Write-Host "  5. Add monitored paths (e.g., C:\Users, C:\Program Files)" -ForegroundColor Gray
Write-Host ""
