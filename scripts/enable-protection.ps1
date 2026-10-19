# Enable Expiro Protection via SQL

$dbPath = "$env:APPDATA\GSMShieldAV\gsm-shield.db"

Write-Host "GSM Shield AV - Protection Enabler" -ForegroundColor Cyan
Write-Host ""

if (!(Test-Path $dbPath)) {
    Write-Host "[!] Database not found at: $dbPath" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Database found: $dbPath" -ForegroundColor Green
Write-Host ""

# Try using sqlite3.exe if available
$sqlite3Path = "C:\Program Files\Git\usr\bin\sqlite3.exe"

if (!(Test-Path $sqlite3Path)) {
    Write-Host "[i] sqlite3.exe not found at Git location" -ForegroundColor Yellow
    Write-Host "[i] Proceeding without database modification" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "RECOMMENDATION: Proceed with full removal anyway" -ForegroundColor Cyan
    Write-Host "The Expiro monitor will still work during removal" -ForegroundColor Cyan
    exit 0
}

Write-Host "[+] Using sqlite3.exe" -ForegroundColor Green
Write-Host ""

# Enable Expiro protection
Write-Host "Enabling Expiro real-time protection..." -ForegroundColor Yellow

$sql1 = "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('expiro_protection_enabled', 'true', datetime('now'));"
& $sqlite3Path $dbPath $sql1

# Add monitored paths
Write-Host "Configuring monitored paths..." -ForegroundColor Yellow

$paths = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Users\$env:USERNAME\AppData\Local",
    "C:\Users\$env:USERNAME\Downloads"
)

foreach ($path in $paths) {
    $escapedPath = $path.Replace("\", "\\")
    $sql2 = "INSERT OR IGNORE INTO monitored_paths (path, enabled, created_at, updated_at) VALUES ('$escapedPath', 1, datetime('now'), datetime('now'));"
    & $sqlite3Path $dbPath $sql2 2>$null
    Write-Host "   [+] $path" -ForegroundColor Green
}

Write-Host ""
Write-Host "[SUCCESS] Expiro protection enabled!" -ForegroundColor Green
Write-Host ""
Write-Host "Next: Proceed with full Expiro removal" -ForegroundColor Cyan
Write-Host ""
