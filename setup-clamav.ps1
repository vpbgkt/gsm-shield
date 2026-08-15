# ============================================================
# ClamAV Setup Script for GSM Shield AV
# Automatically downloads and installs ClamAV binaries
# ============================================================

$ErrorActionPreference = "Stop"

$projectPath = "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield"
$tempDir = "$env:USERPROFILE\Downloads\clamav-temp"
$clamavAssets = "$projectPath\assets\clamav"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ClamAV Setup for GSM Shield AV" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# Step 1: Create temp directory
Write-Host "[1/7] Creating temporary directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
Set-Location $tempDir
Write-Host "  ✓ Created: $tempDir`n" -ForegroundColor Green

# Step 2: Download ClamAV
Write-Host "[2/7] Downloading ClamAV for Windows..." -ForegroundColor Yellow
Write-Host "  Note: This downloads ~50 MB. Please be patient.`n" -ForegroundColor Gray

# Try multiple ClamAV download sources
$clamavUrls = @(
    "https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.zip",
    "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.4.1/clamav-1.4.1.win.x64.zip"
)

$downloaded = $false
foreach ($url in $clamavUrls) {
    try {
        Write-Host "  Trying: $url" -ForegroundColor Gray
        Invoke-WebRequest -Uri $url -OutFile "clamav.zip" -UseBasicParsing -TimeoutSec 300
        Write-Host "  ✓ Download complete!`n" -ForegroundColor Green
        $downloaded = $true
        break
    } catch {
        Write-Host "  ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $downloaded) {
    Write-Host "`n  ⚠ Automatic download failed.`n" -ForegroundColor Yellow
    Write-Host "  Please download ClamAV manually:" -ForegroundColor White
    Write-Host "  1. Visit: https://www.clamav.net/downloads" -ForegroundColor Cyan
    Write-Host "  2. Download: ClamAV for Windows (portable)" -ForegroundColor Cyan
    Write-Host "  3. Save as: $tempDir\clamav.zip`n" -ForegroundColor Cyan
    Read-Host "  Press Enter after downloading"
    
    if (-not (Test-Path "clamav.zip")) {
        Write-Host "`n  ✗ clamav.zip not found. Exiting." -ForegroundColor Red
        exit 1
    }
}

# Step 3: Extract ClamAV
Write-Host "[3/7] Extracting ClamAV..." -ForegroundColor Yellow
Expand-Archive -Path "clamav.zip" -DestinationPath "extracted" -Force

# Find the ClamAV directory (it might be nested)
$clamavDir = Get-ChildItem -Path "extracted" -Recurse -Filter "clamscan.exe" | Select-Object -First 1
if ($clamavDir) {
    Set-Location $clamavDir.Directory.FullName
    Write-Host "  ✓ Extracted to: $($clamavDir.Directory.FullName)`n" -ForegroundColor Green
} else {
    Write-Host "  ✗ Could not find clamscan.exe in extracted files`n" -ForegroundColor Red
    exit 1
}

# Step 4: Create FreshClam configuration
Write-Host "[4/7] Creating FreshClam configuration..." -ForegroundColor Yellow
$freshclamConfig = @"
DatabaseDirectory ./
UpdateLogFile ./freshclam.log
LogVerbose yes
DatabaseMirror database.clamav.net
"@
$freshclamConfig | Out-File -FilePath "freshclam.conf" -Encoding ASCII
Write-Host "  ✓ Configuration created`n" -ForegroundColor Green

# Step 5: Download virus definitions
Write-Host "[5/7] Downloading virus definitions..." -ForegroundColor Yellow
Write-Host "  This may take 5-10 minutes (~230 MB total)" -ForegroundColor Gray
Write-Host "  - main.cvd (~160 MB)" -ForegroundColor Gray
Write-Host "  - daily.cvd (~70 MB)" -ForegroundColor Gray
Write-Host "  - bytecode.cvd (~290 KB)`n" -ForegroundColor Gray

$definitionsDownloaded = $false

# Try using FreshClam first
try {
    $freshclamProcess = Start-Process -FilePath ".\freshclam.exe" -ArgumentList "--config-file=freshclam.conf" -Wait -NoNewWindow -PassThru
    if ($freshclamProcess.ExitCode -eq 0) {
        Write-Host "  ✓ Definitions downloaded via FreshClam`n" -ForegroundColor Green
        $definitionsDownloaded = $true
    }
} catch {
    Write-Host "  ⚠ FreshClam failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# If FreshClam failed, try manual download
if (-not $definitionsDownloaded) {
    Write-Host "  Trying manual download...`n" -ForegroundColor Yellow
    
    try {
        Write-Host "  Downloading main.cvd..." -ForegroundColor Gray
        Invoke-WebRequest -Uri "http://database.clamav.net/main.cvd" -OutFile "main.cvd" -TimeoutSec 600
        Write-Host "  ✓ main.cvd downloaded`n" -ForegroundColor Green
        
        Write-Host "  Downloading daily.cvd..." -ForegroundColor Gray
        Invoke-WebRequest -Uri "http://database.clamav.net/daily.cvd" -OutFile "daily.cvd" -TimeoutSec 600
        Write-Host "  ✓ daily.cvd downloaded`n" -ForegroundColor Green
        
        Write-Host "  Downloading bytecode.cvd..." -ForegroundColor Gray
        Invoke-WebRequest -Uri "http://database.clamav.net/bytecode.cvd" -OutFile "bytecode.cvd" -TimeoutSec 300
        Write-Host "  ✓ bytecode.cvd downloaded`n" -ForegroundColor Green
        
        $definitionsDownloaded = $true
    } catch {
        Write-Host "  ✗ Manual download failed: $($_.Exception.Message)`n" -ForegroundColor Red
    }
}

if (-not $definitionsDownloaded) {
    Write-Host "  ⚠ Could not download virus definitions." -ForegroundColor Yellow
    Write-Host "  The installer will be created without definitions." -ForegroundColor Yellow
    Write-Host "  Users will need to run 'Check for Updates' after installation.`n" -ForegroundColor Yellow
    Read-Host "  Press Enter to continue anyway"
}

# Step 6: Create assets/clamav directory
Write-Host "[6/7] Preparing project directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $clamavAssets | Out-Null
Write-Host "  ✓ Created: $clamavAssets`n" -ForegroundColor Green

# Step 7: Copy files to project
Write-Host "[7/7] Copying files to project..." -ForegroundColor Yellow

# Copy executables
if (Test-Path "clamscan.exe") {
    Copy-Item -Path "clamscan.exe" -Destination $clamavAssets -Force
    Write-Host "  ✓ clamscan.exe" -ForegroundColor Green
}
if (Test-Path "freshclam.exe") {
    Copy-Item -Path "freshclam.exe" -Destination $clamavAssets -Force
    Write-Host "  ✓ freshclam.exe" -ForegroundColor Green
}

# Copy DLLs
$dllCount = 0
Get-ChildItem -Path "*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $clamavAssets -Force
    $dllCount++
}
Write-Host "  ✓ $dllCount DLL files" -ForegroundColor Green

# Copy virus definitions
if (Test-Path "main.cvd") {
    Copy-Item -Path "main.cvd" -Destination $clamavAssets -Force
    $mainSize = [math]::Round((Get-Item "main.cvd").Length / 1MB, 1)
    Write-Host "  ✓ main.cvd ($mainSize MB)" -ForegroundColor Green
}
if (Test-Path "daily.cvd") {
    Copy-Item -Path "daily.cvd" -Destination $clamavAssets -Force
    $dailySize = [math]::Round((Get-Item "daily.cvd").Length / 1MB, 1)
    Write-Host "  ✓ daily.cvd ($dailySize MB)" -ForegroundColor Green
}
if (Test-Path "bytecode.cvd") {
    Copy-Item -Path "bytecode.cvd" -Destination $clamavAssets -Force
    Write-Host "  ✓ bytecode.cvd" -ForegroundColor Green
}

Write-Host ""

# Verification
Write-Host "Verifying installation..." -ForegroundColor Cyan
Set-Location $clamavAssets
$files = Get-ChildItem | Select-Object Name, @{Name='Size';Expression={
    if ($_.Length -gt 1MB) {
        "{0:N1} MB" -f ($_.Length / 1MB)
    } elseif ($_.Length -gt 1KB) {
        "{0:N1} KB" -f ($_.Length / 1KB)
    } else {
        "$($_.Length) bytes"
    }
}}
Write-Host ""
$files | Format-Table -AutoSize

# Summary
$totalSize = [math]::Round((Get-ChildItem | Measure-Object -Property Length -Sum).Sum / 1MB, 1)

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  ✓ ClamAV Setup Complete!" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green

Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Files copied to: $clamavAssets" -ForegroundColor White
Write-Host "  Total size: $totalSize MB`n" -ForegroundColor White

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Test ClamAV:" -ForegroundColor White
Write-Host "     cd `"$clamavAssets`"" -ForegroundColor Gray
Write-Host "     .\clamscan.exe --version`n" -ForegroundColor Gray

Write-Host "  2. Rebuild your installer:" -ForegroundColor White
Write-Host "     cd `"$projectPath`"" -ForegroundColor Gray
Write-Host "     node scripts/build.js`n" -ForegroundColor Gray

Write-Host "  3. The new installer will include ClamAV binaries!`n" -ForegroundColor White

# Optional: Test ClamAV
$test = Read-Host "Would you like to test ClamAV now? (y/n)"
if ($test -eq 'y') {
    Write-Host "`nTesting ClamAV..." -ForegroundColor Cyan
    Set-Location $clamavAssets
    
    # Test version
    Write-Host "`nClamAV Version:" -ForegroundColor Yellow
    .\clamscan.exe --version
    
    # Create EICAR test file
    Write-Host "`nCreating EICAR test file..." -ForegroundColor Yellow
    "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" | Out-File -FilePath "eicar.txt" -NoNewline -Encoding ASCII
    
    # Scan EICAR
    Write-Host "Scanning EICAR test file...`n" -ForegroundColor Yellow
    .\clamscan.exe --database=. eicar.txt
    
    # Clean up
    Remove-Item "eicar.txt" -Force -ErrorAction SilentlyContinue
    
    Write-Host "`nIf you saw 'FOUND' above, ClamAV is working correctly!`n" -ForegroundColor Green
}

# Optional: Clean up
$cleanup = Read-Host "Delete temporary files? (y/n)"
if ($cleanup -eq 'y') {
    try {
        Set-Location $env:USERPROFILE
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
        Write-Host "✓ Temporary files deleted.`n" -ForegroundColor Green
    } catch {
        Write-Host "⚠ Could not delete temp folder: $tempDir" -ForegroundColor Yellow
        Write-Host "You can delete it manually later.`n" -ForegroundColor Gray
    }
} else {
    Write-Host "`nTemp files kept at: $tempDir`n" -ForegroundColor Gray
}

Write-Host "Setup complete! You're ready to build the installer." -ForegroundColor Green
