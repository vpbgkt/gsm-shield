# ClamAV Binaries Setup Guide for GSM Shield AV

## Where to Get ClamAV for Windows

### Official ClamAV Downloads

**Option 1: Direct Download from ClamAV (Recommended)**

1. **Visit the official ClamAV website:**
   - URL: https://www.clamav.net/downloads
   - Or direct Windows builds: https://www.clamav.net/downloads#otherversions

2. **Download ClamAV for Windows:**
   - Look for: "ClamAV for Windows" or "Win64 portable"
   - Latest stable version: Usually named like `clamav-1.X.X-win-x64.zip`
   - File size: ~40-50 MB

3. **Alternative - Cisco official releases:**
   - URL: https://github.com/Cisco-Talos/clamav/releases
   - Download the Windows installer: `clamav-X.X.X-win-x64-portable.zip`

---

## Step-by-Step Installation Instructions

### Step 1: Download ClamAV

```powershell
# Create a temporary download directory
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\Downloads\clamav-temp"
cd "$env:USERPROFILE\Downloads\clamav-temp"

# Download the latest ClamAV portable version (example - check for latest version)
# You'll need to download manually from the website or use this example:
Invoke-WebRequest -Uri "https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.zip" -OutFile "clamav.zip"

# Note: The URL above is an example. Always check https://www.clamav.net/downloads 
# for the latest version number
```

### Step 2: Extract the Archive

```powershell
# Extract the downloaded ZIP file
Expand-Archive -Path "clamav.zip" -DestinationPath "extracted" -Force

# Navigate to the extracted folder
cd extracted
```

### Step 3: Locate the Required Files

After extraction, you'll find these files in the ClamAV folder:

**Required Executables:**
- `clamscan.exe` - The scanner executable
- `freshclam.exe` - The definition updater
- Various DLL files (also required)

**Required Definition Files:**
These need to be downloaded separately using freshclam:
- `main.cvd` - Main virus definitions (~160 MB)
- `daily.cvd` - Daily updates (~70 MB)
- `bytecode.cvd` - Bytecode signatures

---

## Step 4: Download Virus Definitions

ClamAV requires virus definition files to function. These are NOT included in the portable download.

### Method 1: Use FreshClam (Recommended)

1. **Create a configuration file for FreshClam:**

```powershell
# Navigate to the ClamAV directory
cd "$env:USERPROFILE\Downloads\clamav-temp\extracted"

# Create freshclam.conf
@"
# FreshClam Configuration
DatabaseDirectory ./
UpdateLogFile ./freshclam.log
LogVerbose yes
DatabaseMirror database.clamav.net
"@ | Out-File -FilePath "freshclam.conf" -Encoding ASCII
```

2. **Run FreshClam to download definitions:**

```powershell
# Download the virus definitions
.\freshclam.exe --config-file=freshclam.conf

# This will download (may take 5-10 minutes):
# - main.cvd (~160 MB)
# - daily.cvd (~70 MB)  
# - bytecode.cvd (~290 KB)
```

### Method 2: Manual Download (If FreshClam Fails)

If FreshClam doesn't work, you can manually download the definition files:

```powershell
# Download main.cvd
Invoke-WebRequest -Uri "http://database.clamav.net/main.cvd" -OutFile "main.cvd"

# Download daily.cvd
Invoke-WebRequest -Uri "http://database.clamav.net/daily.cvd" -OutFile "daily.cvd"

# Download bytecode.cvd
Invoke-WebRequest -Uri "http://database.clamav.net/bytecode.cvd" -OutFile "bytecode.cvd"
```

---

## Step 5: Copy Files to Your Project

Now copy the required files to your GSM Shield AV project:

```powershell
# Define your project path
$projectPath = "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield"
$clamavAssets = "$projectPath\assets\clamav"

# Create the assets/clamav directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $clamavAssets

# Copy the executables
Copy-Item -Path "clamscan.exe" -Destination $clamavAssets -Force
Copy-Item -Path "freshclam.exe" -Destination $clamavAssets -Force

# Copy all required DLL files
Copy-Item -Path "*.dll" -Destination $clamavAssets -Force

# Copy the virus definition files
Copy-Item -Path "main.cvd" -Destination $clamavAssets -Force
Copy-Item -Path "daily.cvd" -Destination $clamavAssets -Force
Copy-Item -Path "bytecode.cvd" -Destination $clamavAssets -Force
```

---

## Step 6: Verify Installation

```powershell
# Navigate to your project's clamav assets folder
cd "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield\assets\clamav"

# List all files
Get-ChildItem | Format-Table Name, Length

# You should see:
# - clamscan.exe (several MB)
# - freshclam.exe (several MB)
# - main.cvd (~160 MB)
# - daily.cvd (~70 MB)
# - bytecode.cvd (~290 KB)
# - Various .dll files
```

---

## Complete PowerShell Script (All-in-One)

Here's a complete script that does everything:

```powershell
# ============================================================
# ClamAV Setup Script for GSM Shield AV
# ============================================================

$projectPath = "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield"
$tempDir = "$env:USERPROFILE\Downloads\clamav-temp"
$clamavAssets = "$projectPath\assets\clamav"

# Step 1: Create temp directory
Write-Host "Creating temporary directory..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
Set-Location $tempDir

# Step 2: Download ClamAV (you'll need to update the version number)
Write-Host "`nDownloading ClamAV for Windows..." -ForegroundColor Cyan
Write-Host "Please check https://www.clamav.net/downloads for the latest version" -ForegroundColor Yellow
$clamavUrl = "https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.zip"

try {
    Invoke-WebRequest -Uri $clamavUrl -OutFile "clamav.zip" -UseBasicParsing
    Write-Host "Download complete!" -ForegroundColor Green
} catch {
    Write-Host "Failed to download ClamAV automatically." -ForegroundColor Red
    Write-Host "Please download manually from https://www.clamav.net/downloads" -ForegroundColor Yellow
    Write-Host "Save it as: $tempDir\clamav.zip" -ForegroundColor Yellow
    Read-Host "Press Enter after downloading..."
}

# Step 3: Extract ClamAV
Write-Host "`nExtracting ClamAV..." -ForegroundColor Cyan
Expand-Archive -Path "clamav.zip" -DestinationPath "extracted" -Force
$clamavDir = Get-ChildItem -Path "extracted" -Directory | Select-Object -First 1
Set-Location $clamavDir.FullName

# Step 4: Create FreshClam configuration
Write-Host "`nCreating FreshClam configuration..." -ForegroundColor Cyan
@"
DatabaseDirectory ./
UpdateLogFile ./freshclam.log
LogVerbose yes
DatabaseMirror database.clamav.net
"@ | Out-File -FilePath "freshclam.conf" -Encoding ASCII

# Step 5: Download virus definitions
Write-Host "`nDownloading virus definitions (this may take 5-10 minutes)..." -ForegroundColor Cyan
Write-Host "File sizes: main.cvd (~160 MB), daily.cvd (~70 MB)" -ForegroundColor Yellow

try {
    .\freshclam.exe --config-file=freshclam.conf
    Write-Host "Definitions downloaded successfully!" -ForegroundColor Green
} catch {
    Write-Host "FreshClam failed. Trying manual download..." -ForegroundColor Yellow
    
    # Manual fallback
    Invoke-WebRequest -Uri "http://database.clamav.net/main.cvd" -OutFile "main.cvd"
    Invoke-WebRequest -Uri "http://database.clamav.net/daily.cvd" -OutFile "daily.cvd"
    Invoke-WebRequest -Uri "http://database.clamav.net/bytecode.cvd" -OutFile "bytecode.cvd"
}

# Step 6: Create assets/clamav directory
Write-Host "`nCreating assets/clamav directory..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $clamavAssets | Out-Null

# Step 7: Copy files to project
Write-Host "`nCopying files to project..." -ForegroundColor Cyan
Copy-Item -Path "clamscan.exe" -Destination $clamavAssets -Force
Copy-Item -Path "freshclam.exe" -Destination $clamavAssets -Force
Copy-Item -Path "*.dll" -Destination $clamavAssets -Force

if (Test-Path "main.cvd") {
    Copy-Item -Path "main.cvd" -Destination $clamavAssets -Force
    Write-Host "  ✓ main.cvd copied" -ForegroundColor Green
}
if (Test-Path "daily.cvd") {
    Copy-Item -Path "daily.cvd" -Destination $clamavAssets -Force
    Write-Host "  ✓ daily.cvd copied" -ForegroundColor Green
}
if (Test-Path "bytecode.cvd") {
    Copy-Item -Path "bytecode.cvd" -Destination $clamavAssets -Force
    Write-Host "  ✓ bytecode.cvd copied" -ForegroundColor Green
}

# Step 8: Verify
Write-Host "`nVerifying installation..." -ForegroundColor Cyan
Set-Location $clamavAssets
$files = Get-ChildItem | Select-Object Name, @{Name='Size (MB)';Expression={[math]::Round($_.Length / 1MB, 2)}}
$files | Format-Table -AutoSize

# Summary
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "ClamAV Setup Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "`nFiles copied to: $clamavAssets" -ForegroundColor Cyan
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Rebuild your installer: node scripts/build.js" -ForegroundColor White
Write-Host "2. The new installer will include ClamAV binaries" -ForegroundColor White
Write-Host "`nYou can delete the temp folder: $tempDir" -ForegroundColor Gray

# Optional: Clean up
$cleanup = Read-Host "`nDelete temporary files? (y/n)"
if ($cleanup -eq 'y') {
    Set-Location $env:USERPROFILE
    Remove-Item -Path $tempDir -Recurse -Force
    Write-Host "Temporary files deleted." -ForegroundColor Green
}
```

---

## Quick Manual Method (If Script Fails)

### 1. Download Manually

Visit: **https://www.clamav.net/downloads**

Click: **"Download ClamAV for Windows"** or look for the portable version

### 2. Extract to Desktop

Right-click the downloaded ZIP → Extract All → Choose Desktop

### 3. Run FreshClam

Open Command Prompt in the extracted folder:
```cmd
freshclam.exe
```
This downloads the definitions.

### 4. Copy Files

Copy these files from the ClamAV folder to your project:
```
Source: C:\Users\[YourName]\Desktop\clamav-[version]\
  → clamscan.exe
  → freshclam.exe
  → *.dll (all DLL files)
  → main.cvd
  → daily.cvd
  → bytecode.cvd

Destination: C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield\assets\clamav\
```

---

## File Size Reference

| File | Approximate Size | Required |
|------|------------------|----------|
| `clamscan.exe` | ~10 MB | ✅ Yes |
| `freshclam.exe` | ~8 MB | ✅ Yes |
| `main.cvd` | ~160 MB | ✅ Yes |
| `daily.cvd` | ~70 MB | ✅ Yes |
| `bytecode.cvd` | ~290 KB | ✅ Yes |
| Various DLLs | ~20-30 MB total | ✅ Yes |
| **Total** | **~270 MB** | |

---

## Testing ClamAV Installation

After copying files, test that ClamAV works:

```powershell
cd "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield\assets\clamav"

# Test scanner
.\clamscan.exe --version

# Should output something like:
# ClamAV 1.4.1/27534/Sat Jun 27 2026

# Test with EICAR test file
"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" | Out-File -FilePath "eicar.txt" -NoNewline

# Scan the EICAR test file
.\clamscan.exe --database=. eicar.txt

# Should detect: "eicar.txt: Eicar-Signature FOUND"
```

---

## Troubleshooting

### Issue: FreshClam fails to download

**Solution 1:** Check firewall/antivirus isn't blocking
**Solution 2:** Use manual download method (see above)
**Solution 3:** Download from alternative mirrors at http://www.clamav.net/downloads

### Issue: "clamscan.exe is not recognized"

**Solution:** Make sure you're in the correct directory or use full path

### Issue: DLL errors when running clamscan

**Solution:** Copy ALL .dll files from the ClamAV package to assets/clamav/

### Issue: Database is too old

**Solution:** Re-run freshclam.exe to get latest definitions

---

## Alternative Sources

If the official ClamAV site is down, try:

1. **Chocolatey (Windows package manager):**
   ```powershell
   choco install clamav
   # Then copy files from C:\ProgramData\chocolatey\lib\clamav\tools\
   ```

2. **GitHub Releases:**
   - https://github.com/Cisco-Talos/clamav/releases
   - Download the Windows portable build

---

## After Setup

Once you have copied all files to `assets/clamav/`, rebuild your installer:

```powershell
cd "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield"
node scripts/build.js
```

The new installer will include all ClamAV binaries and definitions! 🎉

---

## Keeping Definitions Updated

Virus definitions should be updated regularly. Your app includes an auto-update feature via FreshClam, but you can also:

1. **Manual update before building installer:**
   ```powershell
   cd assets/clamav
   .\freshclam.exe
   ```

2. **Schedule updates:**
   - The app will auto-update definitions when users click "Check for Updates" in Settings
   - The app can schedule automatic 24-hour updates (if licensed)

---

## License Information

- **ClamAV is open source** (GPL v2)
- Free to use and distribute
- No commercial restrictions
- Attribution: ClamAV is developed by Cisco Talos

---

**Need Help?**
- ClamAV Documentation: https://docs.clamav.net/
- ClamAV FAQ: https://www.clamav.net/documents/faq
