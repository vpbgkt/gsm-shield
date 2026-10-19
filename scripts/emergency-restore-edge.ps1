# Emergency Edge Browser Restoration
# Restores Microsoft Edge so you can download other installers

Write-Host "=====================================================================" -ForegroundColor Red
Write-Host " EMERGENCY: RESTORE MICROSOFT EDGE" -ForegroundColor Red
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "[!] Your Edge browser was quarantined - you need it to download files" -ForegroundColor Yellow
Write-Host "[!] This will restore Edge executables TEMPORARILY" -ForegroundColor Yellow
Write-Host ""
Write-Host "Plan:" -ForegroundColor Cyan
Write-Host "  1. Restore Edge executables from quarantine" -ForegroundColor White
Write-Host "  2. Use Edge to download: Node.js, Git, Brave" -ForegroundColor White
Write-Host "  3. Install clean versions" -ForegroundColor White
Write-Host "  4. Remove restored Edge, reinstall clean Edge" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to proceed or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

$quarantine = "C:\GSMShield\Quarantine"
$edgeDir = "C:\Program Files (x86)\Microsoft\Edge\Application"

# Find Edge files
$edgeFiles = Get-ChildItem $quarantine -Recurse -Filter "msedge*.exe"

Write-Host ""
Write-Host "Found $($edgeFiles.Count) Edge files in quarantine" -ForegroundColor Cyan
Write-Host ""

$restored = 0
foreach ($file in $edgeFiles) {
    # Determine original location based on file name
    $destPath = ""
    
    if ($file.Name -eq "msedge.exe") {
        $destPath = Join-Path $edgeDir "msedge.exe"
    } elseif ($file.Name -match "^msedge_\d+\.exe$") {
        # Versioned Edge executables - skip for now
        continue
    } elseif ($file.Name -match "msedge_proxy") {
        continue  # Skip proxy for now
    } elseif ($file.Name -match "msedge_pwa") {
        continue  # Skip PWA launcher
    } elseif ($file.Name -match "msedgewebview2") {
        continue  # Skip WebView2
    }
    
    if ($destPath -and $destPath -ne "") {
        try {
            # Create directory if needed
            $destDir = Split-Path $destPath
            if (!(Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            
            Copy-Item $file.FullName -Destination $destPath -Force
            Write-Host "[+] Restored: $($file.Name) -> $destPath" -ForegroundColor Green
            $restored++
        } catch {
            Write-Host "[-] Failed to restore: $($file.Name)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "Restored $restored Edge files" -ForegroundColor White
Write-Host ""

if ($restored -gt 0) {
    Write-Host "[SUCCESS] Edge should now work!" -ForegroundColor Green
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  1. Test Edge: Start-Process msedge" -ForegroundColor White
    Write-Host "  2. Download Node.js: https://nodejs.org" -ForegroundColor White
    Write-Host "  3. Download Git: https://git-scm.com/download/win" -ForegroundColor White
    Write-Host "  4. Download Brave: https://brave.com/download" -ForegroundColor White
    Write-Host ""
    Write-Host "[!!!] IMPORTANT: After downloads, reinstall Edge from:" -ForegroundColor Red
    Write-Host "https://www.microsoft.com/edge" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "[!] No files could be restored" -ForegroundColor Red
    Write-Host ""
    Write-Host "Alternative: Use another computer to download installers" -ForegroundColor Yellow
    Write-Host "Then transfer via USB drive to this computer" -ForegroundColor Yellow
}

Write-Host "=====================================================================" -ForegroundColor Cyan
