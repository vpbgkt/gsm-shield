# Test Expiro Removal - Quarantine 10 Files Only
# GSM Shield AV - October 3, 2026
# Safe testing before full removal

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " GSM SHIELD AV - TEST REMOVAL (10 FILES ONLY)" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[i] This will quarantine only 10 infected files for testing" -ForegroundColor Yellow
Write-Host "[i] System impact will be minimal and reversible" -ForegroundColor Yellow
Write-Host ""

# Create quarantine directory
$quarantineDir = "C:\GSMShield\Quarantine\Test"
if (!(Test-Path $quarantineDir)) {
    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
    Write-Host "Created test quarantine directory: $quarantineDir" -ForegroundColor Green
    Write-Host ""
}

# Read the list of infected files from previous scan
$logFile = Get-ChildItem "research\logs\full_scan_results_*.txt" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (!$logFile) {
    Write-Host "[!] ERROR: No scan results found. Run full scan first." -ForegroundColor Red
    exit 1
}

Write-Host "Loading infected files from: $($logFile.Name)" -ForegroundColor Cyan
$infectedFiles = Import-Csv $logFile.FullName

if ($infectedFiles.Count -eq 0) {
    Write-Host "[!] ERROR: No infected files found in log." -ForegroundColor Red
    exit 1
}

Write-Host "Total infected files available: $($infectedFiles.Count)" -ForegroundColor White
Write-Host ""

# Select 10 files for testing - prefer lower confidence scores to minimize impact
$testFiles = $infectedFiles | 
    Sort-Object {[int]$_.Confidence} | 
    Select-Object -First 10

Write-Host "Selected 10 files for test quarantine:" -ForegroundColor Yellow
Write-Host ""

$counter = 1
$successCount = 0
$failCount = 0
$results = @()

foreach ($file in $testFiles) {
    $filePath = $file.Path
    $fileName = Split-Path $filePath -Leaf
    
    Write-Host "[$counter/10] Processing: $fileName" -ForegroundColor Cyan
    Write-Host "  Path: $filePath" -ForegroundColor Gray
    Write-Host "  Confidence: $($file.Confidence)%" -ForegroundColor Gray
    
    # Check if file still exists
    if (!(Test-Path $filePath)) {
        Write-Host "  [!] File not found - may have been removed already" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            File = $fileName
            Status = "Not Found"
            QuarantinePath = "N/A"
            Error = "File does not exist"
        }
        $counter++
        continue
    }
    
    # Quarantine the file
    try {
        $quarantinePath = Join-Path $quarantineDir $fileName
        $fileCounter = 1
        while (Test-Path $quarantinePath) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
            $extension = [System.IO.Path]::GetExtension($fileName)
            $quarantinePath = Join-Path $quarantineDir "${baseName}_${fileCounter}${extension}"
            $fileCounter++
        }
        
        # Move file to quarantine
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        
        Write-Host "  [+] SUCCESS: Quarantined" -ForegroundColor Green
        Write-Host "  [+] Location: $quarantinePath" -ForegroundColor Green
        
        $successCount++
        $results += [PSCustomObject]@{
            File = $fileName
            Status = "Quarantined"
            QuarantinePath = $quarantinePath
            OriginalPath = $filePath
            Confidence = $file.Confidence
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Log the action
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | TEST | $filePath | Quarantined to: $quarantinePath | Confidence: $($file.Confidence)%"
        Add-Content -Path (Join-Path (Split-Path $quarantineDir) "test_quarantine_log.txt") -Value $logEntry
        
    } catch {
        Write-Host "  [-] FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
        $results += [PSCustomObject]@{
            File = $fileName
            Status = "Failed"
            QuarantinePath = "N/A"
            Error = $_.Exception.Message
        }
    }
    
    Write-Host ""
    $counter++
}

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " TEST QUARANTINE COMPLETE" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Results:" -ForegroundColor White
Write-Host "  Successfully Quarantined: $successCount" -ForegroundColor $(if($successCount -gt 0){"Green"}else{"Gray"})
Write-Host "  Failed: $failCount" -ForegroundColor $(if($failCount -gt 0){"Red"}else{"Gray"})
Write-Host ""

if ($successCount -gt 0) {
    Write-Host "Quarantined Files:" -ForegroundColor Yellow
    $results | Where-Object {$_.Status -eq "Quarantined"} | Format-Table -AutoSize File, Confidence, @{Name="Quarantine Location";Expression={$_.QuarantinePath}}
    
    Write-Host ""
    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host " VERIFICATION STEPS" -ForegroundColor Yellow
    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. CHECK SYSTEM STABILITY:" -ForegroundColor White
    Write-Host "   - Can you still use your computer normally?" -ForegroundColor Gray
    Write-Host "   - Try opening a few programs" -ForegroundColor Gray
    Write-Host "   - Check if Windows is still responsive" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. CHECK QUARANTINE:" -ForegroundColor White
    Write-Host "   - Files are in: $quarantineDir" -ForegroundColor Gray
    Write-Host "   - You can browse the folder to see them" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. TEST REVERSIBILITY (OPTIONAL):" -ForegroundColor White
    Write-Host "   - If needed, you can restore files from quarantine" -ForegroundColor Gray
    Write-Host "   - Simply copy them back to original location" -ForegroundColor Gray
    Write-Host ""
    Write-Host "4. NEXT STEPS:" -ForegroundColor White
    Write-Host "   If everything looks good:" -ForegroundColor Green
    Write-Host "   - Run full removal: .\research\tools\Full-System-Expiro-Scan.ps1 -RemoveInfections" -ForegroundColor Green
    Write-Host ""
    Write-Host "   If there are issues:" -ForegroundColor Yellow
    Write-Host "   - We can restore these 10 files" -ForegroundColor Yellow
    Write-Host "   - Investigate what went wrong" -ForegroundColor Yellow
    Write-Host "   - Adjust strategy if needed" -ForegroundColor Yellow
    Write-Host ""
    
    # Export detailed results
    $resultsPath = "research\logs\test_removal_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $resultsPath -NoTypeInformation
    Write-Host "[i] Detailed results saved to: $resultsPath" -ForegroundColor Cyan
}

Write-Host "=====================================================================" -ForegroundColor Cyan
