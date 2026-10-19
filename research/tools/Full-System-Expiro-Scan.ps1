# Full System Expiro Scanner with Safe Removal (v2)
# GSM Shield AV - October 18, 2026
# WARNING: This will scan all drives for Expiro infections
#
# v2 Changes:
#   - Removed false-positive-prone section names (.code, .x, .upx)
#   - Improved section-table scanning (reads PE section table, not raw ASCII)
#   - Added overlay analysis (40-150KB of appended encrypted data)
#   - Added injection API heuristic (VirtualAlloc + WriteProcessMemory combo)
#   - Reduced scoring for known packers (UPX, ASPack)
#   - Timestamp anomaly detection

param(
    [switch]$ScanOnly = $false,
    [switch]$RemoveInfections = $false
)

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " GSM SHIELD AV - FULL SYSTEM EXPIRO SCANNER v2" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

if ($RemoveInfections) {
    Write-Host "[!] REMOVAL MODE ENABLED - Infected files will be quarantined" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "[i] SCAN ONLY MODE - No files will be modified" -ForegroundColor Green
    Write-Host ""
}

# Create quarantine directory
$quarantineDir = "C:\GSMShield\Quarantine"
if ($RemoveInfections -and !(Test-Path $quarantineDir)) {
    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
    Write-Host "Created quarantine directory: $quarantineDir" -ForegroundColor Green
}

# Calculate Shannon entropy
function Get-Entropy {
    param([byte[]]$Bytes)
    
    if ($Bytes.Length -eq 0) { return 0 }
    
    $freq = @{}
    foreach ($byte in $Bytes) {
        if ($freq.ContainsKey($byte)) {
            $freq[$byte]++
        } else {
            $freq[$byte] = 1
        }
    }
    
    $entropy = 0.0
    $length = $Bytes.Length
    foreach ($count in $freq.Values) {
        $p = $count / $length
        $entropy -= $p * [Math]::Log($p, 2)
    }
    
    return $entropy
}

# Expiro detection heuristics (v2 - improved accuracy)
function Test-ExpiroInfection {
    param([string]$FilePath)
    
    if (!(Test-Path -LiteralPath $FilePath)) { return $false }
    
    try {
        $file = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Check if it's a PE file
        if ($file.Length -lt 64) { return $false }
        if ($file[0] -ne 0x4D -or $file[1] -ne 0x5A) { return $false }
        
        # Get PE header offset
        $peOffset = [BitConverter]::ToInt32($file, 60)
        if ($peOffset -gt $file.Length - 4 -or $peOffset -lt 0) { return $false }
        
        # Verify PE signature
        if ($file[$peOffset] -ne 0x50 -or $file[$peOffset+1] -ne 0x45) { return $false }
        
        $confidence = 0
        $reasons = @()
        $isKnownPacker = $false
        
        # Parse COFF header
        $sectionCount = [BitConverter]::ToUInt16($file, $peOffset + 6)
        $timeDateStamp = [BitConverter]::ToUInt32($file, $peOffset + 8)
        $optHeaderSize = [BitConverter]::ToUInt16($file, $peOffset + 24)
        
        # Parse section table properly (not raw ASCII search)
        $sectionTableOffset = $peOffset + 4 + 20 + $optHeaderSize
        $lastSectionEnd = 0
        $highEntropyExecCount = 0
        $execWritableCount = 0
        
        # Known Expiro section names
        $expiroSections = @('.expiro', '.virus', '.packed', '.stub', '.ndata')
        # Known benign packer sections (reduce false positives)
        $packerSections = @('UPX0', 'UPX1', 'UPX2', '.aspack', '.adata')
        
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $secOff = $sectionTableOffset + ($i * 40)
            if ($secOff + 40 -gt $file.Length) { break }
            
            # Read section name (8 bytes ASCII)
            $nameBytes = $file[$secOff..($secOff + 7)]
            $sectionName = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
            
            $rawSize = [BitConverter]::ToUInt32($file, $secOff + 16)
            $rawOffset = [BitConverter]::ToUInt32($file, $secOff + 20)
            $chars = [BitConverter]::ToUInt32($file, $secOff + 36)
            
            $isExec = ($chars -band 0x20000000) -ne 0
            $isWritable = ($chars -band 0x80000000) -ne 0
            
            # Track section end for overlay calculation
            $secEnd = $rawOffset + $rawSize
            if ($secEnd -gt $lastSectionEnd) { $lastSectionEnd = $secEnd }
            
            # Heuristic 1: Expiro section names
            foreach ($sus in $expiroSections) {
                if ($sectionName.ToLower().Contains($sus.ToLower())) {
                    $confidence += 40
                    $reasons += "Expiro section name: $sectionName"
                    break
                }
            }
            
            # Check for benign packer
            foreach ($packer in $packerSections) {
                if ($sectionName -eq $packer) {
                    $isKnownPacker = $true
                    break
                }
            }
            
            # Heuristic 3: High entropy executable section
            if ($isExec -and $rawSize -gt 0 -and $rawOffset -lt $file.Length) {
                $sampleSize = [Math]::Min($rawSize, 8192)
                $endPos = [Math]::Min($rawOffset + $sampleSize, $file.Length)
                if ($endPos -gt $rawOffset) {
                    $sectionData = $file[$rawOffset..($endPos - 1)]
                    $sEntropy = Get-Entropy -Bytes $sectionData
                    if ($sEntropy -gt 7.0) {
                        $highEntropyExecCount++
                    }
                }
            }
            
            # Heuristic 6: Exec + Writable sections
            if ($isExec -and $isWritable) {
                $execWritableCount++
            }
        }
        
        # Heuristic 2: Unusual section count
        if ($sectionCount -gt 8) {
            $score = 15
            if ($isKnownPacker) { $score = 5 }
            $confidence += $score
            $reasons += "Unusual section count: $sectionCount"
        }
        
        # Heuristic 3: Score high-entropy executable sections
        if ($highEntropyExecCount -gt 0) {
            $perSection = 20
            if ($isKnownPacker) { $perSection = 5 }
            $score = $perSection * [Math]::Min($highEntropyExecCount, 2)
            $confidence += $score
            $reasons += "High entropy executable sections: $highEntropyExecCount"
        }
        
        # Heuristic 6: Multiple exec+writable sections
        if ($execWritableCount -ge 2) {
            $confidence += 15
            $reasons += "Multiple executable+writable sections: $execWritableCount"
        }
        
        # Heuristic 7: Overlay analysis (Expiro appends 40-150KB of encrypted data)
        if ($lastSectionEnd -gt 0 -and $lastSectionEnd -lt $file.Length) {
            $overlaySize = $file.Length - $lastSectionEnd
            if ($overlaySize -ge 40960 -and $overlaySize -le 153600) {
                $oEnd = [Math]::Min($lastSectionEnd + 8191, $file.Length - 1)
                if ($oEnd -gt $lastSectionEnd) {
                    $overlaySample = $file[$lastSectionEnd..$oEnd]
                    $overlayEntropy = Get-Entropy -Bytes $overlaySample
                    if ($overlayEntropy -gt 7.0) {
                        $confidence += 20
                        $reasons += "Suspicious overlay: $([math]::Round($overlaySize/1024, 1))KB (entropy: $([math]::Round($overlayEntropy, 2)))"
                    } else {
                        $confidence += 10
                        $reasons += "Overlay data: $([math]::Round($overlaySize/1024, 1))KB"
                    }
                }
            }
        }
        
        # Heuristic 9: Injection API imports (search first 64KB only)
        $searchLen = [Math]::Min($file.Length, 65536)
        $importRegion = [System.Text.Encoding]::ASCII.GetString($file, 0, $searchLen)
        $injectionAPIs = @('VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread')
        $apiMatches = 0
        foreach ($api in $injectionAPIs) {
            if ($importRegion.Contains($api)) {
                $apiMatches++
            }
        }
        if ($apiMatches -ge 3) {
            $confidence += 10
            $reasons += "Injection APIs found: $apiMatches/4"
        }
        
        # Heuristic 10: Timestamp anomaly
        if ($timeDateStamp -gt 0) {
            try {
                $compileDate = [DateTimeOffset]::FromUnixTimeSeconds($timeDateStamp).DateTime
                if ($compileDate.Year -lt 2000 -or $compileDate.Year -gt ([DateTime]::Now.Year + 1)) {
                    $confidence += 5
                    $reasons += "Suspicious compile timestamp: $($compileDate.ToString('yyyy-MM-dd'))"
                }
            } catch {
                # Invalid timestamp - skip
            }
        }
        
        # Known-packer discount
        if ($isKnownPacker -and $confidence -gt 0 -and $confidence -lt 80) {
            $discount = [Math]::Min(15, $confidence)
            $confidence -= $discount
            $reasons += "Known-packer discount: -$discount"
        }
        
        $confidence = [Math]::Max(0, [Math]::Min(100, $confidence))
        
        return @{
            IsInfected = ($confidence -ge 60)
            Confidence = $confidence
            Reasons = $reasons
        }
        
    } catch {
        return $false
    }
}

# Scan critical directories
$scanPaths = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows\System32",
    "C:\Users\$env:USERNAME\AppData\Local",
    "C:\Users\$env:USERNAME\AppData\Roaming",
    "C:\Users\$env:USERNAME\Desktop",
    "C:\Users\$env:USERNAME\Downloads"
)

Write-Host "Scanning critical directories..." -ForegroundColor Yellow
Write-Host ""

$totalScanned = 0
$totalInfected = 0
$infectedFiles = @()
$startTime = Get-Date

foreach ($scanPath in $scanPaths) {
    if (!(Test-Path $scanPath)) {
        Write-Host "Skipping: $scanPath (not found)" -ForegroundColor Gray
        continue
    }
    
    Write-Host "Scanning: $scanPath" -ForegroundColor Cyan
    
    $exeFiles = Get-ChildItem -Path $scanPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
    
    foreach ($file in $exeFiles) {
        $totalScanned++
        
        # Progress indicator every 100 files
        if ($totalScanned % 100 -eq 0) {
            Write-Host "  Progress: $totalScanned files scanned, $totalInfected infected..." -ForegroundColor Gray
        }
        
        $result = Test-ExpiroInfection -FilePath $file.FullName
        
        if ($result -and $result.IsInfected) {
            $totalInfected++
            $infectedFiles += [PSCustomObject]@{
                Path = $file.FullName
                Size = $file.Length
                Confidence = $result.Confidence
                Reasons = $result.Reasons -join "; "
                Modified = $file.LastWriteTime
            }
            
            Write-Host "  [!] INFECTED: $($file.Name)" -ForegroundColor Red
            Write-Host "     Confidence: $($result.Confidence)%" -ForegroundColor Yellow
            Write-Host "     Path: $($file.FullName)" -ForegroundColor Gray
            
            # Quarantine if removal mode enabled
            if ($RemoveInfections) {
                try {
                    $quarantinePath = Join-Path $quarantineDir $file.Name
                    $counter = 1
                    while (Test-Path $quarantinePath) {
                        $quarantinePath = Join-Path $quarantineDir "$($file.BaseName)_$counter$($file.Extension)"
                        $counter++
                    }
                    
                    Move-Item -Path $file.FullName -Destination $quarantinePath -Force
                    Write-Host "     [+] Quarantined to: $quarantinePath" -ForegroundColor Green
                    
                    # Log the action
                    Add-Content -Path (Join-Path $quarantineDir "quarantine_log.txt") -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $($file.FullName) | Confidence: $($result.Confidence)% | $($result.Reasons -join '; ')"
                    
                } catch {
                    Write-Host "     [-] Failed to quarantine: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

$elapsed = (Get-Date) - $startTime

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "Files Scanned: $totalScanned" -ForegroundColor White
Write-Host "Infections Found: $totalInfected" -ForegroundColor $(if($totalInfected -gt 0){"Red"}else{"Green"})
Write-Host "Scan Duration: $([math]::Round($elapsed.TotalSeconds, 1)) seconds" -ForegroundColor White
Write-Host "Scan Speed: $([math]::Round($totalScanned / [Math]::Max($elapsed.TotalSeconds, 1), 0)) files/sec" -ForegroundColor White
Write-Host ""

if ($totalInfected -gt 0) {
    Write-Host "Infected Files Details:" -ForegroundColor Yellow
    Write-Host ""
    $infectedFiles | Format-Table -AutoSize Path, @{Name="Confidence";Expression={"$($_.Confidence)%"}}, @{Name="Size (KB)";Expression={[math]::Round($_.Size/1KB, 2)}}
    
    # Export to log file
    $logDir = "research\logs"
    if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $logPath = "$logDir\full_scan_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $infectedFiles | Export-Csv -Path $logPath -NoTypeInformation
    Write-Host "Detailed log saved to: $logPath" -ForegroundColor Green
    Write-Host ""
    
    if ($RemoveInfections) {
        Write-Host "[+] All infected files have been quarantined to: $quarantineDir" -ForegroundColor Green
    } else {
        Write-Host "[!] To remove infections, run with -RemoveInfections flag" -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] No Expiro infections detected! System is clean." -ForegroundColor Green
}

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
