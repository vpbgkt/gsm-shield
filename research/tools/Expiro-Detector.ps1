#Requires -Version 5.1
<#
.SYNOPSIS
    GSM Shield AV - Expiro File Infector Detector (PowerShell Edition)

.DESCRIPTION
    Scans directories for Win32/Expiro.EK!MTB infections using heuristic analysis.
    Does NOT delete files - only reports detections for further analysis.

.PARAMETER Path
    Directory to scan

.PARAMETER Recursive
    Scan subdirectories recursively

.PARAMETER OutputReport
    Path to save detailed report

.EXAMPLE
    .\Expiro-Detector.ps1 -Path "C:\Windows\System32" -Recursive
    
.EXAMPLE
    .\Expiro-Detector.ps1 -Path "C:\Program Files" -OutputReport "scan_results.txt"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    
    [switch]$Recursive,
    
    [string]$OutputReport = "research\logs\expiro_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# Banner
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "GSM SHIELD AV - EXPIRO DETECTOR v1.0 (PowerShell)" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

# Statistics
$script:FilesScanned = 0
$script:InfectedFiles = @()
$script:Errors = 0

function Get-FileEntropy {
    param([byte[]]$Bytes)
    
    if ($Bytes.Length -eq 0) { return 0 }
    
    $frequency = @{}
    foreach ($byte in $Bytes) {
        if ($frequency.ContainsKey($byte)) {
            $frequency[$byte]++
        } else {
            $frequency[$byte] = 1
        }
    }
    
    $entropy = 0.0
    $length = $Bytes.Length
    
    foreach ($count in $frequency.Values) {
        $probability = $count / $length
        if ($probability -gt 0) {
            $entropy -= $probability * [Math]::Log($probability, 2)
        }
    }
    
    return $entropy
}

function Test-PEFile {
    param([string]$FilePath)
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Check DOS header "MZ"
        if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
            return $false
        }
        
        # Get PE header offset
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        
        if ($peOffset -lt 0 -or $peOffset -ge $bytes.Length - 4) {
            return $false
        }
        
        # Check PE signature "PE\0\0"
        if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45 -and 
            $bytes[$peOffset+2] -eq 0x00 -and $bytes[$peOffset+3] -eq 0x00) {
            return $true
        }
        
        return $false
        
    } catch {
        return $false
    }
}

function Get-PEInfectionSignatures {
    param([string]$FilePath)
    
    $detectionReasons = @()
    $confidenceScore = 0
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileSize = $bytes.Length
        
        # Get PE header offset
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        
        # Parse COFF header
        $coffOffset = $peOffset + 4
        $numberOfSections = [BitConverter]::ToUInt16($bytes, $coffOffset + 2)
        
        # Check for unusual number of sections
        if ($numberOfSections -gt 8) {
            $detectionReasons += "Unusual section count: $numberOfSections (normal: 3-6)"
            $confidenceScore += 15
        }
        
        # Parse Optional Header
        $optHeaderOffset = $coffOffset + 20
        $magic = [BitConverter]::ToUInt16($bytes, $optHeaderOffset)
        
        $is64bit = ($magic -eq 0x20B)
        $entryPointOffset = if ($is64bit) { $optHeaderOffset + 16 } else { $optHeaderOffset + 16 }
        $entryPointRVA = [BitConverter]::ToUInt32($bytes, $entryPointOffset)
        
        # Parse Section Table
        $sectionTableOffset = $optHeaderOffset + (if ($is64bit) { 240 } else { 224 })
        
        $suspiciousSections = @('.expiro', '.virus', '.packed', '.stub', 'UPX0', 'UPX1')
        $highEntropySections = 0
        $entryPointSection = $null
        
        for ($i = 0; $i -lt $numberOfSections; $i++) {
            $sectionOffset = $sectionTableOffset + ($i * 40)
            
            # Section name (8 bytes)
            $sectionNameBytes = $bytes[$sectionOffset..($sectionOffset+7)]
            $sectionName = [System.Text.Encoding]::ASCII.GetString($sectionNameBytes).TrimEnd([char]0)
            
            # Virtual Address
            $virtualAddress = [BitConverter]::ToUInt32($bytes, $sectionOffset + 12)
            $virtualSize = [BitConverter]::ToUInt32($bytes, $sectionOffset + 8)
            
            # Raw data
            $rawSize = [BitConverter]::ToUInt32($bytes, $sectionOffset + 16)
            $rawOffset = [BitConverter]::ToUInt32($bytes, $sectionOffset + 20)
            
            # Characteristics
            $characteristics = [BitConverter]::ToUInt32($bytes, $sectionOffset + 36)
            $isExecutable = ($characteristics -band 0x20000000) -ne 0
            
            # Check 1: Suspicious section names
            foreach ($susName in $suspiciousSections) {
                if ($sectionName -like "*$susName*") {
                    $detectionReasons += "Suspicious section name: $sectionName"
                    $confidenceScore += 30
                    break
                }
            }
            
            # Check 2: High entropy in executable sections
            if ($isExecutable -and $rawSize -gt 0 -and $rawOffset -lt $bytes.Length) {
                $maxReadSize = [Math]::Min($rawSize, 8192)  # Sample first 8KB
                $sectionData = $bytes[$rawOffset..($rawOffset + $maxReadSize - 1)]
                $entropy = Get-FileEntropy -Bytes $sectionData
                
                if ($entropy -gt 7.0) {
                    $detectionReasons += "High entropy executable section: $sectionName (entropy: $($entropy.ToString('F2')))"
                    $confidenceScore += 20
                    $highEntropySections++
                }
            }
            
            # Check 3: Entry point location
            if ($virtualAddress -le $entryPointRVA -and $entryPointRVA -lt ($virtualAddress + $virtualSize)) {
                $entryPointSection = $sectionName
            }
            
            # Check 4: Suspicious size ratios
            if ($rawSize -gt 0 -and $virtualSize -gt 0) {
                $ratio = $virtualSize / $rawSize
                if ($ratio -gt 2.5 -or $ratio -lt 0.4) {
                    $detectionReasons += "Suspicious section size ratio: $sectionName (virt/raw: $($ratio.ToString('F2')))"
                    $confidenceScore += 10
                }
            }
        }
        
        # Check 5: Entry point in unusual section
        if ($entryPointSection -and $entryPointSection -notmatch '^(\.text|CODE|\.code|_text)$') {
            $detectionReasons += "Entry point in unusual section: $entryPointSection"
            $confidenceScore += 25
        }
        
        # Check 6: Multiple high-entropy sections
        if ($highEntropySections -ge 2) {
            $detectionReasons += "Multiple high-entropy sections detected ($highEntropySections)"
            $confidenceScore += 15
        }
        
        # Check 7: File size analysis (Expiro adds 40-150 KB)
        # This requires knowing original size, so we use heuristics
        if ($fileSize -lt 50KB) {
            # Small files shouldn't have many sections
            if ($numberOfSections -gt 5) {
                $detectionReasons += "Small file with many sections (possible inflation)"
                $confidenceScore += 10
            }
        }
        
        # Check 8: Scan for common Expiro byte patterns
        $byteString = [System.Text.Encoding]::ASCII.GetString($bytes)
        
        # Look for suspicious strings (case-insensitive)
        $suspiciousStrings = @('expiro', 'infected', 'dropper', 'payload')
        foreach ($str in $suspiciousStrings) {
            if ($byteString -match $str) {
                $detectionReasons += "Suspicious string found in binary: $str"
                $confidenceScore += 5
            }
        }
        
    } catch {
        $script:Errors++
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            IsInfected = $false
            Confidence = 0
            Reasons = @("Analysis error: $($_.Exception.Message)")
        }
    }
    
    $isInfected = $confidenceScore -ge 50
    
    return @{
        IsInfected = $isInfected
        Confidence = $confidenceScore
        Reasons = $detectionReasons
        FilePath = $FilePath
        FileSize = $fileSize
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Scan-File {
    param([System.IO.FileInfo]$File)
    
    $script:FilesScanned++
    
    # Progress indicator
    if ($script:FilesScanned % 50 -eq 0) {
        Write-Host "`r  [Progress: $script:FilesScanned files scanned, $($script:InfectedFiles.Count) infected]" -NoNewline -ForegroundColor Gray
    }
    
    # Only scan PE files
    if ($File.Extension -notin @('.exe', '.dll', '.sys', '.scr', '.com')) {
        return
    }
    
    # Check if it's a valid PE file
    if (-not (Test-PEFile -FilePath $File.FullName)) {
        return
    }
    
    # Analyze for infection
    $result = Get-PEInfectionSignatures -FilePath $File.FullName
    
    if ($result.IsInfected) {
        $script:InfectedFiles += $result
        
        Write-Host ""  # Clear progress line
        Write-Host ""
        Write-Host "🦠 INFECTED: $($File.FullName)" -ForegroundColor Red
        Write-Host "   Confidence: $($result.Confidence)%" -ForegroundColor Yellow
        Write-Host "   Size: $([math]::Round($result.FileSize / 1KB, 2)) KB" -ForegroundColor Gray
        foreach ($reason in $result.Reasons) {
            Write-Host "   - $reason" -ForegroundColor Gray
        }
    }
}

function Scan-Directory {
    param([string]$DirectoryPath, [bool]$ScanRecursive)
    
    Write-Host "[*] Scanning: $DirectoryPath" -ForegroundColor Cyan
    Write-Host "[*] Recursive: $ScanRecursive" -ForegroundColor Cyan
    Write-Host "-" * 70
    Write-Host ""
    
    try {
        if ($ScanRecursive) {
            $files = Get-ChildItem -Path $DirectoryPath -File -Recurse -ErrorAction SilentlyContinue
        } else {
            $files = Get-ChildItem -Path $DirectoryPath -File -ErrorAction SilentlyContinue
        }
        
        foreach ($file in $files) {
            Scan-File -File $file
        }
        
    } catch {
        Write-Host ""
        Write-Host "ERROR scanning directory: $($_.Exception.Message)" -ForegroundColor Red
        $script:Errors++
    }
}

function Save-Report {
    param([string]$ReportPath)
    
    $reportLines = @()
    $reportLines += "================================================================================"
    $reportLines += "GSM SHIELD AV - EXPIRO DETECTION REPORT"
    $reportLines += "================================================================================"
    $reportLines += ""
    $reportLines += "Scan Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $reportLines += "Scan Path: $Path"
    $reportLines += "Recursive: $Recursive"
    $reportLines += "Files Scanned: $script:FilesScanned"
    $reportLines += "Infected Files: $($script:InfectedFiles.Count)"
    $reportLines += "Errors: $script:Errors"
    $reportLines += ""
    $reportLines += "================================================================================"
    $reportLines += ""
    
    if ($script:InfectedFiles.Count -eq 0) {
        $reportLines += "No Expiro infections detected."
    } else {
        for ($i = 0; $i -lt $script:InfectedFiles.Count; $i++) {
            $detection = $script:InfectedFiles[$i]
            
            $reportLines += ""
            $reportLines += "[$($i+1)] INFECTED FILE"
            $reportLines += "--------------------------------------------------------------------------------"
            $reportLines += "Path: $($detection.FilePath)"
            $reportLines += "Size: $([math]::Round($detection.FileSize / 1KB, 2)) KB"
            $reportLines += "Confidence: $($detection.Confidence)%"
            $reportLines += "Detection Time: $($detection.Timestamp)"
            $reportLines += ""
            $reportLines += "Reasons:"
            
            foreach ($reason in $detection.Reasons) {
                $reportLines += "  - $reason"
            }
            
            $reportLines += ""
        }
    }
    
    $reportLines += ""
    $reportLines += "================================================================================"
    $reportLines += "END OF REPORT"
    $reportLines += "================================================================================"
    
    # Ensure directory exists
    $reportDir = Split-Path -Path $ReportPath -Parent
    if ($reportDir -and -not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    $reportLines | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host ""
    Write-Host "[✓] Report saved to: $ReportPath" -ForegroundColor Green
}

# Main execution
if (-not (Test-Path $Path)) {
    Write-Host "ERROR: Path not found: $Path" -ForegroundColor Red
    exit 1
}

# Start scan
$startTime = Get-Date
Scan-Directory -DirectoryPath $Path -ScanRecursive $Recursive

# Calculate duration
$duration = (Get-Date) - $startTime

# Summary
Write-Host ""
Write-Host ""
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Files Scanned: $script:FilesScanned" -ForegroundColor White
Write-Host "Infections Found: $($script:InfectedFiles.Count)" -ForegroundColor $(if ($script:InfectedFiles.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "Errors: $script:Errors" -ForegroundColor $(if ($script:Errors -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor White
Write-Host "=" * 70 -ForegroundColor Cyan

# Save report
Save-Report -ReportPath $OutputReport

# Display infected file list
if ($script:InfectedFiles.Count -gt 0) {
    Write-Host ""
    Write-Host "Infected Files:" -ForegroundColor Yellow
    foreach ($detection in $script:InfectedFiles) {
        $filePath = $detection.FilePath
        Write-Host "  - $filePath" -ForegroundColor Red
    }
}

Write-Host ""
