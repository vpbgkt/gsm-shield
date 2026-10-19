# Quick Expiro Scanner v2 - Simple PowerShell Version
# Updated with v2 heuristics (UPX false-positive fix, overlay analysis)
param(
    [Parameter(Mandatory=$false)]
    [string]$Path = "$env:USERPROFILE\Downloads"
)

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " GSM SHIELD AV — QUICK EXPIRO SCANNER v2" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$infected = @()
$scanned = 0

# Simple PE checker
function Test-IsPE {
    param([string]$FilePath)
    
    try {
        $bytes = [IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -lt 64) { return $false }
        
        # Check MZ header
        if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            # Check PE signature
            $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
            if ($peOffset -gt 0 -and $peOffset -lt ($bytes.Length - 4)) {
                if ($bytes[$peOffset] -eq 0x50 -and $bytes[$peOffset+1] -eq 0x45) {
                    return $true
                }
            }
        }
    } catch {}
    
    return $false
}

# v2 Expiro heuristic (improved accuracy)
function Test-ExpiroSigns {
    param([string]$FilePath)
    
    try {
        $bytes = [IO.File]::ReadAllBytes($FilePath)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
        $sectionsOffset = $peOffset + 4 + 20 + $optHeaderSize
        $sectionCount = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
        
        $score = 0
        $reasons = @()
        $isKnownPacker = $false
        
        # Expiro section names (NOT including UPX — that's a benign packer)
        $expiroNames = @('expiro', 'virus', 'packed', 'stub', 'ndata')
        $packerNames = @('UPX0', 'UPX1', 'UPX2', '.aspack')
        
        $lastSectionEnd = 0
        
        # Check section names
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $offset = $sectionsOffset + ($i * 40)
            if ($offset + 40 -gt $bytes.Length) { break }
            
            $name = [Text.Encoding]::ASCII.GetString($bytes[$offset..($offset+7)]).Trim([char]0)
            $rawSize = [BitConverter]::ToUInt32($bytes, $offset + 16)
            $rawOffset = [BitConverter]::ToUInt32($bytes, $offset + 20)
            
            # Track section end for overlay
            $secEnd = $rawOffset + $rawSize
            if ($secEnd -gt $lastSectionEnd) { $lastSectionEnd = $secEnd }
            
            # Check for Expiro sections
            foreach ($sus in $expiroNames) {
                if ($name.ToLower().Contains($sus)) {
                    $score += 40
                    $reasons += "Expiro section: $name"
                    break
                }
            }
            
            # Check for benign packer
            foreach ($packer in $packerNames) {
                if ($name -eq $packer) { $isKnownPacker = $true; break }
            }
        }
        
        # Many sections = suspicious
        if ($sectionCount -gt 8) {
            $s = if ($isKnownPacker) { 5 } else { 15 }
            $score += $s
            $reasons += "Many sections: $sectionCount"
        }
        
        # Overlay analysis (Expiro appends 40-150KB)
        $overlaySize = $bytes.Length - $lastSectionEnd
        if ($overlaySize -ge 40KB -and $overlaySize -le 150KB) {
            $score += 15
            $reasons += "Suspicious overlay: $([math]::Round($overlaySize/1KB, 1))KB"
        }
        
        # Known-packer discount
        if ($isKnownPacker -and $score -gt 0 -and $score -lt 80) {
            $discount = [Math]::Min(15, $score)
            $score -= $discount
            $reasons += "Packer discount: -$discount"
        }
        
        if ($score -ge 60) {
            return @{
                Infected = $true
                Score = $score
                Reasons = $reasons
            }
        }
        
    } catch {}
    
    return @{ Infected = $false }
}

Write-Host "Scanning: $Path" -ForegroundColor Yellow
Write-Host ""

Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Extension -match '\.(exe|dll|sys|scr)$') {
        $scanned++
        
        if (Test-IsPE -FilePath $_.FullName) {
            $result = Test-ExpiroSigns -FilePath $_.FullName
            
            if ($result.Infected) {
                Write-Host "[INFECTED] $($_.FullName)" -ForegroundColor Red
                Write-Host "  Score: $($result.Score)%" -ForegroundColor Yellow
                foreach ($r in $result.Reasons) {
                    Write-Host "  - $r" -ForegroundColor Gray
                }
                Write-Host ""
                
                $infected += @{
                    Path = $_.FullName
                    Score = $result.Score
                    Reasons = $result.Reasons
                }
            }
        }
        
        if ($scanned % 20 -eq 0) {
            Write-Host "  Scanned: $scanned files..." -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "Files Scanned: $scanned" -ForegroundColor White
Write-Host "Infections: $($infected.Count)" -ForegroundColor $(if ($infected.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "===================================================================" -ForegroundColor Cyan

if ($infected.Count -gt 0) {
    Write-Host ""
    Write-Host "INFECTED FILES:" -ForegroundColor Yellow
    foreach ($item in $infected) {
        Write-Host "  $($item.Path)" -ForegroundColor Red
    }
}

Write-Host ""
