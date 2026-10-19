# Get Defender threat info without pipeline filtering issues
$threats = Get-MpThreat
Write-Host "=== ACTIVE THREATS ===" -ForegroundColor Red
foreach ($t in $threats) {
    Write-Host ""
    Write-Host "Threat: $($t.ThreatName)" -ForegroundColor Yellow
    Write-Host "Active: $($t.IsActive)"
    Write-Host "Severity: $($t.SeverityID)"
    if ($t.Resources) {
        foreach ($r in $t.Resources) {
            Write-Host "  Resource: $r" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "=== RECENT DETECTIONS ===" -ForegroundColor Red
$detections = Get-MpThreatDetection | Select-Object -First 10
foreach ($d in $detections) {
    Write-Host ""
    Write-Host "ThreatID: $($d.ThreatID)" -ForegroundColor Yellow
    Write-Host "Time: $($d.InitialDetectionTime)"
    Write-Host "Success: $($d.ActionSuccess)"
    if ($d.Resources) {
        foreach ($r in $d.Resources) {
            Write-Host "  File: $r" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "=== SCANNING FOR LIVE INFECTED FILES ===" -ForegroundColor Red
# Check which exe files still exist and might be infected
$checkPaths = @(
    "C:\Program Files\Git\cmd",
    "C:\Program Files\Git\usr\bin",
    "C:\Program Files\nodejs",
    "C:\Users\$env:USERNAME\AppData\Local",
    "C:\Users\$env:USERNAME\Downloads"
)

$liveExes = @()
foreach ($cp in $checkPaths) {
    if (Test-Path -LiteralPath $cp) {
        $files = Get-ChildItem -Path $cp -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 5
        foreach ($f in $files) {
            $liveExes += $f.FullName
            Write-Host "Found: $($f.FullName) ($([math]::Round($f.Length/1KB))KB)" -ForegroundColor Cyan
        }
    }
}

Write-Host ""
Write-Host "Total live exe files found for analysis: $($liveExes.Count)"
