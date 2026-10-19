# Selective File Restoration from Quarantine
# Use ONLY for files you absolutely need and cannot reinstall

param(
    [Parameter(Mandatory=$true)]
    [string]$FileName,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListOnly = $false
)

$quarantineDir = "C:\GSMShield\Quarantine"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " GSM SHIELD AV - SELECTIVE FILE RESTORATION" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[!!!] WARNING: Restoring infected files is DANGEROUS" -ForegroundColor Red
Write-Host "[!!!] Only use this if you ABSOLUTELY need a file and cannot reinstall" -ForegroundColor Red
Write-Host ""

if ($ListOnly) {
    Write-Host "Available files in quarantine:" -ForegroundColor Yellow
    Write-Host ""
    Get-ChildItem $quarantineDir -Recurse -File | Select-Object Name, @{Name="Size (KB)";Expression={[math]::Round($_.Length/1KB, 2)}}, LastWriteTime | Format-Table -AutoSize
    Write-Host ""
    Write-Host "To restore a file, run:" -ForegroundColor Cyan
    Write-Host ".\scripts\selective-restore.ps1 -FileName 'filename.exe'" -ForegroundColor White
    exit 0
}

# Find the file
$file = Get-ChildItem $quarantineDir -Recurse -Filter $FileName | Select-Object -First 1

if (!$file) {
    Write-Host "[!] File not found: $FileName" -ForegroundColor Red
    Write-Host ""
    Write-Host "Run with -ListOnly to see available files:" -ForegroundColor Yellow
    Write-Host ".\scripts\selective-restore.ps1 -ListOnly" -ForegroundColor White
    exit 1
}

Write-Host "[+] Found file: $($file.FullName)" -ForegroundColor Green
Write-Host "[i] Size: $([math]::Round($file.Length/1KB, 2)) KB" -ForegroundColor Gray
Write-Host ""

# Try to find original location from quarantine log
$logFile = Join-Path (Split-Path $quarantineDir) "quarantine_log.txt"
if (Test-Path $logFile) {
    $logEntry = Get-Content $logFile | Where-Object {$_ -match [regex]::Escape($FileName)} | Select-Object -First 1
    if ($logEntry) {
        Write-Host "[i] Original location found in log:" -ForegroundColor Cyan
        Write-Host $logEntry -ForegroundColor Gray
        Write-Host ""
    }
}

Write-Host "[!!!] FINAL WARNING" -ForegroundColor Red
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host "This file is INFECTED with Expiro virus!" -ForegroundColor Red
Write-Host "Restoring it will:" -ForegroundColor Red
Write-Host "  - Put the infection back on your system" -ForegroundColor Red
Write-Host "  - May spread to other files" -ForegroundColor Red
Write-Host "  - File may not work correctly anyway" -ForegroundColor Red
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "Are you ABSOLUTELY SURE you want to restore this file?" -ForegroundColor Yellow
Write-Host "Type 'YES I UNDERSTAND THE RISKS' to proceed:" -ForegroundColor Yellow
$confirmation = Read-Host

if ($confirmation -ne "YES I UNDERSTAND THE RISKS") {
    Write-Host ""
    Write-Host "[i] Restoration cancelled. Good choice!" -ForegroundColor Green
    Write-Host ""
    Write-Host "RECOMMENDATION: Reinstall the application instead" -ForegroundColor Cyan
    exit 0
}

Write-Host ""
Write-Host "Where should the file be restored to?" -ForegroundColor Yellow
Write-Host "Enter full path (or press Enter to see suggestions):" -ForegroundColor Yellow
$destination = Read-Host

if ([string]::IsNullOrEmpty($destination)) {
    Write-Host ""
    Write-Host "Restoration cancelled." -ForegroundColor Green
    exit 0
}

# Restore the file
try {
    Copy-Item $file.FullName -Destination $destination -Force
    Write-Host ""
    Write-Host "[+] File restored to: $destination" -ForegroundColor Green
    Write-Host ""
    Write-Host "[!!!] IMPORTANT: Re-scan your system immediately!" -ForegroundColor Red
    Write-Host "Run: .\research\tools\Full-System-Expiro-Scan.ps1 -ScanOnly" -ForegroundColor Yellow
    Write-Host ""
} catch {
    Write-Host ""
    Write-Host "[!] ERROR: Failed to restore file" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
