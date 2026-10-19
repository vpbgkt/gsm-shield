# Expiro Memory Hunter - Find the active infection source
# The virus is resident in memory, infecting files as they run
# We need to find WHICH process is doing the infecting

Write-Host "================================================================" -ForegroundColor Red
Write-Host " GSM SHIELD AV - EXPIRO MEMORY HUNTER" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host ""

# 1. Check Defender threat history (with timeout to prevent hanging)
Write-Host "=== DEFENDER THREAT HISTORY ===" -ForegroundColor Yellow
$defenderJob = Start-Job -ScriptBlock { Get-MpThreat }
if (Wait-Job $defenderJob -Timeout 2) {
    $threats = Receive-Job $defenderJob
    foreach ($t in $threats) {
        Write-Host "  Threat: $($t.ThreatName)" -ForegroundColor Red
        Write-Host "  Active: $($t.IsActive) | Severity: $($t.SeverityID)"
        if ($t.Resources) {
            foreach ($r in $t.Resources) {
                Write-Host "    -> $r" -ForegroundColor Gray
            }
        }
        Write-Host ""
    }
} else {
    Stop-Job $defenderJob -ErrorAction SilentlyContinue
    Remove-Job $defenderJob -Force -ErrorAction SilentlyContinue
    Write-Host "  [Defender query timed out - Defender service inactive or locked]" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "=== RUNNING PROCESSES ANALYSIS ===" -ForegroundColor Yellow

# 3. Get all running processes with their file paths
$procs = Get-Process | Where-Object { $_.Path -ne $null } | Select-Object Id, ProcessName, Path, StartTime, WorkingSet64

# 4. Check each process executable for signs of infection
$suspicious = @()
foreach ($p in $procs) {
    try {
        if (!(Test-Path -LiteralPath $p.Path)) { continue }
        
        $bytes = [System.IO.File]::ReadAllBytes($p.Path)
        if ($bytes.Length -lt 64) { continue }
        if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { continue }
        
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($peOffset -lt 0 -or $peOffset -ge $bytes.Length - 4) { continue }
        if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45) { continue }
        
        $sectionCount = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
        $optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 24)
        $epRVA = [BitConverter]::ToUInt32($bytes, $peOffset + 4 + 20 + 16)
        
        $secTableOff = $peOffset + 4 + 20 + $optHeaderSize
        $sections = @()
        $lastSecEnd = 0
        
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $o = $secTableOff + ($i * 40)
            if ($o + 40 -gt $bytes.Length) { break }
            
            $name = [System.Text.Encoding]::ASCII.GetString($bytes[$o..($o+7)]).TrimEnd([char]0)
            $va = [BitConverter]::ToUInt32($bytes, $o + 12)
            $vs = [BitConverter]::ToUInt32($bytes, $o + 8)
            $rs = [BitConverter]::ToUInt32($bytes, $o + 16)
            $ro = [BitConverter]::ToUInt32($bytes, $o + 20)
            $ch = [BitConverter]::ToUInt32($bytes, $o + 36)
            
            $isExec = ($ch -band 0x20000000) -ne 0
            $isWrite = ($ch -band 0x80000000) -ne 0
            
            $secEnd = $ro + $rs
            if ($secEnd -gt $lastSecEnd) { $lastSecEnd = $secEnd }
            
            $sections += @{
                Name = $name; VA = $va; VS = $vs; RS = $rs; RO = $ro
                Exec = $isExec; Write = $isWrite; Chars = $ch
            }
        }
        
        $lastSec = $sections[$sections.Count - 1]
        $overlaySize = $bytes.Length - $lastSecEnd
        
        # Check: EP in last section?
        $epInLast = $false
        if ($lastSec -and $sections.Count -gt 1) {
            if ($epRVA -ge $lastSec.VA -and $epRVA -lt ($lastSec.VA + $lastSec.VS)) {
                $epInLast = $true
            }
        }
        
        # Check: Last section exec+write?
        $lastExecWrite = $false
        if ($lastSec) {
            $lastExecWrite = $lastSec.Exec -and $lastSec.Write
        }
        
        # Check: Suspicious overlay
        $susOverlay = ($overlaySize -ge 40960 -and $overlaySize -le 153600)
        
        # Score
        $score = 0
        $reasons = @()
        
        if ($epInLast) {
            $score += 25
            $reasons += "EP in last section [$($lastSec.Name)]"
        }
        if ($lastExecWrite) {
            $score += 20
            $reasons += "Last section EXEC+WRITE [$($lastSec.Name)]"
        }
        if ($susOverlay) {
            $score += 15
            $reasons += "Overlay: $([math]::Round($overlaySize/1024, 1))KB"
        }
        if ($sectionCount -gt 8) {
            $score += 5
            $reasons += "Sections: $sectionCount"
        }
        
        # Check for injection APIs in the running process
        $searchLen = [Math]::Min($bytes.Length, 65536)
        $importRegion = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $searchLen)
        $apis = @('VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'NtWriteVirtualMemory')
        $apiCount = 0
        foreach ($api in $apis) {
            if ($importRegion.Contains($api)) { $apiCount++ }
        }
        if ($apiCount -ge 3) {
            $score += 15
            $reasons += "Injection APIs: $apiCount/4"
        }
        
        if ($score -ge 30) {
            $suspicious += [PSCustomObject]@{
                PID = $p.Id
                Name = $p.ProcessName
                Path = $p.Path
                Score = $score
                Memory = [math]::Round($p.WorkingSet64/1MB, 1)
                StartTime = $p.StartTime
                Sections = $sectionCount
                Reasons = $reasons -join "; "
            }
        }
    } catch {
        # Skip processes we can't read
    }
}

Write-Host ""
if ($suspicious.Count -gt 0) {
    Write-Host "=== SUSPICIOUS RUNNING PROCESSES ===" -ForegroundColor Red
    $suspicious | Sort-Object Score -Descending | Format-Table -AutoSize PID, Name, Score, Memory, Sections, Reasons
    
    Write-Host "DETAILS:" -ForegroundColor Yellow
    foreach ($s in ($suspicious | Sort-Object Score -Descending)) {
        Write-Host "  [$($s.Score)%] PID=$($s.PID) $($s.Name)" -ForegroundColor Red
        Write-Host "    Path: $($s.Path)" -ForegroundColor Gray
        Write-Host "    Started: $($s.StartTime)" -ForegroundColor Gray
        Write-Host "    Memory: $($s.Memory) MB" -ForegroundColor Gray
        Write-Host "    $($s.Reasons)" -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "No suspicious running processes found." -ForegroundColor Green
}

# 5. Check for recently modified exe/dll files (sign of active infection)
Write-Host ""
Write-Host "=== RECENTLY MODIFIED EXECUTABLES (Last 2 hours) ===" -ForegroundColor Yellow
$cutoff = (Get-Date).AddHours(-2)
$recentMods = @()

$checkDirs = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows\System32"
)

foreach ($dir in $checkDirs) {
    if (Test-Path -LiteralPath $dir) {
        $files = Get-ChildItem -Path $dir -Recurse -Include "*.exe","*.dll" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff }
        foreach ($f in $files) {
            $recentMods += [PSCustomObject]@{
                Path = $f.FullName
                Modified = $f.LastWriteTime
                Size = [math]::Round($f.Length/1KB, 1)
            }
        }
    }
}

if ($recentMods.Count -gt 0) {
    Write-Host "Found $($recentMods.Count) recently modified executables:" -ForegroundColor Red
    $recentMods | Sort-Object Modified -Descending | Select-Object -First 20 | Format-Table -AutoSize Path, Modified, @{N="Size(KB)";E={$_.Size}}
} else {
    Write-Host "No recently modified executables found." -ForegroundColor Green
}

# 6. Check scheduled tasks for persistence
Write-Host ""
Write-Host "=== CHECKING FOR SUSPICIOUS SCHEDULED TASKS ===" -ForegroundColor Yellow
$tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" }
$susTask = @()
foreach ($task in $tasks) {
    $actions = $task.Actions
    foreach ($a in $actions) {
        if ($a.Execute -and $a.Execute -match '\\AppData\\|\\Temp\\|\\Users\\.*\\Downloads\\') {
            $susTask += [PSCustomObject]@{
                Name = $task.TaskName
                Path = $task.TaskPath
                Execute = $a.Execute
                State = $task.State
            }
        }
    }
}

if ($susTask.Count -gt 0) {
    Write-Host "Suspicious scheduled tasks found:" -ForegroundColor Red
    $susTask | Format-Table -AutoSize
} else {
    Write-Host "No suspicious scheduled tasks found." -ForegroundColor Green
}

# 7. Check Run keys for persistence
Write-Host ""
Write-Host "=== CHECKING REGISTRY RUN KEYS ===" -ForegroundColor Yellow
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        $props = $entries.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
        if ($props.Count -gt 0) {
            Write-Host "  $key :" -ForegroundColor Cyan
            foreach ($prop in $props) {
                Write-Host "    $($prop.Name) = $($prop.Value)" -ForegroundColor Gray
            }
        }
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Red
Write-Host " SCAN COMPLETE" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
