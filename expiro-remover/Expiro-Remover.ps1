<#
.SYNOPSIS
  Expiro Remover - scan for, contain and quarantine Expiro (Virus:Win32/Expiro, Virus:Win64/Expiro)
  file-infector infections on Windows. Single file, PowerShell 5.1+, no dependencies.

.DESCRIPTION
  Modes
    Scan       (default, read-only) structural scan of executables, running processes, services,
               autostart entries and published IOCs. Writes a report; changes nothing.
    Remediate  (administrator) everything Scan does, then:
                 1. stops running processes whose executable is infected
                 2. stops and disables services whose executable is infected
                 3. quarantines infected files outside protected Windows folders
                    (neutralized copy, original removed; reversible with Undo)
                 4. writes a reinstall / repair plan
               Protected Windows files (System32, SysWOW64, WinSxS, DriverStore, WindowsApps) are
               never deleted: their services are disabled and the plan says how to repair them.
    Undo       restores service start types and quarantined files from a Remediate state file.
    Verify     Scan, exit code 0 only when nothing infected was found.

  Detection is structural (validated on real infected/clean pairs, see the project docs):
    S1 last section executable but named as data (.reloc .rsrc .debug .symtab ...)        +50
    S1b last section executable+writable with another name                                +15
    S2 .reloc section present, base-relocation directory zero                              +25
    S3 ASLR (DYNAMIC_BASE) cleared while .reloc exists                                     +10
    S4 CALL/JMP in the first 32 bytes at the entry point lands in the last section        +40
    S5 last section RWX and >= 512 KB                                                      +10
    S6 1..8 rel32 branches in the entry section target the last section (no S4)          +15
    infected = score >= 75 and (S1 or S4)

  The tool never executes, opens for write, or patches a scanned file. In-place repair of
  Expiro-infected files is deliberately not attempted: replace them from the vendor (apps) or
  with DISM/SFC (Windows).

  Quarantine format: <QuarantineDir>\<sha256-16>_<name>.gsmq = "GSMQ\x01\0\0\0" + content XOR 0xA5
  (compatible with GSM Shield engine/quarantine.js). A .gsmq file is not a PE image and cannot run.

.EXAMPLE
  .\Expiro-Remover.ps1                                   # read-only scan of all fixed drives
.EXAMPLE
  .\Expiro-Remover.ps1 -Mode Remediate                   # elevated; asks for confirmation
.EXAMPLE
  .\Expiro-Remover.ps1 -Mode Undo -StateFile C:\ProgramData\ExpiroRemover\reports\<run>\state.json
#>
[CmdletBinding()]
param(
  [ValidateSet('Scan', 'Remediate', 'Undo', 'Verify')][string]$Mode = 'Scan',
  [string[]]$Roots,
  [string]$ReportDir,
  [string]$QuarantineDir = (Join-Path $env:ProgramData 'ExpiroRemover\quarantine'),
  [string]$StateFile,
  [switch]$Force,
  [switch]$SkipFiles,
  [switch]$SkipProcesses,
  [switch]$SkipServices
)

$ErrorActionPreference = 'Continue'
$Version = '0.1.0'

# ----------------------------------------------------------------------------------------------
# Core (C#): structural check + neutralized quarantine I/O
# ----------------------------------------------------------------------------------------------
$core = @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;
public class ErResult { public string Path; public bool IsPE; public int Score; public string Verdict; public string Last; public uint LastRaw; public string Indicators; public bool Is64; public string Error; }
public static class ExpiroRemoverCore {
  static readonly HashSet<string> Data = new HashSet<string>(new[]{".reloc",".rsrc",".debug",".data",".rdata",".pdata",".xdata",".idata",".edata",".tls",".bss",".didat","_RDATA",".fptable",".gfids",".00cfg",".CRT",".buildid",".symtab"});
  static bool IsData(string n){ return Data.Contains(n) || Regex.IsMatch(n, @"^/\d+$") || Regex.IsMatch(n, @"^\.z?debug"); }
  public static ErResult Check(string path) {
    var r = new ErResult(); r.Path = path; r.Verdict = "not-pe";
    try {
      using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
        long size = fs.Length; if (size < 0x200) return r;
        byte[] h = new byte[(int)Math.Min(size, 65536)]; int n = fs.Read(h, 0, h.Length);
        if (h[0] != 'M' || h[1] != 'Z') return r;
        int pe = BitConverter.ToInt32(h, 0x3C); if (pe < 0x40 || pe + 0x108 > n || BitConverter.ToUInt32(h, pe) != 0x4550) return r;
        int coff = pe + 4; int ns = BitConverter.ToUInt16(h, coff + 2); int opt = coff + 20; int optSize = BitConverter.ToUInt16(h, coff + 16);
        ushort magic = BitConverter.ToUInt16(h, opt); if (magic != 0x10B && magic != 0x20B) return r; r.Is64 = magic == 0x20B;
        uint ep = BitConverter.ToUInt32(h, opt + 16); ushort dllch = BitConverter.ToUInt16(h, opt + 70);
        int dd = opt + (r.Is64 ? 112 : 96); uint numDirs = BitConverter.ToUInt32(h, opt + (r.Is64 ? 108 : 92));
        uint relocRva = numDirs > 5 ? BitConverter.ToUInt32(h, dd + 40) : 0;
        int st = opt + optSize; if (ns == 0 || ns > 96 || st + ns * 40 > n) return r;
        r.IsPE = true;
        var nm = new string[ns]; var va = new uint[ns]; var vs = new uint[ns]; var rp = new uint[ns]; var rs = new uint[ns]; var ch = new uint[ns]; bool hasReloc = false;
        for (int i = 0; i < ns; i++) { int s = st + i * 40; nm[i] = System.Text.Encoding.ASCII.GetString(h, s, 8).TrimEnd('\0'); vs[i] = BitConverter.ToUInt32(h, s + 8); va[i] = BitConverter.ToUInt32(h, s + 12); rs[i] = BitConverter.ToUInt32(h, s + 16); rp[i] = BitConverter.ToUInt32(h, s + 20); ch[i] = BitConverter.ToUInt32(h, s + 36); if (nm[i] == ".reloc") hasReloc = true; }
        int li = ns - 1; bool lx = (ch[li] & 0x20000000) != 0 || (ch[li] & 0x20) != 0; bool lw = (ch[li] & 0x80000000) != 0;
        r.Last = nm[li]; r.LastRaw = rs[li];
        var ind = new List<string>(); int score = 0; bool anchor = false;
        if (lx && IsData(nm[li])) { score += 50; ind.Add("S1"); anchor = true; } else if (lx && lw) { score += 15; ind.Add("S1b"); }
        if (hasReloc && relocRva == 0) { score += 25; ind.Add("S2"); }
        if (hasReloc && (dllch & 0x40) == 0 && (lx || relocRva == 0)) { score += 10; ind.Add("S3"); }
        if (lx) {
          ulong lo = va[li], hi = (ulong)va[li] + Math.Max(vs[li], rs[li]);
          int es = -1; for (int i = 0; i < ns; i++) { if (ep >= va[i] && ep < va[i] + Math.Max(vs[i], rs[i])) { es = i; break; } }
          bool s4 = false;
          if (es >= 0 && es != li) {
            long fo = (long)rp[es] + (ep - va[es]);
            if (fo >= 0 && fo + 32 <= size) { byte[] b = new byte[32]; fs.Seek(fo, SeekOrigin.Begin); fs.Read(b, 0, 32);
              for (int k = 0; k + 5 <= 32; k++) { if (b[k] != 0xE8 && b[k] != 0xE9) continue; long t = (long)ep + k + 5 + BitConverter.ToInt32(b, k + 1); if (t >= (long)lo && t < (long)hi) { s4 = true; break; } } }
          }
          if (s4) { score += 40; ind.Add("S4"); anchor = true; }
          if (lw && rs[li] >= 0x80000) { score += 10; ind.Add("S5"); }
          if (!s4 && es >= 0 && es != li && rs[es] > 0) {
            int len = (int)Math.Min(Math.Min(rs[es], 4u * 1024 * 1024), Math.Max(0, size - rp[es])); byte[] b = new byte[len]; fs.Seek(rp[es], SeekOrigin.Begin); int got = fs.Read(b, 0, len); int cnt = 0;
            for (int k = 0; k + 5 <= got; k++) { if (b[k] != 0xE8 && b[k] != 0xE9) continue; long t = (long)va[es] + k + 5 + BitConverter.ToInt32(b, k + 1); if (t >= (long)lo && t < (long)hi) cnt++; }
            if (cnt >= 1 && cnt <= 8) { score += 15; ind.Add("S6"); }
          }
        }
        r.Score = Math.Min(100, score); r.Indicators = string.Join("+", ind);
        r.Verdict = (anchor && r.Score >= 75) ? "infected" : (r.Score >= 40 ? "suspicious" : "clean");
      }
    } catch (Exception ex) { r.Verdict = "error"; r.Error = ex.Message; }
    return r;
  }
  static readonly byte[] Magic = { 0x47, 0x53, 0x4D, 0x51, 0x01, 0x00, 0x00, 0x00 };
  static void Xcopy(Stream i, Stream o) { byte[] b = new byte[1 << 20]; int n; while ((n = i.Read(b, 0, b.Length)) > 0) { for (int k = 0; k < n; k++) b[k] ^= 0xA5; o.Write(b, 0, n); } }
  public static void Neutralize(string src, string dst) {
    using (var i = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
    using (var o = new FileStream(dst, FileMode.CreateNew, FileAccess.Write)) { o.Write(Magic, 0, Magic.Length); Xcopy(i, o); }
  }
  public static void Restore(string src, string dst) {
    using (var i = new FileStream(src, FileMode.Open, FileAccess.Read)) {
      byte[] m = new byte[8]; if (i.Read(m, 0, 8) != 8) throw new IOException("truncated quarantine file");
      for (int k = 0; k < 8; k++) if (m[k] != Magic[k]) throw new IOException("not a GSMQ quarantine file");
      using (var o = new FileStream(dst, FileMode.CreateNew, FileAccess.Write)) Xcopy(i, o);
    }
  }
}
'@
if (-not ('ExpiroRemoverCore' -as [type])) { Add-Type -TypeDefinition $core -Language CSharp }

# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Exts = @('.exe', '.scr', '.com', '.cpl', '.tmp', '.dll', '.ocx', '.sys', '.efi')
$win = $env:SystemRoot
$Protected = @("$win\System32", "$win\SysWOW64", "$win\WinSxS", "$win\servicing", "$win\SystemApps", "$env:ProgramFiles\WindowsApps", "$env:ProgramFiles\Windows Defender", "${env:ProgramFiles(x86)}\Windows Defender", "$env:ProgramData\Microsoft\Windows Defender") | ForEach-Object { $_.TrimEnd('\').ToLowerInvariant() + '\' }
$NormallyNotAuto = @('ssh-agent', 'perceptionsimulation', 'midisrv', 'refsdedupsvc', 'perfhost', 'comsysapp', 'sensordataservice', 'wmpnetworksvc', 'alg', 'msdtc')
$checked = @{}

function Test-Protected([string]$p) { $l = $p.ToLowerInvariant(); foreach ($x in $Protected) { if ($l.StartsWith($x)) { return $true } }; return $false }
function Get-Structure([string]$p) { if (-not $p) { return $null }; if ($checked.ContainsKey($p)) { return $checked[$p] }; $r = [ExpiroRemoverCore]::Check($p); $checked[$p] = $r; return $r }
function Get-ImagePath([string]$cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 0) { $c = $c.Substring(1, $e - 1) } }
  elseif ($c -match '^(.+?\.(exe|com|scr))(\s|$)') { $c = $matches[1] }
  if ($c -match '^\\SystemRoot\\') { $c = Join-Path $win $c.Substring(12) }
  elseif ($c -match '^system32\\') { $c = Join-Path $win $c }
  elseif ($c -match '^\\\?\?\\') { $c = $c.Substring(4) }
  return $c
}
function Log([string]$m) { $line = "{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $line; Add-Content -Encoding UTF8 -Path (Join-Path $ReportDir 'log.txt') -Value $line }
function Get-Sha256([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }

# ----------------------------------------------------------------------------------------------
# Undo
# ----------------------------------------------------------------------------------------------
if ($Mode -eq 'Undo') {
  if (-not $StateFile -or -not (Test-Path -LiteralPath $StateFile)) { throw 'Undo needs -StateFile <path to state.json from a Remediate run>' }
  if (-not $IsAdmin) { throw 'Undo must run as administrator.' }
  $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
  $ReportDir = Split-Path $StateFile
  Log "Expiro Remover $Version UNDO of $StateFile"
  foreach ($s in @($state.services)) {
    $mode = @{ Auto = 'auto'; Manual = 'demand'; Disabled = 'disabled'; Boot = 'boot'; System = 'system' }[$s.previousStartMode]
    if ($mode) { & sc.exe config $s.name start= $mode | Out-Null; Log "service $($s.name) start type restored to $mode (exit $LASTEXITCODE)" }
  }
  foreach ($q in @($state.quarantined)) {
    if (Test-Path -LiteralPath $q.original) { Log "skip restore, file exists: $($q.original)"; continue }
    try { New-Item -ItemType Directory -Force (Split-Path $q.original) | Out-Null; [ExpiroRemoverCore]::Restore($q.quarantine, $q.original); Log "restored $($q.original)" }
    catch { Log "FAILED restore $($q.original): $($_.Exception.Message)" }
  }
  Log 'Undo finished. Restored files are still infected; do not run them.'
  return
}

# ----------------------------------------------------------------------------------------------
# Scan
# ----------------------------------------------------------------------------------------------
if (-not $ReportDir) { $ReportDir = Join-Path $env:ProgramData ("ExpiroRemover\reports\{0:yyyyMMdd-HHmmss}-{1}" -f (Get-Date), $Mode.ToLower()) }
New-Item -ItemType Directory -Force $ReportDir | Out-Null
if (-not $Roots) { $Roots = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID + '\' } }
if ($Mode -eq 'Remediate' -and -not $IsAdmin) { throw 'Remediate must run as administrator (right-click PowerShell > Run as administrator).' }

Log "Expiro Remover $Version mode=$Mode elevated=$IsAdmin roots=$($Roots -join ',') report=$ReportDir"
$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($type, $path, $r, $extra) {
  $findings.Add([pscustomobject]@{ Type = $type; Verdict = $r.Verdict; Score = $r.Score; Indicators = $r.Indicators; Last = $r.Last; Path = $path; Detail = $extra; Protected = (Test-Protected $path) })
}

$stats = @{ files = 0; pe = 0; unreadableDirs = 0 }
if (-not $SkipFiles) {
  function Walk([string]$dir) {
    try { $files = [IO.Directory]::EnumerateFiles($dir) } catch { $script:stats.unreadableDirs++; return }
    try {
      foreach ($f in $files) {
        if ($Exts -notcontains [IO.Path]::GetExtension($f).ToLowerInvariant()) { continue }
        $script:stats.files++
        $r = Get-Structure $f
        if ($r.IsPE) { $script:stats.pe++ }
        if ($r.Verdict -eq 'infected' -or $r.Verdict -eq 'suspicious') { Add-Finding 'file' $f $r '' }
      }
    } catch { $script:stats.unreadableDirs++ }
    try { $dirs = [IO.Directory]::EnumerateDirectories($dir) } catch { $script:stats.unreadableDirs++; return }
    foreach ($d in $dirs) { try { if (([IO.File]::GetAttributes($d) -band [IO.FileAttributes]::ReparsePoint) -eq 0) { Walk $d } } catch { $script:stats.unreadableDirs++ } }
  }
  foreach ($root in $Roots) { Log "scanning $root"; Walk $root }
  Log ("files checked={0} pe={1} unreadable folders={2}" -f $stats.files, $stats.pe, $stats.unreadableDirs)
}

$procInfected = @()
if (-not $SkipProcesses) {
  $hidden = 0
  foreach ($p in Get-CimInstance Win32_Process) {
    if (-not $p.ExecutablePath) { if ($p.ProcessId -gt 4) { $hidden++ }; continue }
    $r = Get-Structure $p.ExecutablePath
    if ($r.Verdict -eq 'infected') { $procInfected += $p; Add-Finding 'process' $p.ExecutablePath $r "pid=$($p.ProcessId)" }
  }
  Log ("running processes with infected image: {0}; processes whose path is hidden from this account: {1}" -f $procInfected.Count, $hidden)
}

$svcInfected = @()
if (-not $SkipServices) {
  foreach ($s in Get-CimInstance Win32_Service) {
    $img = Get-ImagePath $s.PathName
    if ($img -and $img -match '\.(exe|com)$' -and $img -notmatch '\\svchost\.exe$' -and (Test-Path -LiteralPath $img)) {
      $r = Get-Structure $img
      if ($r.Verdict -eq 'infected') { $svcInfected += [pscustomobject]@{ Service = $s; Image = $img }; Add-Finding 'service' $img $r "service=$($s.Name) start=$($s.StartMode) state=$($s.State)" }
    }
    if ($NormallyNotAuto -contains $s.Name.ToLowerInvariant() -and $s.StartMode -eq 'Auto') {
      $findings.Add([pscustomobject]@{ Type = 'service-autostart'; Verdict = 'suspicious'; Score = 0; Indicators = ''; Last = ''; Path = $img; Detail = "service=$($s.Name) normally manual/disabled but set to Auto"; Protected = $true })
    }
  }
  Log ("services with infected executable: {0}" -f $svcInfected.Count)
}

# Autostart entries (Run keys, startup shortcuts, scheduled tasks)
$auto = @()
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
  $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
  if ($v) { $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $auto += [pscustomobject]@{ Source = "$k\$($_.Name)"; Image = (Get-ImagePath ([string]$_.Value)) } } }
}
$shell = New-Object -ComObject WScript.Shell
foreach ($d in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
  Get-ChildItem $d -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object { $auto += [pscustomobject]@{ Source = $_.FullName; Image = $shell.CreateShortcut($_.FullName).TargetPath } }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $t = $_; $t.Actions | Where-Object { $_.Execute } | ForEach-Object { $auto += [pscustomobject]@{ Source = "task:$($t.TaskPath)$($t.TaskName)"; Image = (Get-ImagePath $_.Execute) } } }
foreach ($a in $auto) { if ($a.Image -and (Test-Path -LiteralPath $a.Image -PathType Leaf)) { $r = Get-Structure $a.Image; if ($r.Verdict -eq 'infected') { Add-Finding 'autostart' $a.Image $r $a.Source } } }

# IOC: %APPDATA%\<16 hex>.bin (published Expiro stolen-data store)
$profiles = if ($IsAdmin) { Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming' } } else { @($env:APPDATA) }
foreach ($pr in $profiles) {
  Get-ChildItem $pr -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-f]{16}\.bin$' } | ForEach-Object {
    $findings.Add([pscustomobject]@{ Type = 'ioc'; Verdict = 'infected'; Score = 0; Indicators = 'stolen-data store'; Last = ''; Path = $_.FullName; Detail = "size=$($_.Length) created=$($_.CreationTime.ToString('yyyy-MM-dd HH:mm'))"; Protected = $false })
  }
}

$findings | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $ReportDir 'findings.csv')
$infectedFiles = @($findings | Where-Object { ($_.Type -eq 'file' -or $_.Type -eq 'ioc') -and $_.Verdict -eq 'infected' } | Sort-Object Path -Unique)
Log ("RESULT: infected files={0} (protected={1}), suspicious={2}, infected processes={3}, infected services={4}, IOC files={5}" -f `
  @($infectedFiles | Where-Object Type -eq 'file').Count, @($infectedFiles | Where-Object Protected).Count, @($findings | Where-Object { $_.Verdict -eq 'suspicious' }).Count,
  $procInfected.Count, $svcInfected.Count, @($findings | Where-Object Type -eq 'ioc').Count)

if ($Mode -eq 'Scan' -or $Mode -eq 'Verify') {
  Log "Report: $ReportDir"
  if ($infectedFiles.Count -gt 0 -or $procInfected.Count -gt 0 -or $svcInfected.Count -gt 0) { exit 1 } else { exit 0 }
}

# ----------------------------------------------------------------------------------------------
# Remediate
# ----------------------------------------------------------------------------------------------
if (-not $Force) {
  Write-Host ''
  Write-Host "About to: stop $($procInfected.Count) process(es), disable $($svcInfected.Count) service(s), quarantine $(@($infectedFiles | Where-Object { -not $_.Protected }).Count) file(s)."
  $ans = Read-Host 'Type YES to continue'
  if ($ans -ne 'YES') { Log 'cancelled by user'; exit 3 }
}
New-Item -ItemType Directory -Force $QuarantineDir | Out-Null
$state = [ordered]@{ tool = "Expiro Remover $Version"; created = (Get-Date).ToString('o'); computer = $env:COMPUTERNAME; services = @(); stoppedProcesses = @(); quarantined = @(); failed = @(); protectedLeftInPlace = @() }
$failures = 0

foreach ($p in $procInfected) {
  if ($p.ProcessId -eq $PID) { continue }
  try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $state.stoppedProcesses += [ordered]@{ pid = $p.ProcessId; image = $p.ExecutablePath }; Log "stopped process $($p.ProcessId) $($p.ExecutablePath)" }
  catch { $failures++; $state.failed += [ordered]@{ action = 'stop-process'; target = "$($p.ProcessId) $($p.ExecutablePath)"; error = $_.Exception.Message }; Log "FAILED to stop $($p.ProcessId): $($_.Exception.Message)" }
}

foreach ($x in $svcInfected) {
  $s = $x.Service
  $state.services += [ordered]@{ name = $s.Name; previousStartMode = $s.StartMode; image = $x.Image }
  & sc.exe stop $s.Name 2>&1 | Out-Null
  $out = & sc.exe config $s.Name start= disabled 2>&1
  if ($LASTEXITCODE -eq 0) { Log "service $($s.Name) stopped and disabled (was $($s.StartMode))" }
  else { $failures++; $state.failed += [ordered]@{ action = 'disable-service'; target = $s.Name; error = ($out -join ' ') }; Log "FAILED to disable $($s.Name): $out" }
}

foreach ($f in $infectedFiles) {
  if ($f.Protected) { $state.protectedLeftInPlace += $f.Path; Log "protected, left in place: $($f.Path)"; continue }
  try {
    $hash = Get-Sha256 $f.Path
    $size = (Get-Item -LiteralPath $f.Path -Force).Length
    $dst = Join-Path $QuarantineDir ("{0}_{1}.gsmq" -f $hash.Substring(0, 16), [IO.Path]::GetFileName($f.Path))
    if (-not (Test-Path -LiteralPath $dst)) { [ExpiroRemoverCore]::Neutralize($f.Path, $dst) }
    Remove-Item -LiteralPath $f.Path -Force -ErrorAction Stop
    $state.quarantined += [ordered]@{ original = $f.Path; quarantine = $dst; sha256 = $hash; size = $size; type = $f.Type }
    Log "quarantined $($f.Path)"
  } catch {
    $failures++; $state.failed += [ordered]@{ action = 'quarantine'; target = $f.Path; error = $_.Exception.Message }; Log "FAILED to quarantine $($f.Path): $($_.Exception.Message)"
  }
}

$statePath = Join-Path $ReportDir 'state.json'
($state | ConvertTo-Json -Depth 5) | Set-Content -Encoding UTF8 $statePath

# Reinstall / repair plan
$plan = New-Object System.Collections.Generic.List[string]
$plan.Add("Expiro Remover plan - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"); $plan.Add('')
$plan.Add('1. Reinstall these applications from the vendor (their infected files were quarantined):')
$apps = $state.quarantined | ForEach-Object { $o = $_.original
  if ($o -match '^(.:\\Program Files( \(x86\))?\\[^\\]+)') { $matches[1] } elseif ($o -match '^(.:\\Users\\[^\\]+\\AppData\\Local\\(Programs\\)?[^\\]+)') { $matches[1] } else { Split-Path $o } } | Sort-Object -Unique
foreach ($a in $apps) { $plan.Add("   - $a") }
$plan.Add(''); $plan.Add('2. Protected Windows files left in place (their services were disabled if applicable):')
foreach ($p in $state.protectedLeftInPlace) { $plan.Add("   - $p") }
if ($state.protectedLeftInPlace.Count) {
  $plan.Add('   Repair: DISM /Online /Cleanup-Image /RestoreHealth ; sfc /scannow ; reinstall vendor drivers (DriverStore) ;')
  $plan.Add('   if services were deleted by another antivirus, run an in-place upgrade from verified Windows media.')
}
$plan.Add(''); $plan.Add('3. Archives (.zip/.rar/.7z/.tar/.iso) are not opened by this tool. Scan them with Microsoft Defender or delete them; never extract and run their executables.')
$plan.Add(''); $plan.Add('4. If an IOC stolen-data file was found, change browser/email/GitHub passwords and tokens from a clean device.')
$plan.Add('4. Re-run: .\Expiro-Remover.ps1 -Mode Verify   (and a Microsoft Defender full + offline scan).')
$plan.Add("5. Undo (restores files, still infected): .\Expiro-Remover.ps1 -Mode Undo -StateFile `"$statePath`"")
$plan | Set-Content -Encoding UTF8 (Join-Path $ReportDir 'plan.txt')
$plan | ForEach-Object { Write-Host $_ }
Log ("Remediate finished: stopped={0} servicesDisabled={1} quarantined={2} protected={3} failures={4} state={5}" -f $state.stoppedProcesses.Count, $state.services.Count, $state.quarantined.Count, $state.protectedLeftInPlace.Count, $failures, $statePath)
New-Item -ItemType File -Force (Join-Path $ReportDir 'DONE') | Out-Null
if ($failures) { exit 2 } else { exit 0 }
