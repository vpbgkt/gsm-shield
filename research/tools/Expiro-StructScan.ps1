<#
.SYNOPSIS
  Read-only structural Expiro scanner (PowerShell port of engine/expiro-structural.js).

.DESCRIPTION
  Reads PE headers, 32 bytes at the entry point and a bounded window of the entry
  section. Never executes, modifies, moves or deletes anything.
  Rules (derived from real infected files, see research/EXPIRO_TECHNICAL_REFERENCE.md):
    S1 last section executable but named like a data section (.reloc/.rsrc/.debug/.symtab/...)  +50
    S1b last section RWX with another name                                                     +15
    S2 .reloc section present but base-relocation directory zero                               +25
    S3 DYNAMIC_BASE (ASLR) cleared while a .reloc section exists                               +10
    S4 CALL/JMP rel32 in the first 32 bytes at the entry point targets the last section       +40
    S5 last section RWX and >= 512 KB                                                          +10
    S6 1..8 rel32 branches in the entry section target the last section (only if no S4)       +15
  infected = score >= 75 and (S1 or S4); suspicious = score >= 40.
  Run elevated to cover folders a standard user cannot read.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Expiro-StructScan.ps1 -Roots C:\,D:\ -OutCsv .\scan.csv
#>
param(
  [string[]]$Roots = @('C:\'),
  [string]$OutCsv = (Join-Path $PWD ("expiro-structscan-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date))),
  [switch]$AllFiles
)

$src = @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
public static class StructScanFs {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct WIN32_FIND_DATAW { public uint dwFileAttributes; public long ftCreation, ftAccess, ftWrite; public uint nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName; }
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstFileW(string name, out WIN32_FIND_DATAW data);
  [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);
  // Skip only junctions/mount points and symlinks; scan OneDrive cloud placeholders and other reparse folders.
  public static bool IsLinkLike(string path) {
    WIN32_FIND_DATAW d; IntPtr h = FindFirstFileW(path.TrimEnd('\\'), out d);
    if (h == new IntPtr(-1)) return false; FindClose(h);
    if ((d.dwFileAttributes & 0x400) == 0) return false;
    return d.dwReserved0 == 0xA0000003u || d.dwReserved0 == 0xA000000Cu;
  }
}
public class StructResult { public string Path; public bool IsPE; public int Score; public string Verdict; public string Last; public uint LastRaw; public string Indicators; public bool Is64; public string Error; }
public static class ExpiroStruct {
  static readonly HashSet<string> Data = new HashSet<string>(new[]{".reloc",".rsrc",".debug",".data",".rdata",".pdata",".xdata",".idata",".edata",".tls",".bss",".didat","_RDATA",".fptable",".gfids",".00cfg",".CRT",".buildid",".symtab"});
  static bool IsData(string n){ return Data.Contains(n) || Regex.IsMatch(n, @"^/\d+$") || Regex.IsMatch(n, @"^\.z?debug"); }
  public static StructResult Check(string path) {
    var r = new StructResult(); r.Path = path; r.Verdict = "not-pe";
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
}
'@
if (-not ('ExpiroStruct' -as [type])) { Add-Type -TypeDefinition $src -Language CSharp }

$exts = @('.exe','.dll','.scr','.com','.cpl','.ocx','.sys','.tmp','.efi')
$skipNames = @('pagefile.sys','swapfile.sys','hiberfil.sys','dumpstack.log.tmp','dumpstack.log')
$stats = @{ files = 0; pe = 0; clean = 0; suspicious = 0; infected = 0; error = 0; dirErrors = 0 }
$rows = New-Object System.Collections.Generic.List[object]
function Walk([string]$dir) {
  try { $files = [IO.Directory]::EnumerateFiles($dir) } catch { $script:stats.dirErrors++; return }
  try {
    foreach ($f in $files) {
      if (-not $AllFiles -and $exts -notcontains [IO.Path]::GetExtension($f).ToLowerInvariant()) { continue }
      if ($skipNames -contains [IO.Path]::GetFileName($f).ToLowerInvariant()) { continue }
      $script:stats.files++
      $r = [ExpiroStruct]::Check($f)
      if (-not $r.IsPE) {
        if ($r.Verdict -eq 'error') {
          $script:stats.error++
          $why = if ($r.Error -match 'virus|unwanted') { 'blocked by antivirus (already detected)' } else { $r.Error }
          $rows.Add([pscustomobject]@{ Verdict = 'unreadable'; Score = 0; Last = ''; LastRaw = ''; Indicators = $why; Path = $f })
        }
        continue
      }
      $script:stats.pe++; $script:stats[$r.Verdict]++
      if ($r.Verdict -ne 'clean') { $rows.Add([pscustomobject]@{ Verdict = $r.Verdict; Score = $r.Score; Last = $r.Last; LastRaw = ('0x{0:X}' -f $r.LastRaw); Indicators = $r.Indicators; Path = $f }) }
    }
  } catch { $script:stats.dirErrors++ }
  try { $dirs = [IO.Directory]::EnumerateDirectories($dir) } catch { $script:stats.dirErrors++; return }
  foreach ($d in $dirs) { try { if (-not [StructScanFs]::IsLinkLike($d)) { Walk $d } } catch { $script:stats.dirErrors++ } }
}
$t0 = Get-Date
foreach ($root in $Roots) { if (Test-Path -LiteralPath $root -PathType Leaf) { $r = [ExpiroStruct]::Check($root); $rows.Add([pscustomobject]@{ Verdict = $r.Verdict; Score = $r.Score; Last = $r.Last; LastRaw = ('0x{0:X}' -f $r.LastRaw); Indicators = $r.Indicators; Path = $root }) } else { Walk $root } }
$rows | Sort-Object Verdict, Path | Export-Csv -NoTypeInformation -Encoding UTF8 $OutCsv
$rows | Sort-Object Verdict, Path | Format-Table Verdict, Score, Last, LastRaw, Indicators, Path -AutoSize -Wrap | Out-String -Width 400
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"Elapsed {0:N0}s | elevated={1} | files={2} pe={3} clean={4} suspicious={5} infected={6} errors={7} unreadableDirs={8}" -f ((Get-Date) - $t0).TotalSeconds, $admin, $stats.files, $stats.pe, $stats.clean, $stats.suspicious, $stats.infected, $stats.error, $stats.dirErrors
"CSV: $OutCsv"
if (-not $admin -and $stats.dirErrors -gt 0) { "NOTE: run elevated to scan the $($stats.dirErrors) folder(s) this account cannot read." }
