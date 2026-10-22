# Expiro — technical reference (validated 2026-10-22)

This replaces the speculative model in `EXPIRO_ANALYSIS.md` (".expiro section", "40–150 KB overlay", "entry point moved"). None of those match real samples. Statements are tagged **[published]** (source listed in §8), **[observed]** (measured on this machine, evidence in `logs/2026-10-22/`), or **[inferred]**.

## 1. What Expiro is

- A polymorphic **file infector** (virus) for 32- and 64-bit Windows PE executables, active since at least 2013 **[published: ESET 2013, Quick Heal 2023]**.
- It appends its body to the **last section** of a host executable and redirects execution to it by **patching a CALL** in the code section, so the entry-point RVA in the header does not change ("entry-point obscuring") **[published: Quick Heal/Seqrite 2023; observed]**.
- The body is encrypted; the decrypted code contains a compressed buffer that is again decrypted with ChaCha and custom algorithms. The original bytes it overwrote are stored encrypted in multiple layers **[published: Quick Heal/Seqrite 2023]**.
- Payload: browser extensions/form grabbing, credential and certificate theft (FileZilla, IE/Outlook, certificate store with private keys), backdoor commands, plugin download, proxy/port-forwarding **[published: ESET 2013]**; stolen data stored encrypted in `%AppData%\<random_hex>.bin` **[published: Seqrite 2023; observed: `1c0b060669175429.bin`]**.
- Defender detection names seen here: `Virus:Win32/Expiro.HNW!MTB`, `.EK!MTB`, `.EB!MTB`, `Virus:Win64/Expiro.EM!MTB`, `.DD!MTB` (`!MTB` = machine-learning-based family detection). The Win32/Win64 prefix and the suffix do **not** map one-to-one to body layouts: the 64-bit `ssh-agent.exe` was named Win32/Expiro.HNW, and Win64/Expiro.EM was assigned to files with two different body sizes **[observed]**.

## 2. Infection mechanics observed on real files

### 2.1 Exact clean/infected pairs [observed]

| Host | Clean | Infected |
|---|---|---|
| `clamscan.exe` (official ClamAV 1.5.4 vs repo copy) | 292,352 B; last section `.reloc` read-only; relocation dir set; DllCharacteristics with DYNAMIC_BASE | 1,577,984 B (+1,285,632); `.reloc` raw 0x13B000, **RWX**; relocation dir **0**; DYNAMIC_BASE **cleared**; one byte changed in `.text` (patched call); relocation table bytes **zeroed** in place; PE checksum recomputed |
| `ssh-agent.exe` (WinSxS 10.0.26100.1 vs System32 10.0.26100.9444) | 560,128 B, `.reloc` raw 0xA00 R, signed | 1,969,664 B, `.reloc` raw 0x15A000 RWX, entry stub `48 83 EC 28 E8 <rel32>`: the CALL now targets `.reloc + 0x159000` (0x1000 before section end); security directory zero (signature gone) |
| `esbuild.exe` 0.21.5 (npm tarball vs installed) | 9,913,856 B, `.symtab` raw 0x200 R, DllCharacteristics 0x8160 | 10,494,976 B, `.symtab` raw 0x8E000 RWX, DllCharacteristics 0x8120, reloc dir 0 |
| `claude.exe` 2.1.308 (VS Code extension copy vs Claude desktop copy) | `.bun` R, relocs intact | `.bun` +0x8DA00, RWX; entry CALL → `.bun + (raw − 0x1000)` |

### 2.2 Structural fingerprint (used by `engine/expiro-structural.js`)

| ID | Indicator | Weight | Seen on |
|---|---|---|---|
| S1 | Last section **executable** although named as data (`.reloc`, `.rsrc`, `.debug`, `.symtab`, `/4`-style debug, ...) | 50 | all MSVC/MinGW/Go hosts |
| S1b | Last section RWX with another name (e.g. `.bun`) | 15 | Bun-compiled hosts |
| S2 | `.reloc` section present but base-relocation data directory zero | 25 | all |
| S3 | DYNAMIC_BASE (ASLR) cleared while `.reloc` exists | 10 | all |
| S4 | CALL/JMP rel32 in the first 32 bytes of the entry point lands in the last section | 40 | MSVC-style entry stubs |
| S5 | Last section RWX and ≥ 512 KB | 10 | all |
| S6 | 1–8 rel32 branches in the entry section target the last section (only when S4 absent) | 15 | MinGW (Git) hosts |

Verdict: **infected** if score ≥ 75 **and** S1 or S4; **suspicious** if ≥ 40. Measured on 25,632 PE files on C:/D:: 93 infected (all corroborated), 0 suspicious after adding `.symtab`, 0 false positives found.

### 2.3 Body layout families (raw size of the infected last section) [observed]

| Family | Raw size | Entropy | Notes |
|---|---|---|---|
| A | 0x15A000–0x15C000 (~1.35 MB) | ~4.2 | Most hosts (ssh-agent, Intel PIE, Brave, Git `cmd`/`usr`, canaries) |
| B | ~0x8E000 (~570 KB) | ~7.9 | Git `ucrt64`, Brave installer, esbuild, Claude Code |
| C | 0x13A000–0x13B000 (~1.23 MB) | ~4.5 | ClamAV EXEs committed on 19 Oct |
| D | appended to `.rsrc` (0x9F000/0xBD000 incl. original) | 7.7 | Inno Setup uninstallers, git-lfs |

Families are informational; detection does not depend on them.

## 3. Propagation and persistence

| Mechanism | Detail | Source |
|---|---|---|
| Service infection | Enumerates services, infects the service executable, sets disabled/manual services to **automatic**; skips/stops security services (wscsvc, WinDefend, MsMpSvc, NisSrv) | [published: Virus Bulletin 2014, Allievi 2013, Stop Malvertising, ESET 2013, Trend Micro 2020]; **[observed]** event 7040 for ssh-agent (disabled→auto), COMSysApp, PerfHost, MidiSrv, PerceptionSimulation, SensorDataService, ReFsDedupSvc, WMPNetworkSvc, RstMwService, PIEServiceNew |
| Shortcut targets | Follows `.lnk` files in Start Menu/Desktop and infects their targets | [published: Stop Malvertising, F-Secure, Trend Micro]; **[observed]** Defender flagged `Git Bash.lnk`/`Brave.lnk` as startup resources |
| Drive walk | Infects `.exe` on local, removable and network drives; writes via a temp `.vir`/`.tmp` file then overwrites the host | [published: ESET 2013, Trend Micro, Seqrite] |
| Timestamps | Restores the original LastWriteTime after infecting | **[observed]** Intel_PIE_Service.exe kept 2025-07-23; ClamAV files kept 2026-08-06 |
| User-context execution | When an infected program runs as a normal user, it infects user-writable `.exe` files within seconds (repo, `%TEMP%`, `node_modules`, `%LOCALAPPDATA%` app folders) | **[observed]** |
| Signed binaries | Signature destroyed (security directory zeroed) | [published: ESET 2013]; **[observed]** |
| Non-EXE files | DLLs were not infected (24 ClamAV DLLs untouched next to infected EXEs) | **[observed]** |

### Reinfection pathways on this machine [observed unless marked]

1. **Install media**: infected setup EXEs and a third-party driver package on the Windows USB.
2. **Auto-start infected services** (SYSTEM): ssh-agent, Intel PIE.
3. **Developer tools that run Git constantly**: VS Code SCM, Claude Code, GitHub Desktop → infected Git.
4. **Application self-updaters**: Brave Update, Edge Update, Claude desktop's Claude Code download (all infected after download).
5. **The antivirus repository/installer**: infected ClamAV EXEs in git and in every installer built since 19 Oct.
6. **Cloud sync**: OneDrive Desktop restored infected GSM tools.
7. **Archives and backups on D:**: `update136.tar`; executables in backup folders (currently clean, untrusted).
8. **Quarantine restores based on a blind detector** [inferred, H3].

## 4. Why in-place disinfection is not offered

Recovering the original bytes requires decrypting the virus body (patched CALL target, zeroed relocation table). Quick Heal/Seqrite describe this as difficult and note that bad repairs corrupt files; McAfee describes variants that shrink and encrypt the relocation table specifically to break naive repair. Flag-flipping, entry-point "restoration" or overlay truncation (the removed v2 "surgical" repair) leaves the virus reachable or breaks the host. Supported outcomes are therefore: **replace from a trusted source** (vendor reinstall, SFC/DISM for Windows, verified same-build copy) or **quarantine**.

## 5. Microsoft Defender data

- `Get-MpThreatDetection` resources use prefixes `file:_`, `process:_pid:N,ProcessStart:<FILETIME>`, `service:_`, `regkey:_`, `containerfile:_`, `startup:_`, `taskscheduler:_`.
- ThreatStatusID: 1 Detected, 2 Cleaned, 3 Quarantined, 4 Removed, 5 Allowed, 6 Blocked, 103 RemoveFailed, 104 AllowFailed, 107 BlockedFailed. **102** is "QuarantineFailed" in the WMI docs but "CleanFailed" in `MpClient.h`; **106** is "Abandoned" in `MpClient.h` (sources disagree — treat both as failure).
- Error `0x8007007F` = ERROR_PROC_NOT_FOUND (most failed remediations here).
- Defender **removes service registrations** when it removes an infected service binary, which can leave Windows without COM+ (dllhost), licensing (sppsvc) etc.

## 6. Detection logic decisions for GSM Shield

- Primary: structural fingerprint (§2.2). Secondary: legacy v2 heuristics (kept, cannot veto).
- Integrity: bundled executables must match a SHA-256 manifest before launch.
- Persistence: service binaries + start-type escalations (baseline) are checked.
- Not possible without a kernel driver: blocking execution before it happens. GSM Shield detects after write and quarantines; prevention must come from removing infected binaries and from Windows controls (Defender with Tamper Protection, Smart App Control/WDAC).

## 7. Open questions

- Exact infection step during Windows Setup (H1/H1b).
- Whether the body has a stable byte signature usable for a ClamAV/YARA rule (body not decrypted).
- C2 domains used by this build (no network capture was taken).

## 8. Sources

- Quick Heal Security Labs, "Expiro: Old Virus Poses a New Challenge" (24 Feb 2023) — https://www.quickheal.com/blogs/expiro-old-virus-poses-a-new-challenge/
- Seqrite Labs, "Expiro: Old Virus Resurfaces to Cast New Challenge" (27 Feb 2023) — https://www.seqrite.com/blog/expiro-old-virus-resurfaces-to-cast-new-challenge/
- ESET WeLiveSecurity, "Versatile and infectious: Win64/Expiro is a cross-platform file infector" (30 Jul 2013) — https://www.welivesecurity.com/2013/07/30/versatile-and-infectious-win64expiro-is-a-cross-platform-file-infector/
- Stop Malvertising, "Abuse Teams targeted by Expiro – Analysis" — https://stopmalvertising.com/malware-reports/abuse-teams-targeted-by-expiro-analysis.html
- Trend Micro, Virus.Win64.EXPIRO.AA (3 Sep 2020) — https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/virus.win64.expiro.aa
- Virus Bulletin, "Not Expir-ed yet" (Mar 2014; only the search summary was accessible, page returned 403) — https://www.virusbulletin.com/virusbulletin/2014/03/not-expir-ed-yet
- A. Allievi, "Expiro: Anatomy of a new 64 bit file infector" (2013; PDF could not be rendered, search summary only) — https://www.andrea-allievi.com/files/Expiro_Analysis_2013.pdf
- McAfee Labs, "Expiro Infects, Encrypts Files to Complicate Repair" (page timed out; search summary only) — https://www.mcafee.com/blogs/other-blogs/mcafee-labs/expiro-infects-encrypts-files-to-complicate-repair/
- Gridinsoft, "Virus:Win32/Expiro & Win64/Expiro.DD!MTB Removal" (updated 15 Sep 2026; generic advice) — https://blog.gridinsoft.com/virus-win32-expiro/
- Microsoft, MSFT_MpThreatDetection class — https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection
- log2timeline/plaso issue #5344 (MPTHREAT_STATUS values from MpClient.h) — https://github.com/log2timeline/plaso/issues/5344
- Cisco Talos, ClamAV 1.5.4 release (asset digests) — https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4
