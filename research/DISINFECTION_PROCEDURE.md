# Expiro disinfection and verification procedure

Applies to the 2026-10-22 incident ([EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md)). Steps are ordered so that **evidence is collected before anything is deleted** and so that **no infected program runs again**.

Markers: **[ADMIN]** needs an elevated prompt · **[REBOOT]** restarts the PC · **[MANUAL]** needs you · **[CLEAN PC]** must be done on a different, known-clean computer or phone.

---

## 0. Ground rules until the machine is verified clean

- Do **not** run, install or update anything on this PC. Every program you start can be infected and every infected program spreads the virus.
- Do **not** open Git, Git Bash, GitHub Desktop, VS Code, Claude desktop, Brave, or anything from D:, OneDrive or USB drives.
- Do **not** reboot before step 1 is done (infected services auto-start as SYSTEM).
- Do **not** use this PC to log in to accounts whose passwords you will change later.
- Never rename quarantine/sample files back to `.exe`.

## 1. Stop the active spread (now, no reboot) — [MANUAL] [ADMIN]

1. Close VS Code, Claude desktop, GitHub Desktop, any terminal, Copilot/agents, browsers.
2. Elevated PowerShell (these only change start types; they are reversible):

```powershell
sc.exe stop ssh-agent
sc.exe config ssh-agent start= disabled
sc.exe stop PIEServiceNew
sc.exe config PIEServiceNew start= disabled
Get-CimInstance Win32_Service -Filter "Name='ssh-agent' or Name='PIEServiceNew'" | Format-Table Name,State,StartMode
```

3. Turn Defender real-time protection and Tamper Protection back **on** (Windows Security → Virus & threat protection → Manage settings). Defender may still fail to clean, but it blocks execution of known-infected files.

## 2. Collect evidence — [ADMIN] (optional but recommended)

```powershell
cd C:\Users\vpbgk\gsm-shield\research\tools
powershell -ExecutionPolicy Bypass -File .\Collect-ExpiroEvidence.ps1 -OutDir D:\expiro-evidence-admin -Sweep -SweepRoots C:\,D:\
```

This is read-only. It adds what the non-elevated investigation could not see: Defender quarantine list, protected folders, other profiles, old recycle bins. Keep the folder; it is the "before" picture. Also copy `C:\Windows\Panther\setupact.log` (Windows Setup log) to the evidence folder to test hypothesis H1.

## 3. Choose the remediation path

| | Option A — clean reinstall (**recommended**) | Option B — repair in place |
|---|---|---|
| Removes unknown infected files | Yes (system disk wiped) | No; relies on scans |
| Fixes Defender's deletions (dllhost, sppsvc, services) | Yes | Needs DISM + SFC + in-place upgrade |
| Infected WinSxS component (ssh-agent 9444) | Gone | Needs DISM from Windows Update / verified ISO |
| Effort | ~2–3 h | ~2–4 h, more uncertainty |

Reasons for A: system binaries and service registrations were deleted, the component store copy of a system file is infected, credential theft is likely, and an unknown number of files sit in places a scan may miss. The previous reinstall failed **only** because infected media and data were reused; steps 4.1–4.3 prevent that.

## 4. Option A — clean reinstall

### 4.1 Prepare clean media — [CLEAN PC] [MANUAL]
1. On a clean PC, download the Windows 11 ISO from microsoft.com/software-download and verify its SHA-256 against Microsoft's published value.
2. Create the USB with the Media Creation Tool or Rufus **on the clean PC**. Use a different USB stick or re-format the old one there.
3. If setup needs an Intel RST/VMD storage driver, download it from ASUS/Intel **on the clean PC**, check `Get-AuthenticodeSignature` = Valid for every `.exe/.sys` in it, and copy only the `.inf/.sys/.cat` files needed for "Load driver". Do **not** reuse `RST_V19.1.0.1001_PV` from the old USB.
4. Do not plug the old install USB (E:) into any computer except to re-format it on a clean, protected PC.

### 4.2 Decide what survives — [MANUAL]
- **Keep:** documents, photos, videos, source code text files. Expiro infects executables only (no DLL/data file infection was observed).
- **Delete or treat as infected:** every `.exe/.scr/.com/.tmp` you would copy from D:, OneDrive or backups; `D:\Trash\update136.tar`; `D:\Trash\21octResetBackup\desktop env\USB Redirector ... [Full Cracked]`; `bin\`/`Debug\` build outputs; installers you did not just download from the vendor.
- **D: is internal:** it will remain after setup. Leave it untouched until step 4.4.

### 4.3 Install — [MANUAL] [REBOOT]
1. Boot from the new USB. Delete and recreate **only** the Windows partitions of the system disk. Double-check the disk/partition sizes so D: is not deleted by mistake.
2. Finish setup with the network disconnected if possible. Set the correct time zone and clock (the old setup ran ~12.5 h fast).
3. Connect to the network, run Windows Update until no updates remain (this also updates the Defender engine/platform), confirm **Real-time protection** and **Tamper Protection** are On.
4. Do not install GSM Shield from any installer built since 19 Oct 2026 (they contain infected ClamAV).

### 4.4 Clean D: before using it — [MANUAL]
1. Windows Security → Scan options → **Custom scan** → D:\, then a **Full scan**, then **Microsoft Defender Offline scan** [REBOOT].
2. Structural scan (no Node needed): `powershell -ExecutionPolicy Bypass -File <path>\Expiro-StructScan.ps1 -Roots D:\ -OutCsv D:\d-scan.csv` (copy the script from GitHub web or re-type it; do not copy executables). Expect `infected=0`.
3. Delete `D:\Trash\update136.tar` and the old `$RECYCLE.BIN\S-1-5-21-3007975530-...` folders (empty the recycle bin as admin).

### 4.5 OneDrive — [CLEAN PC] [MANUAL]
Before signing in to OneDrive on the new install, open onedrive.live.com on a clean device and delete `Desktop\workspace-master\workspace-master\gsmmeta-tool-rental\falcon_extracted\adb\*.exe`, `...\Tecno Infinix Itel Fastboot Info Read.exe` and any other `.exe` you do not need; empty the OneDrive recycle bin. Check other PCs that sync the same OneDrive.

### 4.6 Reinstall applications — [MANUAL]
Only from vendor sites, newest versions, one at a time, with Defender on. Git: git-scm.com; VS Code; Node.js; Claude desktop; Brave. After each install run the structural scan on its folder.

## 5. Option B — repair in place (only if A is impossible)

1. Step 1 and 2 above.
2. [ADMIN] Uninstall **Git for Windows**, **GitHub Desktop**, **Brave**, and delete `%LOCALAPPDATA%\Claude-Data\claude_pzs8sxrjxfjjc\claude-code` (the desktop app re-downloads it). Delete `%TEMP%\is-B4N3IB7VVW-uninstall.tmp`.
3. [ADMIN] Repair Windows components (needs internet):
```powershell
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
Get-AuthenticodeSignature C:\Windows\System32\OpenSSH\ssh-agent.exe   # expect Valid
```
   If DISM cannot repair, use `/Source:` pointing at `install.wim` of a verified ISO.
4. [ADMIN] [REBOOT] Restore deleted services and COM+/licensing: mount the verified ISO and run `setup.exe` → "Keep personal files and apps" (in-place upgrade). Then `slmgr /dlv` to confirm licensing works.
5. Intel PIE: reinstall the ASUS/Intel driver package from the vendor, or leave the service disabled.
6. [ADMIN] Full scan + Defender Offline scan + `Expiro-StructScan.ps1 -Roots C:\,D:\` elevated.
7. GSM Shield repo: delete `node_modules`, restore `assets/clamav/*.exe` from the official ClamAV 1.5.4 zip, run `node bin/gsmshield.js verify-binaries` and `npm test` (see §7).

## 6. Verification criteria (required before calling the system clean)

All of these must hold. Record results in a new file under `research/logs/`.

| # | Check | Pass condition |
|---|---|---|
| V1 | `Expiro-StructScan.ps1 -Roots C:\,D:\` **elevated** | `infected=0`, `suspicious=0` (or each suspicious file explained), unreadable folders = 0 or explained |
| V2 | Defender (updated engine) Full scan **and** Defender Offline scan | no detections |
| V3 | `Get-MpThreatDetection` | no detection newer than the remediation date |
| V4 | `node bin/gsmshield.js services` (or Collect-ExpiroEvidence `services.csv`) | every service executable `Valid`; ssh-agent `Disabled`; no `critical/high` findings |
| V5 | `sfc /scannow` and `DISM /Online /Cleanup-Image /ScanHealth` | no integrity violations / no corruption |
| V6 | `%APPDATA%\<16 hex>.bin`, event 7040 "to auto start" for non-standard services | none new |
| V7 | 72 hours of normal use with Defender real-time + Tamper Protection on | no new Expiro detections; V1 still 0 |
| V8 (optional) | Second-opinion on-demand scanner (e.g. ESET Online Scanner, Kaspersky Virus Removal Tool) | clean |

## 7. GSM Shield repository and distribution — [MANUAL] (outward-facing, your decision)

1. On the clean machine run `powershell -ExecutionPolicy Bypass -File scripts\restore-clamav-binaries.ps1` (downloads the official ClamAV 1.5.4 zip, checks the release digest, writes the five executables, re-checks them after 10 s), then `node bin/gsmshield.js verify-binaries` → all OK. Commit and push the fix together with the engine changes.
2. `origin/main` currently serves infected ClamAV executables (commits `88d29a0`, `3c6179c`). Consider rewriting history or at least warning anyone who cloned or installed builds made since 19 Oct 2026; GitHub may also flag the repo.
3. Withdraw any `GSMShieldAV-Setup.exe` built since 19 Oct 2026.

## 8. Credentials — [CLEAN PC] [MANUAL]

From a clean device, rotate: passwords saved in browsers on this PC (Edge, Brave, Chrome), GitHub tokens and SSH keys, any `.env` secrets (e.g. `D:\Trash\21octResetBackup\**\.env*`, `admin-key.txt`), API keys, email, banking. Revoke certificates whose private keys were in the Windows certificate store. Expiro is documented to steal browser credentials, FTP credentials and certificates (ESET 2013, Seqrite 2023), and a matching stolen-data file exists here.
