# After-reset recovery checklist (Expiro)

**Read this first after a clean Windows reinstall.** It is self-contained: you can get it by cloning
this repo with a freshly installed Git, or by downloading the repo as a ZIP from GitHub (green "Code"
button -> Download ZIP) which needs no tools at all. Companion detail:
[DISINFECTION_PROCEDURE.md](DISINFECTION_PROCEDURE.md), [EXPIRO_REINFECTION_SOURCES.md](EXPIRO_REINFECTION_SOURCES.md),
[EXPIRO_TECHNICAL_REFERENCE.md](EXPIRO_TECHNICAL_REFERENCE.md).

## Should you reinstall? Yes, if you do these first
The last reinstall got reinfected because the **install USB and OneDrive copies were reused**. A
reinstall only works if every reservoir is clean before you boot the fresh system. Do PART A before
wiping, PART C after.

---

## PART A — before you wipe C: (do on a KNOWN-CLEAN second PC where possible)

1. **Make new install media on a clean PC.** Download the Windows 11 ISO from
   `https://www.microsoft.com/software-download/windows11` and build the USB with the Media Creation
   Tool or Rufus on that clean PC. **Do not reuse the old install USB (E:).** If setup needs a storage
   driver, download it from ASUS/Intel on the clean PC and verify every `.exe/.sys` is signed before
   copying only the `.inf/.sys/.cat` files.
2. **Clean OneDrive in the cloud** at `https://onedrive.live.com` from a clean device: delete the
   infected GSM tool copies under `Desktop\workspace\gsmmeta-tool-rental\...` and
   `Desktop\workspace-master\...` (adb.exe, fastboot.exe, frp.exe, FalconFRPTool, the Tecno tool,
   `nodemon\bin\windows-kill.exe`), then empty the OneDrive recycle bin. Do this on every device that
   syncs this OneDrive.
3. **Back up DATA ONLY**, never executables. Safe: documents, photos, source text, `.env`/config text.
   Do NOT copy `.exe .dll .scr .com .sys .msi` or `node_modules`, `bin/`, `Debug/` folders, installers,
   or `D:\Trash\update136.tar`. If unsure, scan the backup first (PART C step 4 works on any folder).
4. **Rotate credentials from the clean device**: browser-saved passwords, GitHub tokens/SSH keys,
   email, banking, any `.env` secrets. A stolen-data file was present on the infected machine.
5. **D: drive** stays attached through setup; leave it untouched until PART C. Plan to delete
   `D:\Trash\update136.tar` and the old `$RECYCLE.BIN` folders afterward.

## PART B — install
1. Boot the new USB. Delete and recreate **only** the Windows partitions of the system disk; confirm
   sizes so D: is not touched.
2. Set the correct date/time/zone (the earlier setup ran with a wrong clock).
3. Run Windows Update until no updates remain. Confirm **Real-time protection** and **Tamper
   Protection** are ON in Windows Security.
4. Install apps only from vendor sites (newest versions), one at a time, with Defender on.

## PART C — verify the fresh system (no third-party tools needed)
Get this repo (ZIP or clone). Open **PowerShell as Administrator** in the repo folder.

1. **Scan both drives** with the dependency-free scanner:
   ```powershell
   powershell -ExecutionPolicy Bypass -File research\tools\Expiro-StructScan.ps1 -Roots C:\,D:\ -OutCsv %USERPROFILE%\Desktop\scan.csv
   ```
   Expect the summary to end with `infected=0 suspicious=0`. Any infected row names the file to remove.
2. **Collect a full evidence snapshot** (services, autostart, Defender history, IOCs):
   ```powershell
   powershell -ExecutionPolicy Bypass -File research\tools\Collect-ExpiroEvidence.ps1 -OutDir %USERPROFILE%\Desktop\evidence -Sweep -SweepRoots C:\,D:\
   ```
   Check `services.csv` (no non-Valid service binaries), `scm_events.csv` (no "changed ... to auto
   start" for odd services), `iocs.csv` (empty).
3. **Run a Microsoft Defender full scan, then an Offline scan** (Windows Security > Scan options).
4. **Before reconnecting D: data or restoring any backup**, scan that folder:
   ```powershell
   powershell -ExecutionPolicy Bypass -File research\tools\Expiro-StructScan.ps1 -Roots D:\ -OutCsv %USERPROFILE%\Desktop\d-scan.csv
   ```
5. Delete `D:\Trash\update136.tar` and old recycle-bin folders.

The system is "clean" only when PART C step 1 shows `infected=0`, Defender full + offline scans are
clean, services are all validly signed, and no new Expiro detection appears over a few days of use.

---

## Verified clean download sources (check the hash before running)
Verify a download in PowerShell: `Get-FileHash <file> -Algorithm SHA256`. It must equal the value below
(compare case-insensitively).

| Item | URL | SHA-256 |
|---|---|---|
| Git for Windows 2.56.0.2 (64-bit) | https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-64-bit.exe | `52188f917b378f00c70ec136bcf090005f30d44fbc4eba0bce759cc6592d60f6` (also: signature "Johannes Schindelin" must be Valid) |
| ClamAV 1.5.4 (win x64 zip) | https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip | `0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395` |
| Node.js | https://nodejs.org/en/download (optional; only for the JS tools) | verify against the `SHASUMS256.txt` on the same download page |
| Windows 11 ISO | https://www.microsoft.com/software-download/windows11 | verify against Microsoft's published hash for your exact build |

- Restore this project's bundled ClamAV from the verified zip any time with
  `powershell -ExecutionPolicy Bypass -File scripts\restore-clamav-binaries.ps1`, then
  `node bin\gsmshield.js verify-binaries`.
- The three GitHub repos (`gsm-shield`, `Perfect-Download-Manager`, `workspace`) are **safe to clone**:
  their current HEAD has no infected executables (confirmed 2026-10-23). Do not check out old commits
  of `gsm-shield` or `workspace`, which still hold dormant infected blobs in history.

## Hard rules to stay clean
- Never run cracked/unofficial GSM tools (FRP bypass, flashers). They were the likely original source.
- Never run an executable straight from a USB, backup, download, or OneDrive without scanning it.
- Keep Microsoft Defender real-time + Tamper Protection ON. This project's tools detect and quarantine
  after the fact; they do not block execution before it happens.
