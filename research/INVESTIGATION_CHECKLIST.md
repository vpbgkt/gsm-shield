# Expiro investigation checklist

Use in order. Read-only steps first; nothing is deleted before the evidence for it is saved. `[x]` = done in the 2026-10-22 investigation (non-elevated), `[ ]` = still to do.

## A. Safety before touching anything
- [x] Identify a trusted shell. Verify its signature first: `Get-AuthenticodeSignature (Get-Command powershell).Source` → Valid. **Do not use Git Bash or anything under `C:\Program Files\Git` on an infected machine.**
- [x] Note privilege level (`whoami /groups`): medium integrity = many folders and SYSTEM process paths are invisible.
- [x] Note clock skew: compare `Get-Date`, `LastBootUpTime`, `InstallDate`, and detection times. Future timestamps = wrong clock during setup.
- [ ] Disable infected auto-start services before any reboot ([ADMIN], see DISINFECTION_PROCEDURE §1).

## B. Defender ground truth (works without admin)
- [x] `Get-MpComputerStatus` (real-time, tamper, engine/signature versions).
- [x] `Get-MpThreat` + `Get-MpThreatDetection` exported with ISO dates, one row per resource (`Collect-ExpiroEvidence.ps1`).
- [x] Group by threat name, status ID, detecting process, drive, hour.
- [x] Earliest detections and `process:_pid:N,ProcessStart:<FILETIME>` resources → which infected process ran first.
- [x] Defender operational log 5001/5007 → who disabled real-time / tamper protection.
- [ ] [ADMIN] `MpCmdRun.exe -Restore -ListAll` (quarantine contents).

## C. Current state of every detected file
- [x] Exists? size, LastWriteTime (unreliable: Expiro restores it), signature status.
- [x] Missing system files → Defender deleted them; list services whose registry keys disappeared.

## D. Persistence
- [x] Services: binary signature + start type; `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start`.
- [x] System log 7040 "changed from disabled/demand start to auto start" (Expiro), 7045 (new service), 7034 (crash).
- [x] Run/RunOnce, startup folders, Startup shell-folder values (Trend Micro IOC), non-Microsoft scheduled tasks.
- [x] IOCs: `%APPDATA%\<16 hex>.bin`, `%SystemRoot%\System32\gazt_mx_dis`.
- [ ] [ADMIN] Prefetch (`C:\Windows\Prefetch`) for executions of infected binaries; `C:\Windows\Panther\setupact.log`.

## E. Structural sweep
- [x] `Expiro-StructScan.ps1` / `node research/tools/validate-structural.js` on C:, D: (non-elevated: 117 folders unreadable).
- [ ] [ADMIN] Repeat elevated for full coverage, including other profiles, `WindowsApps`, `System Volume Information`, old `$RECYCLE.BIN`.
- [x] Archives: list `.zip/.rar/.7z/.tar/.iso` (scanner does not open them; rely on Defender for contents).

## F. Reinfection sources
- [x] Install media (E:) — infected.
- [x] Data drive (D:) — PE files clean; `update136.tar` infected; backups contain executables from cracked tools.
- [x] OneDrive — infected GSM tools synced back.
- [x] Developer tools running Git (VS Code, Claude Code, GitHub Desktop) — active vector.
- [x] Project repository / installers — infected ClamAV EXEs.
- [x] App self-updaters (Brave, Edge, Claude desktop) — infected after download.
- [ ] Other PCs/phones sharing OneDrive, USB sticks, network shares.

## G. Active-infection test (non-destructive)
- [x] Run a passive process logger (`Win32_Process` polling) and correlate executions with the time new executables changed.
- [x] Canary: copy a known-clean executable into a user folder and re-check its structure after a few minutes. (Use a fresh clean source each time; an already-infected source makes the canary useless.)

## H. Report
- [x] Separate confirmed facts from hypotheses ([EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md)).
- [x] Save evidence in `research/logs/<date>/`.
- [ ] After remediation: run every check in DISINFECTION_PROCEDURE §6 and record results.
