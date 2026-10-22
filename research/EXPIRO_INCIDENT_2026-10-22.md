# Expiro incident report — 22 October 2026

**Machine:** COSMOS (Windows 11 Home 10.0.26300), user `vpbgk`, reinstalled on 22 Oct 2026.
**Investigator:** Claude (AI assistant), non-elevated session, read-only unless stated.
**Status at end of investigation (18:30 IST):** **NOT CLEAN. Infection active in user context.** Do not reboot before reading [DISINFECTION_PROCEDURE.md](DISINFECTION_PROCEDURE.md).

Companion documents:
[EXPIRO_TECHNICAL_REFERENCE.md](EXPIRO_TECHNICAL_REFERENCE.md) (how Expiro works, with sources) ·
[INVESTIGATION_CHECKLIST.md](INVESTIGATION_CHECKLIST.md) ·
[DISINFECTION_PROCEDURE.md](DISINFECTION_PROCEDURE.md) ·
[AV_CHANGES_2026-10-22.md](AV_CHANGES_2026-10-22.md) (code changes, tests, limitations) ·
evidence in [logs/2026-10-22/](logs/2026-10-22/).

---

## 1. Summary

1. **Why the reinstall did not help.** Infected executables were brought back onto the fresh install. The strongest evidence points at the **Windows installation USB (E:)**: it carried an infected Intel Rapid Storage Technology driver folder (`E:\RST_V19.1.0.1001_PV\RstMwService.exe`) and infected setup programs (`\sources\setuperror.exe`, `\sources\diagtrackrunner.exe`, `\boot\memtest.exe`). The first infected process Defender saw on the new system was `RstMwService.exe` from exactly that driver package, running as a SYSTEM service.
2. **How it persisted.** Expiro infected Windows **service executables** and switched them from manual/disabled to **automatic** start (event 7040), so they ran as SYSTEM at every boot and infected everything else. `ssh-agent` and `Intel PIE Service` are still infected and still set to start automatically.
3. **Why it is still spreading now.** `C:\Program Files\Git` is infected. VS Code's Git integration, Claude Code and (since 18:26) GitHub Desktop run `git.exe` every few seconds; each run executes Expiro as the current user, which infects new user-writable executables within seconds. This was observed directly (process log + infected test files).
4. **The antivirus project was itself a carrier.** The five ClamAV executables committed to this repository on 19 Oct (commit `88d29a0`, also on `origin/main`) are Expiro-infected copies of the official ClamAV 1.5.4 files. GSM Shield runs elevated and starts `clamd.exe` at launch.
5. **The earlier "system verified clean" conclusions were wrong.** The v2 detector scores real Expiro infections at **0**. Any decision made with it (including "false positive" restores from quarantine) is unreliable.
6. **Defender's cleanup damaged Windows.** It deleted infected system binaries (`dllhost.exe`, `sppsvc.exe`, `MidiSrv.exe`, `perfhost.exe`, ...) and their service registrations, and failed on most other files (error `0x8007007F`).
7. **Credential theft is likely.** `%APPDATA%\1c0b060669175429.bin` (12,320 bytes, entropy 7.99, created at first logon) matches the published Expiro stolen-data store.

## 2. Confirmed facts vs hypotheses

### Confirmed (direct evidence on this machine)

| # | Fact | Evidence |
|---|---|---|
| C1 | Defender recorded 823 detections / 1,696 resource rows of Win32/Expiro.HNW, Win32/Expiro.EK, Win32/Expiro.EB, Win64/Expiro.EM, Win64/Expiro.DD. Most remediations failed (status 102/106, error 0x8007007F). | `logs/2026-10-22/defender_detections.csv` |
| C2 | The install USB (E:) held infected `RST_V19.1.0.1001_PV\RstMwService.exe`, `sources\diagtrackrunner.exe`, `sources\setuperror.exe`, `sources\dlmanifests\...\iasmigreader.exe`, `boot\memtest.exe` (quarantined 14:05). | Defender rows for `E:\` |
| C3 | First session after setup: `RstMwService.exe` from `DriverStore\...\iastorvd.inf_amd64_fb9e356192ae1106\` ran (pid 5568, start 02:10:21) and was detected 2 s later. | Defender rows; process start FILETIME |
| C4 | At 02:10:21–02:10:24 the start type of COM+ System Application, Performance Counter DLL Host, Windows MIDI, Perception Simulation, Sensor Data, ReFS Dedup, WMP Network Sharing changed demand→auto and **OpenSSH Authentication Agent disabled→auto**; at 02:11:33 all of them started simultaneously as infected processes. Intel Storage Middleware (RstMwService) disabled→auto at 14:23, PIEServiceNew at boot 16:29. | System log event 7040; Defender process resources |
| C5 | `ssh-agent.exe` and `Intel_PIE_Service.exe` are infected, unsigned, Start=Auto (stopped now). The infected `ssh-agent.exe` is hard-linked with the WinSxS component-store copy `10.0.26100.9444`. The RTM copy `10.0.26100.1` in WinSxS is clean. | structural scan; `fsutil hardlink list`; signatures |
| C6 | Deleted by Defender (files and service keys): `dllhost.exe` (COMSysApp), `sppsvc.exe`, `MidiSrv.exe`, `SensorDataService.exe`, `ReFsDedupSvc.exe`, `PerceptionSimulationService.exe`, `SysWOW64\perfhost.exe`, `wmpnetwk.exe`, Edge/Copilot `elevation_service.exe`, `MicrosoftEdgeUpdate.exe`, Brave binaries, `AsusAppService.exe`. Services `sppsvc`, `midisrv`, `PerfHost`, `COMSysApp`, `WMPNetworkSvc`, `SensorDataService`, `perceptionsimulation`, `ReFsDedupSvc`, `edgeupdate(m)`, `MicrosoftEdgeElevationService`, Brave services are gone. DCOM errors (dllhost missing) appear every few seconds. | `defender_detected_files_state_1730.csv`; registry; System log 10000/10001 |
| C7 | The repo's `assets/clamav/*.exe` (commit `88d29a0`, pushed) are infected: all 24 DLLs are byte-identical to official ClamAV 1.5.4, all 5 EXEs differ; official EXE sizes equal the pre-19-Oct sizes; official score 0, repo score 85–100. | official release digest `0d9e0228…c395`; `research/samples/infected/repo-clamav-2026-10-19/HASHES.csv` |
| C8 | Expiro is executing in user context right now via infected Git. 17:50–18:15: Claude Code (pid 10088) and VS Code (pid 15700) started infected `git.exe` every 5–30 s. Clean ClamAV files written at 17:57:46 were infected by 17:57:47, right after a `git status` started at 17:57:46.97. Canaries (including a copy of signed `cmd.exe`), `npm ci` outputs (`7za.exe`, `esbuild.exe`, `app-builder.exe`) and GitHub Desktop's bundled Git (18:26) were infected within seconds to minutes. | `logs/2026-10-22/process_timeline_git_1750_1815.log`; `session_artifacts_deleted.csv`; structural scans |
| C9 | The v2 detector (`detectExpiroInfection` before today) returns 0 for real infected files. | `engine/expiro-detector.test.js` "legacy v2 scores it 0"; manual run |
| C10 | `%APPDATA%\1c0b060669175429.bin`, 12,320 B, entropy 7.985, created 13:59:17 (first logon). SHA-256 `068C1BDD6B351DEFD0A4E0519A50B12EB6A37DB397EE13F8FA1900F948A64D2A`. Pattern matches the Seqrite/Quick Heal IOC `%AppData%\<random_hex>.bin` (encrypted stolen browser certificates/passwords). | file metadata |
| C11 | Defender real-time protection was disabled at 16:41:03 and Tamper Protection at 16:41:07 with source value 2 (UI) — consistent with the user's own action, not malware. | Defender event 5001/5007 |
| C12 | D: has no structurally infected PE files among 86 readable executables. `D:\Trash\update136.tar` (1.1 GB) contains ≥282 infected entries (Defender, not removed). Four `$RECYCLE.BIN` folders of the previous installation are unreadable without admin; one contained an infected `windows-kill.exe`. | `ps_struct_sweep_D_1735.csv` (0 hits); Defender rows |
| C13 | OneDrive Desktop held infected `adb.exe`, `fastboot.exe`, `Tecno Infinix Itel Fastboot Info Read.exe` (gsmmeta-tool-rental); removed locally by Defender. Cloud copies / OneDrive recycle bin not checked. | Defender rows |
| C14 | Claude desktop app's Claude Code runtimes `Claude-Data\...\claude-code\2.1.304` and `2.1.308` are infected (2.1.304 detected 16:39 as Win64/Expiro.DD; 2.1.308 = clean build + ~570 KB body). The VS Code extension's `claude.exe` and the desktop app binary itself are clean. | structural scan vs clean same-version binary |

### Hypotheses (not proven)

| # | Hypothesis | Confidence | What would confirm/refute it |
|---|---|---|---|
| H1 | The RST driver loaded from the USB during Windows Setup was the **initial** infection vector of the new install. Alternative H1b: Setup ran infected `diagtrackrunner.exe` from the USB in WinPE. Either way the USB is the carrier. | High (carrier), medium (exact step) | Setup logs `C:\Windows\Panther\setupact.log` (admin), Defender history of earlier boots |
| H2 | 16:55 infection of Claude Code 2.1.308 was done by the infected 2.1.304 runtime launched by the desktop app (no SYSTEM infector was alive). | Medium | Prefetch for `claude.exe` under Claude-Data (admin) |
| H3 | On the previous installation, `research/tools/safe-restore-quarantine.js` restored infected files as "false positives" (v2 detector cannot see Expiro). | Medium | Old quarantine log vs. structural rescan (data no longer available) |
| H4 | Original infection of the old system came from cracked or unofficial GSM tools (e.g. `USB Redirector ... [Full Cracked]`, iRemoval PRO, the `update136` driver pack). | Low/unknown | Not determinable from current evidence |
| H5 | Defender's `0x8007007F` (ERROR_PROC_NOT_FOUND) remediation failures relate to the engine version 1.1.26100.4 shipped with this build. | Low | Update engine, rescan, compare |

## 3. Timeline (IST)

The clock was wrong (~+12.5 h) during the first session: InstallDate and the earliest detections read **23 Oct 02:10–02:13** although they happened before 22 Oct 13:43. Events below are in true order.

| Time | Event |
|---|---|
| 19 Oct 22:12 | Commit `88d29a0` adds infected ClamAV EXEs; later pushed to GitHub. |
| (before reinstall) | Install USB exposed to the infected system; RST driver folder and setup EXEs infected. |
| "23 Oct 02:10:21" (session 1) | Infected `RstMwService` runs; 7040 start-type changes; Defender detects. |
| "23 Oct 02:11:33" | Boot: infected ssh-agent, MidiSrv, PerfHost, PerceptionSimulation, ReFsDedup, dllhost (COMSysApp), Edge elevation service start together. |
| 22 Oct 13:43–14:20 | Detections continue; USB (E:) scanned and quarantined 14:00–14:05. |
| 14:48 | Git for Windows installed; infected by 15:05 (by ssh-agent). Brave, Edge/Copilot updaters infected 15:09–15:19. |
| 15:52 | Defender full scan ends. |
| 16:29 | Reboot. Infected PIEServiceNew and ssh-agent auto-start; ssh-agent re-infects Git from 16:29:35. |
| 16:39 | Claude desktop downloads Claude Code 2.1.304; infected by ssh-agent within 20 s. |
| 16:41 | Real-time protection and Tamper Protection turned off (UI). Git reinstalled (unins001). |
| 16:44 | ssh-agent terminated. |
| 16:55 | Claude Code 2.1.308 downloaded; infected afterwards (H2). |
| 17:16–17:25 | **This investigation's Bash tool ran `C:\Program Files\Git\bin\bash.exe` and `git.exe` (infected) ~12 times before the Git infection was discovered.** Switched to PowerShell only afterwards. |
| 17:39 | Node.js 24.22.1 installed by the user (verified clean). |
| 17:42 / 17:57 | Freshly written clean executables infected within ~1–2 s, each time right after a Git status run. |
| 18:04 | `npm ci` (by investigator); `7za`, `esbuild`, `app-builder` infected within minutes (deleted later). |
| ~18:12 | Investigator disables VS Code Git integration for this workspace (`.vscode/settings.json`). |
| 18:26 | GitHub Desktop installed by the user; its bundled Git infected immediately (Defender detection, status "detected"). |

## 4. Current infected inventory (structural scan, 18:25)

| Location | Files | Notes |
|---|---|---|
| `C:\Program Files\Git` | 52 | Reinfected after every reinstall while an infector runs. **Primary active vector.** |
| `C:\Program Files (x86)\BraveSoftware\Update` | 9 | Brave Update + cached installers |
| `C:\Windows\System32\OpenSSH\ssh-agent.exe` (+ WinSxS hard link) | 1 | Start=Auto |
| `...\DriverStore\...\piecomponent.inf...\Intel_PIE_Service.exe` | 1 | Start=Auto |
| `%LOCALAPPDATA%\Claude-Data\...\claude-code\2.1.304`, `2.1.308` | 2 | Claude desktop's Claude Code runtime |
| `%LOCALAPPDATA%\GitHubDesktop\app-3.6.7\resources\app\git\...` | ≥5 | Installed 18:26 (Defender), not structurally rescanned |
| `%TEMP%\is-B4N3IB7VVW-uninstall.tmp\_unins.tmp` | 1 | Git uninstaller copy |
| `gsm-shield\assets\clamav\*.exe` | 0 (deleted) | Re-infected twice after replacement, then removed; restore after remediation |
| `D:\Trash\update136.tar` | ≥282 inside | archive, not removed |
| E: (install USB) | 5 | quarantined by Defender, USB must be re-created |

Readable scope: 25,632 PE files on C: and D: (non-elevated); 117 folders were unreadable (WindowsApps, System Volume Information, other profiles, old recycle bins). An elevated scan is required for full coverage.

## 5. What the investigator changed

- Repository: new structural engine, detector integration, safe disinfector, neutralized quarantine, binary-integrity guard + manifest, service-integrity checker, build guard, CLI commands, monitor scope, tests, research docs and tools ([AV_CHANGES_2026-10-22.md](AV_CHANGES_2026-10-22.md)). Nothing committed or pushed.
- `assets/clamav/*.exe`: replaced twice with the verified official ClamAV 1.5.4 executables; both times re-infected by the active infector (within ~1 s at 17:57, ~2.5 min at 18:35). The re-infected copies were deleted, so the five executables are **absent** from the working tree; restore with `scripts/restore-clamav-binaries.ps1` after remediation. The originally committed infected files are kept as `research/samples/infected/repo-clamav-2026-10-19/*.infected`.
- `.vscode/settings.json` (git-ignored): `git.enabled=false` for this workspace (containment). Revert after Git is clean.
- Created and later deleted: canary executables, extracted ClamAV files, `node_modules` (hashes in `logs/2026-10-22/session_artifacts_deleted.csv`).
- Not changed: Defender settings, services, Program Files, Windows files, D:, OneDrive, git history.
- Test side effects: `defender/register-wsc.bug.test.js` executed `register-wsc.ps1` non-elevated; HKLM writes failed, registry verified unchanged.

## 6. Limits of this investigation

- No elevation: SYSTEM process paths, Defender quarantine, Prefetch, setup logs and 117 folders were not inspected.
- The infection mechanism was established by static structure and behaviour correlation, not by reversing the virus body. The body was not decrypted.
- Polling-based process logging (400 ms) can miss very short-lived processes.
- The structural rules were measured on this machine's corpus (25,539 clean PE files, 0 false positives). Packers not present here (Themida, Enigma, some installers) could still trigger "suspicious" or, rarely, "infected".
- "Clean" cannot be claimed for any part of this machine until the verification criteria in [DISINFECTION_PROCEDURE.md §6](DISINFECTION_PROCEDURE.md#6-verification-criteria-required-before-calling-the-system-clean) pass.
