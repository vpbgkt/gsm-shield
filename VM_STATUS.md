# GSM Shield AV — VM Test Status Log

Live progress log for testing the Defender-replacement + WSC-registration flow
directly on the Windows 10 test VM (VMware Workstation).

## Environment

- **Host**: drives the VM via `vmrun.exe` (VMware Workstation) + a host helper `.vmtmp/vmctl.ps1`.
- **Guest VM**: Windows 10 22H2 (build 19045), user `windwos pc` (elevated for guest ops).
- **Guest tooling**: node / npm / git are **NOT** installed → building happens on the host,
  scripts/artifacts are copied into the VM for testing.
- **Rollback**: VMware snapshot + `git pull` from https://github.com/vpbgkt/gsm-shield.git

## Dev loop

1. Edit PowerShell scripts on the host (in the repo).
2. Push scripts into the VM and run them **elevated** via `vmrun` (fast loop — no reinstall).
3. Observe real Defender status / registry / WSC changes; pull logs back to host.
4. When scripts are verified, rebuild the installer on the host and do a full install test.
5. Commit working changes to GitHub; update this file.

## Baseline VM state (initial diagnostic)

Captured before any script run:

- `Defender RealTimeProtectionEnabled: False` (user turned it off)
- `Defender IsTamperProtected: False` (user turned it off)
- `Defender AntivirusEnabled: True`, `AMServiceEnabled: True`
- `WinDefend Start value: 2` (auto-start — service still active)
- WSC AntiVirusProduct: only `Windows Defender` (state 401664)
- GSM Shield AV **not installed**

## Change / test history

| # | Date | Action | Result |
|---|------|--------|--------|
| 0 | 2026-08-15 | Established vmrun bridge, ran baseline diagnostic | OK — see baseline above |
| 1 | 2026-08-15 | Found PS syntax error in disable-defender.ps1 (em-dash mojibake `â€"` inside a string created a stray quote → runaway string) | Root cause identified |
| 2 | 2026-08-15 | Sanitized all 3 scripts to pure ASCII (UTF-8 no BOM); re-validated with PS parser | All 3 scripts: no parse errors |
| 3 | 2026-08-15 | Ran fixed disable-defender.ps1 in VM (elevated) | **WinDefend Start=4 verified: True**; WdNisSvc/WdFilter/WdBoot Start=4; RealTimeProtection=False; exit 0. Step 4 (scheduled-task disable) failed 4x — tasks not present on this build (non-critical). |
| 4 | 2026-08-15 | **Rebooted VM and re-checked state** | **PASS — disable survives reboot.** WinDefend/WdNisSvc/WdFilter/WdBoot Start=4; `Get-MpComputerStatus` now FAILS ("general error") = WinDefend service did not start = Defender inactive. This is the intended success signal. |
| 5 | 2026-08-15 | Checked what Windows Security still shows (SecurityCenter2) | Even with service disabled, `SecurityCenter2` STILL lists "Windows Defender" (productState 397568) shown as off → user would still see Defender nagging. Decision: hide the UI. |
| 6 | 2026-08-15 | Added Step 7 to disable-defender.ps1: hide Virus & threat protection area (`UILockdown=1`), hide WS tray, remove SecurityHealth auto-start. Added matching undo to restore-defender.ps1. Ran in VM. | **PASS** — `UILockdown=1`, `DisableNotifications=1`, SecurityHealth Run value removed. Defender engine disabled AND its Windows Security page hidden. Reversible via restore-defender.ps1. |
| 7 | 2026-08-15 | Added auto-re-enable WATCHDOG: new `enforce-defender-disabled.ps1` + Step 8 in disable-defender.ps1 registering two SYSTEM scheduled tasks (`GSMShield_DefenderWatchdog` every 30 min, `..._Boot` at startup). Removal added to restore Step 0. | Fixed two false starts (Register-ScheduledTask `TimeSpan::MaxValue`; schtasks `/RI`+`/SC ONSTART` conflict). Switched to two schtasks tasks. **Both register (Ready).** |
| 8 | 2026-08-15 | **End-to-end watchdog test**: injected drift (WinDefend Start=2), triggered the SYSTEM task via `schtasks /Run` | **PASS** — task restored WinDefend + all driver services to Start=4; watchdog log confirms "DONE: Defender disable re-enforced." Auto-re-enable protection works. |
| 9 | 2026-08-15 | Reboot test of BOOT watchdog (drift injected before reboot) | **Found real bug**: boot task ran as SYSTEM but FAILED to re-disable WinDefend while it was running (fixed the 4 driver services only). Root cause: enforce script used file-only `takeown`/`icacls` (no-ops on registry) + took ownership as Administrators (blocked on a running WinDefend). |
| 10 | 2026-08-15 | Fixed enforce script: take ownership as **LocalSystem** + drop file-only takeown/icacls; tested against running WinDefend (Start=2) | **PASS** — re-disabled WinDefend to Start=4 while the service was Running. |
| 11 | 2026-08-15 | Enabled auto-login; injected drift; **rebooted** and let the boot watchdog run unattended | **PASS** — auto-login worked; boot watchdog auto-detected drift (WinDefend Start=2) and restored Start=4 with no manual action. Full unattended reboot scenario verified. |

## Verified capabilities (on real Windows 10 22H2 VM)

- Defender services permanently disabled (Start=4), **survives reboot**.
- Windows Security "Virus & threat protection" page hidden (`UILockdown`), notifications
  suppressed, WS tray removed.
- **Auto-re-enable watchdog** (two SYSTEM scheduled tasks: every 30 min + at every boot)
  re-disables Defender if Windows/Windows Update turns it back on — including WinDefend
  while it is actively running (LocalSystem ownership).
- Fully reversible via `restore-defender.ps1` (removes watchdog tasks first, restores
  services, MpPreference, policies, UI, and WSC registration).
- All PowerShell scripts are pure ASCII and parser-clean.

## Strategy decision (per product owner)

- **No code signing.** Therefore "show GSM Shield as the AV in Windows Security" is
  NOT achievable (Windows requires an Authenticode/MVI-signed binary). Goal changed to:
  **fully neutralize Defender + hide it from the user's view.**
- Target users are GSM technicians whose drivers/flash tools are blocked by Defender;
  they consent to disabling/removing Defender. `restore-defender.ps1` keeps it reversible.
- **Signing/WSC code is retained** (register-wsc.ps1 kept as best-effort) so it can be
  switched on if a code-signing certificate is obtained in the future.
- Achieved so far: permanent service disable (survives reboot) + hidden Virus & threat
  protection UI + suppressed notifications + **auto-re-enable watchdog (SYSTEM tasks).**

## Key learnings

- `runProgramInGuest` runs **elevated** in this VM, so the SYSTEM scheduled-task
  elevation path in disable-defender.ps1 succeeds (WinDefend Start=4 verified).
- **Scripts must be pure ASCII** — non-ASCII (em-dash, box-drawing) gets corrupted
  when the file is saved/copied, and a corrupted em-dash inside a string literal
  produced a stray `"` that broke parsing. Keep .ps1 files ASCII-only.
- After disable, `AntivirusEnabled`/`AMServiceEnabled` remain True in the same
  session (WinDefend can't be stopped live), but `Start=4` should make Defender
  inactive after a reboot. **Reboot persistence test pending.**

## Next steps

1. ~~Reboot the VM and confirm WinDefend does not start.~~ **DONE — PASS.**
2. ~~Hide Defender from Windows Security UI.~~ **DONE — PASS (UILockdown).**
3. ~~Add auto-re-enable watchdog.~~ **DONE — PASS (SYSTEM scheduled tasks).**
4. ~~Confirm watchdog auto-runs at boot and re-disables WinDefend.~~ **DONE — PASS.**
5. Optional: GSM driver compatibility (auto exclusions + Test Mode toggle).
6. Rebuild installer on host with sanitized scripts; full install test in VM
   (validate the installer's [Run] step wires the watchdog + hide-UI end-to-end).

## Scanner performance + engine upgrade (ClamAV 1.5.4 + clamd daemon)

- Upgraded bundled ClamAV engine from 1.5.2 to **1.5.4** (official Cisco-Talos
  Windows x64 release, downloaded from GitHub). Replaced all runtime DLLs +
  clamscan/freshclam; added `clamd.exe`, `clamdscan.exe`, `clamconf.exe`.
  Kept the existing `.cvd` virus definitions (version-independent data).
- Added `engine/clamd-manager.js`: starts the **clamd daemon** on a local TCP
  socket (127.0.0.1:13310) at app launch, waits for PING/PONG readiness, and is
  stopped on app quit. Config generated to AppData with absolute paths.
- `engine/scanner.js` now routes scans through the **warm daemon (clamdscan)**
  when ready, falling back to cold `clamscan.exe` (and using clamscan for Full
  Scan since it needs `--exclude-dir`). Same verdict-line parser for both.
- **Measured speedup (verified by direct execution):**
  - Cold clamscan EICAR scan: ~14,000 ms (full DB reload every run).
  - Warm clamd EICAR scan: **58-165 ms** (~65-150x faster). Daemon warm-up is a
    one-time ~30-37s at app launch, in the background.
- clamd protocol reports only infected files (no clean-file count), so
  daemon-mode "files scanned" is computed via a bounded file walk in
  `scan-handlers.js` (cap 1M files / 20s), which also streams live counts.
- UX: Scanner page shows phase (Loading definitions vs Scanning), live current
  file, live files/threats counters, elapsed timer, and per-threat quarantine
  status. All 16 scanner unit tests pass.
