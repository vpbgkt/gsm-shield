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

## Strategy decision (per product owner)

- **No code signing.** Therefore "show GSM Shield as the AV in Windows Security" is
  NOT achievable (Windows requires an Authenticode/MVI-signed binary). Goal changed to:
  **fully neutralize Defender + hide it from the user's view.**
- Target users are GSM technicians whose drivers/flash tools are blocked by Defender;
  they consent to disabling/removing Defender. `restore-defender.ps1` keeps it reversible.
- Achieved so far: permanent service disable (survives reboot) + hidden Virus & threat
  protection UI + suppressed notifications.

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
3. Reboot again and confirm the Virus & threat protection page is actually gone
   from the Windows Security app (needs a look at the running app).
4. Add auto-re-enable **watchdog** in GSMShieldAVService (re-apply Start=4 if Windows resets it).
5. Optional: GSM driver compatibility (auto exclusions + Test Mode toggle).
6. Rebuild installer on host with sanitized scripts; full install test in VM.
