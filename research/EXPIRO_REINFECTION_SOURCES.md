# Why Expiro keeps coming back — reinfection reservoirs

**Date:** 2026-10-23. Companion to [EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md).

The system drive has been cleaned more than once, yet Windows Defender keeps raising Expiro alerts.
This is **not a new outbreak and not active spread** — each time, the structural scan of C: and D:
shows no running infected process and (after cleanup) zero infected files. The alerts come from
Defender's real-time protection touching **pre-existing infected copies that live outside the
system drive** and get re-introduced. To stop the cycle, those reservoirs must be purged too.

## Confirmed reservoirs

| # | Reservoir | What is infected | Status after this session |
|---|---|---|---|
| R1 | **OneDrive cloud** (`OneDrive\Desktop\workspace`, `workspace-master`) | cracked GSM tools: `adb.exe`, `fastboot.exe`, `frp.exe`, `FalconFRPTool_V1.0.0.1.exe`, `Tecno Infinix Itel Fastboot Info Read.exe`, `nodemon\bin\windows-kill.exe` | local working-tree copies restored from clean git history or removed by Defender; **cloud copies still infected and will re-sync** |
| R2 | **GitHub `vpbgkt/workspace`** | committed history contains an infected `node_modules/nodemon/bin/windows-kill.exe` (tracked blob is the virus); the adb/fastboot/Tecno blobs in history are clean | **not yet cleaned** — needs history rewrite or file removal |
| R3 | **GitHub `vpbgkt/gsm-shield`** | five infected ClamAV `.exe` in commits `88d29a0`/`3c6179c` | HEAD fixed (commits `56b089b`, `f9bc90d`); **old blobs remain in history** |
| R4 | **Windows install USB (E:)** | infected setup files + Intel RST driver package | re-create the USB on a clean PC; do not reuse |
| R5 | **D: archives / backups** | `D:\Trash\update136.tar` (>=282 infected entries), executables in `D:\Trash\21octResetBackup`, old `$RECYCLE.BIN` | delete or keep offline; never extract-and-run |
| R6 | **Cracked / unofficial GSM tools** (the likely original vector) | FRP bypass and flashing tools from unofficial sources | replace with vendor tools; treat all such downloads as untrusted |

## The mechanism of "reinfection"

1. The original infection (before the first reinstall) infected executables that were also stored in
   OneDrive and pushed to GitHub. The infected **bytes** went to the cloud and to the repos.
2. After each reinstall, OneDrive re-syncs those infected files down, and cloning/pulling a repo
   brings back the infected committed blob. Defender then flags them — which looks like reinfection.
3. There is no need for a live infector for this to happen; the infected files are simply copies
   that already exist elsewhere and come back.

A single genuinely-active path existed earlier (infected Git being run constantly by VS Code /
Claude Code), and that was closed by reinstalling Git. Since then every alert has been a re-detection
of a stored copy, not propagation.

## Required actions to break the cycle (user)

1. **OneDrive:** from a clean device open onedrive.live.com and delete the infected tool copies in
   `Desktop\workspace\gsmmeta-tool-rental\...` and `workspace-master\...`, then empty the OneDrive
   recycle bin. Check every other device that syncs this OneDrive.
2. **`vpbgkt/workspace` repo:** remove the infected `windows-kill.exe` from history (e.g. `git filter-repo`),
   or delete/recreate the repo. Do not `git clone` it onto a clean machine until done.
3. **`vpbgkt/gsm-shield` repo:** decide whether to rewrite history to purge the old infected ClamAV
   blobs; HEAD is already clean.
4. **Install USB (E:):** re-create on a clean PC.
5. **D: and backups:** delete `D:\Trash\update136.tar` and old recycle-bin folders; scan backups
   before reuse; never run executables from them.
6. **Stop using cracked GSM tools**; they are the most likely original source.
7. **Rotate credentials** from a clean device (a stolen-data file was present earlier).

## What was done on the system drive this session

- Removed the infected Intel driver package `oem29.inf` (`piecomponent.inf`) and deleted the
  `PIEServiceNew` service; `Intel_PIE_Service.exe` is gone.
- Flushed the orphaned `WinSxS\Temp\PendingDeletes` ssh-agent copy via a local
  `DISM /StartComponentCleanup` (no Windows Update needed).
- Deleted the preserved infected ClamAV analysis samples (hashes retained in
  `research/samples/infected/repo-clamav-2026-10-19/HASHES.csv`).
- Restored clean working-tree copies of `adb.exe`, `fastboot.exe`, `Tecno ...exe` from clean git
  history in the OneDrive `workspace` clone.

**Final system-drive state:** C: and D: scan 0 infected / 0 suspicious across 26,402 readable PE
files; no infected process; ssh-agent clean and disabled. 127 folders need an elevated scan for full
coverage (other user profiles, `WindowsApps`, `System Volume Information`). The system drive is clean;
the machine will stay clean only once the external reservoirs R1-R6 are purged.
