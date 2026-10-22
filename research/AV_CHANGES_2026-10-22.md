# GSM Shield changes for Expiro — 2026-10-22

Why: the real samples on this machine showed that the v2 Expiro engine detected none of them, that its "surgical" repair reported false success, that quarantined files stayed executable, and that the antivirus itself shipped infected ClamAV binaries. Details: [EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md), [EXPIRO_TECHNICAL_REFERENCE.md](EXPIRO_TECHNICAL_REFERENCE.md). Nothing has been committed.

## 1. Changes

| Area | File(s) | Change |
|---|---|---|
| Detection | `engine/expiro-structural.js` (new) | Structural Expiro detector (S1–S6 in the technical reference). Reads header + 32 bytes at EP + ≤4 MB of the EP section; no file-size cap; never executes. Exposes `buildIdentity`/`isSameBuild` for verified restores. |
| Detection | `engine/expiro-detector.js` | Structural layer is primary; an "infected" structural verdict cannot be vetoed by the legacy packer/Authenticode overrides; "suspicious" can raise confidence but never to the threshold alone. Structural layer also checks `.com .cpl .ocx .sys .tmp .efi`. v2 heuristics kept as `detectLegacyHeuristics`. |
| Remediation | `engine/expiro-disinfector.js` | Removed in-place "surgical" patching, automatic backups of infected files (stored as runnable `.exe`) and the filename-based clean-source lookup. New order: protected Windows paths → DISM/SFC guidance; verified same-build, structurally clean copy from a caller-supplied trusted directory → restore; else quarantine + "reinstall from vendor". Fixed the batch sort comparator. |
| Quarantine | `engine/quarantine.js` | Files stored as `<uuid>_<name>.gsmq` with an 8-byte header and XOR-encoded content (not a PE, cannot run even if renamed). Restore decodes; legacy raw entries still restore. If the original cannot be deleted, the copy is rolled back. |
| Integrity | `engine/binary-integrity.js` (new), `assets/clamav/clamav-binaries.sha256.json` (new) | Bundled ClamAV executables must match SHA-256 from the official 1.5.4 release and be structurally clean before launch. `GSM_ALLOW_UNVERIFIED_BINARIES=1` allows a hash mismatch for deliberate upgrades but never an infected file. |
| Integrity | `engine/scanner.js`, `engine/clamd-manager.js`, `engine/updater.js` | Call the guard before every `spawn` of clamscan/clamdscan/clamd/freshclam; refuse with a clear error. |
| Build | `scripts/build.js` | Stage 2 refuses to package if the bundled binaries fail verification. |
| Persistence | `engine/service-integrity.js` (new) | Reads services via `reg.exe query` (read-only); flags infected service executables (critical), disabled/manual→auto escalations against a saved baseline (high), known-disabled services set to Auto (medium), missing binaries (info). |
| Real-time | `monitor/expiro-monitor.js`, `engine/expiro-prevention.js` | `%LOCALAPPDATA%\Temp` no longer ignored (downloads/installers/uninstaller copies land there); watches `.exe .dll .scr .com .cpl .tmp`. |
| CLI | `bin/gsmshield.js` | New `services` (with `--save-baseline/--baseline`) and `verify-binaries`; `disinfect --trusted-source=<dir>`; removed "surgical" wording and the legacy backup folder; `status` warns about legacy runnable quarantine folders. |
| UI text | `renderer/src/store/expiroStore.js` | No more "Surgically disinfected" message; outcomes are "Replaced with a verified clean copy of the same build" or "Quarantined (neutralized) — reinstall". |
| Research tool | `research/tools/safe-restore-quarantine.js` | Restores only files with an explicit structural "clean" verdict (the v2-only version could restore infected files). |
| Research tools | `research/tools/validate-structural.js`, `Expiro-StructScan.ps1`, `Collect-ExpiroEvidence.ps1`, `scripts/restore-clamav-binaries.ps1` (new) | Read-only validation/scan/evidence collection; verified ClamAV restore. |
| Assets | `assets/clamav/*.exe` | **Currently absent from the working tree.** Official ClamAV 1.5.4 executables were written twice (17:57 and 18:33) and re-infected within 1 s and ~2.5 min by the active infector, so the re-infected copies were deleted (hashes in `research/samples/infected/repo-clamav-2026-10-19/REINFECTED_AFTER_RESTORE.csv`; committed infected originals preserved as `*.infected`). After remediation run `scripts/restore-clamav-binaries.ps1`, then `node bin/gsmshield.js verify-binaries`. Until then the repository-assets test fails and GSM Shield refuses to scan (by design). |

## 2. Tests

New: `engine/expiro-structural.test.js` (17), `engine/binary-integrity.test.js` (8), `engine/service-integrity.test.js` (13), `engine/expiro-disinfector.test.js` (6), `engine/quarantine.neutralize.test.js` (5), 3 new cases in `engine/expiro-detector.test.js`; `engine/quarantine.test.js` updated for the `.gsmq` name plus 3 new cases. Synthetic PE images (`engine/__tests__/helpers/pe-builder.js`) reproduce the measured layouts.

Final run on Node 24.22.1 (`npm ci --ignore-scripts`):

| Suite group | Result |
|---|---|
| Expiro engine (structural, detector, disinfector, integration, service-integrity, binary-integrity unit tests), quarantine neutralize, scanner, updater, monitor (unit + property), build smoke | **165 passed** |
| `binary-integrity` › repository assets match manifest | **failed as intended** at that moment: the active infector had re-infected the restored ClamAV files; it passes when the files are clean (see `node bin/gsmshield.js verify-binaries`) |
| `engine/quarantine.test.js`, `scanner.property`, whitelist/database suites | not runnable here: better-sqlite3 11.10.0 has no prebuilt binary for Node 24 and no C++ build tools are installed (pre-existing, environmental) |
| `first-run.preservation`, renderer build smoke, backend routes, Defender WSC/preservation | not runnable here (Electron binary not downloaded with `--ignore-scripts`, npm not on the test PATH, backend deps not installed, scripts need elevation). The renderer build was deliberately not run because `esbuild.exe` in `node_modules` had been infected. |

Real-file validation (read-only, `research/tools/validate-structural.js`, C: and D:): 25,632 PE files → **93 infected, 0 suspicious, 25,539 clean**. Every infected verdict is corroborated by a Defender detection, a mismatch against an official release hash (ClamAV, esbuild), or a canary observed changing from clean to infected. The PowerShell port gives identical scores on the same files.

## 3. False-positive risk

- Indicators were chosen because legitimate toolchains never produce them together: executable **data-named** last section + zeroed relocation directory + ASLR cleared. On this corpus no clean file had an executable+writable last section at all.
- Residual risks: protectors that place code in a section named like data (e.g. a custom-renamed `.rsrc`) and also strip relocations; very old binaries linked `/FIXED` with odd section flags; self-modifying installers. Themida/VMProtect/UPX-style layouts are covered by tests and classify as clean or "suspicious", but real Themida/Enigma samples were not available here.
- A "suspicious" verdict never quarantines on its own.

## 4. Limitations

- **No pre-execution blocking.** Without a kernel minifilter, GSM Shield detects after a file is written and quarantines it. It cannot stop an already-running infected process or prevent a user from launching an infected file. Windows Defender (with Tamper Protection) or Smart App Control/WDAC must stay enabled for that.
- **No disinfection.** Infected files are replaced or quarantined; the virus body is not decrypted.
- **Unknown variants.** A future Expiro build that keeps the relocation directory and section flags intact would evade the structural layer. ClamAV signatures and Defender remain necessary.
- **Service checker** needs a saved baseline to detect start-type escalations reliably; without one it only knows a short list of normally-disabled services.
- **Integrity manifest** covers the five ClamAV executables only; Electron/app binaries are not yet covered (code signing of the installer is still disabled in `electron-builder.yml`).
- **This machine:** tests ran on an actively infected system. Results for the code are valid (deterministic, synthetic inputs plus read-only scans); results about the machine are a snapshot.

## 5. Recommended next steps for the project

1. Commit these changes from a clean machine, with the official ClamAV executables, and push. Decide how to handle the infected binaries already in `origin` history.
2. Enable code signing for the installer and add the Electron executable and DLLs to an integrity manifest.
3. Wire `service-integrity` into the Electron main process (periodic check + saved baseline + UI alert).
4. Add a ClamAV/YARA rule once a decrypted body is available, to complement the structural layer.
5. Move the better-sqlite3 dependency to a version with Node 24 prebuilds (or pin the test runtime to a supported Node) so the full suite runs in CI.
