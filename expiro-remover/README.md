# Expiro Remover

A single-file, dependency-free Windows PowerShell tool to **detect, contain and remove** the
Expiro file-infector (`Virus:Win32/Expiro`, `Virus:Win64/Expiro`, Defender families EK/EB/HNW/EM/DD),
plus a helper to drive Windows' own repair of infected OS components.

It is defensive incident-response tooling: it scans, stops, disables and quarantines. It never
executes a scanned file, and it does not modify protected Windows binaries in place.

## Why Expiro needs special handling

Expiro appends an encrypted body to the **last PE section**, makes that section RWX, zeroes the
base-relocation directory, clears ASLR, and repoints **one existing `CALL` in `.text`** into its
body (the PE entry point is left unchanged). The bytes it overwrites are stored encrypted, so the
original cannot be reconstructed without decrypting a polymorphic blob. This is shown byte-for-byte
on two independent clean/infected pairs in [`../research/EXPIRO_INFECTION_TRANSFORM.md`](../research/EXPIRO_INFECTION_TRANSFORM.md).

Consequences this tool is built around:
- **Detection is structural**, not signature-based, so it survives Expiro's polymorphism.
- **Repair = replacement.** Infected files are quarantined (or replaced from a verified clean copy
  of the same build); in-place "repair" is not attempted because it cannot be done safely.
- A single run of any infected program re-infects user-writable executables within seconds, so
  **containment order matters**: stop processes and disable services before quarantining files.

## Detection rule

An executable is flagged **infected** when its score is >= 75 and it has either S1 or S4:

| ID | Indicator | Score |
|---|---|---|
| S1 | last section is executable but named as data (`.reloc .rsrc .debug .symtab` ...) | 50 |
| S1b | last section executable+writable with a non-data name | 15 |
| S2 | `.reloc` section present but base-relocation directory is zero | 25 |
| S3 | ASLR (DYNAMIC_BASE) cleared while a `.reloc` section exists | 10 |
| S4 | CALL/JMP in the first 32 bytes at the entry point targets the last section | 40 |
| S5 | last section RWX and >= 512 KB | 10 |
| S6 | 1-8 rel32 branches in the entry section target the last section (when S4 absent) | 15 |

Measured on this machine: 31,258 clean PE files, 0 false positives; every infected verdict was
corroborated by Windows Defender, a mismatch against an official release hash, or a canary observed
turning from clean to infected. Residual false-positive risk (protectors that place code in a
data-named last section and also strip relocations) is discussed in the research notes.

## Files

| File | Purpose |
|---|---|
| `Expiro-Remover.ps1` | scan / remediate / undo / verify (details below) |
| `Repair-WindowsComponents.ps1` | run DISM + SFC to repair infected protected Windows files, and report service registrations that need an in-place upgrade |
| `../research/tools/Expiro-StructScan.ps1` | same detector, scan-only, portable |
| `../research/tools/expiro-diff.js` | read-only forensic diff of a clean/infected pair (Node) |
| `../research/EXPIRO_TECHNICAL_REFERENCE.md` | how Expiro works, with sources |
| `../research/DISINFECTION_PROCEDURE.md` | full procedure, verification criteria, credential rotation |

## Usage

Read-only scan of all fixed drives (safe, no elevation):
```powershell
.\Expiro-Remover.ps1
```

Remove (elevated; asks for confirmation unless `-Force`):
```powershell
# right-click PowerShell > Run as administrator
.\Expiro-Remover.ps1 -Mode Remediate
```
Remediate, in order: stops processes whose image is infected, stops and **disables** services whose
image is infected, then quarantines infected files outside protected Windows folders. Protected
Windows files are left in place (their services are disabled) and listed in `plan.txt` for DISM/SFC.
Everything it does is written to a `state.json` so it can be undone.

Undo a remediation (restores service start types and files; restored files are still infected):
```powershell
.\Expiro-Remover.ps1 -Mode Undo -StateFile C:\ProgramData\ExpiroRemover\reports\<run>\state.json
```

Verify (exit code 0 only when nothing infected is found):
```powershell
.\Expiro-Remover.ps1 -Mode Verify
```

Repair infected Windows components after remediation (elevated; uses Windows Update unless
`-Source <install.wim>` of verified media is given):
```powershell
.\Repair-WindowsComponents.ps1 -StateFile C:\ProgramData\ExpiroRemover\reports\<run>\state.json
```

## Quarantine format

`<QuarantineDir>\<sha256-16>_<name>.gsmq` = the 8 bytes `GSMQ\x01\0\0\0` followed by the file content
XOR `0xA5`. The stored file has no `MZ` header and a non-executable extension, so it cannot run even
if renamed. `-Mode Undo` reverses it. This matches GSM Shield's `engine/quarantine.js`.

## Limitations

- **No pre-execution blocking.** Without a kernel driver the tool cannot stop a file from running;
  it detects and quarantines after the fact. Keep Microsoft Defender (with Tamper Protection) on.
- **No in-place repair.** Infected files are quarantined or replaced from a clean source.
- **Protected OS files** (System32, WinSxS, DriverStore, WindowsApps) are never deleted; their
  services are disabled and repair is delegated to DISM/SFC or an in-place upgrade.
- **Archives** (.zip/.rar/.7z/.tar/.iso) are not opened; scan them with Defender.
- A future Expiro build that keeps relocations and section flags intact would evade the structural
  rule; the tool complements, and does not replace, a maintained AV engine.

## License / sharing

Intended for open-source release alongside the GSM Shield project. It ships no malware samples; the
research folder keeps infected samples out of version control (`.gitignore: research/samples/`).
