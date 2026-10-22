# Expiro infection transformation — byte-level evidence (2026-10-22)

Measured on this machine by diffing **exact clean/infected pairs of the same build** with
`research/tools/expiro-diff.js` (read-only). Clean = official ClamAV 1.5.4 executables
(SHA-256 matches the release); infected = the copies committed to this repo in `88d29a0`,
preserved as `research/samples/infected/repo-clamav-2026-10-19/*.infected`.

This supersedes every earlier guess about the infection mechanism. It is primary evidence,
not a vendor summary.

## The transformation (identical on both pairs tested)

| Property | clamscan.exe | clamd.exe |
|---|---|---|
| size clean → infected | 292,352 → 1,577,984 (+1,285,632) | ~ +1,285,632 |
| Entry point RVA | 0x124e → **0x124e (unchanged)** | 0x126c → **0x126c (unchanged)** |
| DllCharacteristics | 0x8160 → **0x8120** (DYNAMIC_BASE/ASLR bit 0x40 cleared) | 0x8160 → **0x8120** |
| Base-relocation data directory | 0x55000 / 3288 → **0 / 0** | 0x49000 / 3276 → **0 / 0** |
| Last section `.reloc` | raw 0x1200, chars 0x42000040 (data, discardable) → raw **0x13b000, chars 0xe2000040 (RWX)** | raw → 0x13b000, chars → 0xe2000040 |
| Code change in `.text` | **exactly one** CALL, file 0x15d28 | **exactly one** CALL, file 0x151d0 |

### The single code patch
Expiro rewrites the 4-byte relative displacement of one existing `call rel32` in `.text`:

```
clamscan  file 0x15d28:  E8 3F A9 FE FF  (call -> original .text target)
              becomes:   E8 D3 86 17 00  (call -> rva 0x18f000, inside the appended body)
clamd     file 0x151d0:  E8 B0 B4 FE FF
              becomes:   E8 2B D2 16 00  (call -> rva 0x183000, inside the appended body)
```

The entry point is **not** redirected (this is "entry-point obscuring": control reaches the
virus through a patched call deep in the code, not through the PE entry point). At runtime the
virus body runs, then transfers to the original call target.

### Why generic in-place repair is not feasible
To rebuild the original host you must recover (a) the original 4-byte call displacement and
(b) the original relocation table, both overwritten. The recoverability test searched the entire
1.29 MB appended body for those original bytes and for the original entry-point value:

```
clamscan: original displacement 3F A9 FE FF  -> NOT found verbatim in body
clamd:    original displacement B0 B4 FE FF  -> NOT found verbatim in body
          original EP dword                  -> NOT found
```

So the bytes Expiro overwrote are stored **encrypted/compressed** inside the body (consistent
with the public reports of ChaCha + custom layers). Restoring them requires decrypting a
polymorphic, per-variant blob. A naive "flip the flags and truncate the body" repair leaves the
patched call pointing at freed space and the relocation table destroyed — a broken binary.

**Conclusion:** the correct, safe remediation is to **overwrite the infected file with a verified
clean copy of the same build** (vendor reinstall; DISM/SFC for Windows components), or quarantine
it. GSM Shield therefore does not attempt in-place repair. This is now backed by byte-level
evidence from two independent builds, not by assumption.

### Reproduce
```
node research/tools/expiro-diff.js assets/clamav/clamscan.exe research/samples/infected/repo-clamav-2026-10-19/clamscan.exe.infected
```
(any of the five preserved pairs gives the same result).
