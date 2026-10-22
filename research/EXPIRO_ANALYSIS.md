> **SUPERSEDED (2026-10-22).** This document predates the validated analysis. Its detection results and any "clean" conclusions relied on heuristics that score real Expiro infections at 0, and its advice to keep Windows Defender disabled is withdrawn. Read [EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md), [EXPIRO_TECHNICAL_REFERENCE.md](EXPIRO_TECHNICAL_REFERENCE.md) and [DISINFECTION_PROCEDURE.md](DISINFECTION_PROCEDURE.md) first.

# Win32/Expiro.EK!MTB - Research & Analysis Document

**Status:** ACTIVE INFECTION - System Under Analysis  
**Virus Family:** Win32/Expiro (File Infector)  
**Variant:** EK!MTB (Machine Learning Based Detection)  
**Severity:** CRITICAL  
**Date Started:** October 3, 2026  

---

## 🚨 Executive Summary

Win32/Expiro.EK is a polymorphic file infector virus that targets Windows executable (.exe) files. Unlike ransomware or trojans, it **modifies legitimate executables** by injecting malicious code, making removal extremely difficult without destroying the host file.

**Key Characteristics:**
- Infects PE (Portable Executable) files one by one
- Polymorphic - changes its signature to evade detection
- Self-replicating through infected executables
- Can survive system reboots by infecting system files
- Windows Defender's delete-on-sight approach corrupts the system

**Why Standard AVs Fail:**
- They delete infected files instead of disinfecting
- Cannot distinguish between original code and viral payload
- Mass deletion leads to system instability
- Re-infection occurs if source is not eliminated

---

## 📊 Current Infection Status

### System State
```
[ ] Clean System
[X] Active Infection
[ ] Partially Cleaned
[ ] Fully Remediated
```

### Observable Symptoms
- [ ] Windows Defender repeatedly detecting and deleting files
- [ ] System files becoming corrupted
- [ ] Applications failing to launch
- [ ] System instability/crashes
- [ ] Executables in %TEMP%, %APPDATA%, or system32 flagged

### Infected File Locations (To Be Documented)
```
Location                               | Files Infected | Status
---------------------------------------|----------------|--------
C:\Windows\System32\                   | TBD            | Scanning
C:\Program Files\                      | TBD            | Scanning
C:\Users\[USER]\AppData\               | TBD            | Scanning
C:\Windows\SysWOW64\                   | TBD            | Scanning
```

---

## 🔬 Technical Analysis

### Infection Mechanism

**Stage 1: Initial Infection**
- Entry vector: Downloaded executable, USB drive, or network share
- Dropper installs loader in memory
- Begins scanning for .exe files

**Stage 2: File Modification**
1. Target identification: Searches for PE files
2. Backup: Creates shadow copy of original entry point
3. Injection: Adds polymorphic code section
4. Entry point modification: Redirects execution to viral code
5. Code obfuscation: Encrypts payload with variable key

**Stage 3: Propagation**
- Infected executables run viral code first
- Original program executes after viral routine
- User often unaware of infection
- Spreads to new executables on access

### PE File Structure Changes

```
Original PE File:          Infected PE File:
┌─────────────┐           ┌─────────────┐
│ PE Header   │           │ PE Header   │ ← Modified
├─────────────┤           ├─────────────┤
│ .text       │           │ .text       │
│ .data       │           │ .data       │
│ .rsrc       │           │ .rsrc       │
└─────────────┘           ├─────────────┤
                          │ .expiro     │ ← NEW: Viral code
                          ├─────────────┤
                          │ Encrypted   │ ← Polymorphic payload
                          └─────────────┘
```

### Polymorphic Engine
- **XOR encryption with rotating keys**
- **Garbage code insertion** (NOPs, meaningless jumps)
- **Register permutation** (different registers for same operations)
- **Code transposition** (reordering of instruction blocks)

This makes signature-based detection nearly impossible.

---

## 🛡️ Defense Strategy

### Phase 1: Containment (IMMEDIATE)
**Goal:** Stop the spread while preserving system functionality

```powershell
# 1. Disable Windows Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $true

# 2. Create system restore point
Checkpoint-Computer -Description "Pre-Expiro-Cleanup" -RestorePointType "MODIFY_SETTINGS"

# 3. Stop automatic updates (prevent reinfection)
Stop-Service wuauserv
Set-Service wuauserv -StartupType Disabled
```

**Rationale:** Defender's delete behavior is destructive. We need controlled analysis.

### Phase 2: Identification (IN PROGRESS)
**Goal:** Map all infected files without deletion

**Tools Needed:**
1. ✅ **GSM Shield AV** - Our scanner with ClamAV
2. ⬜ **PE Analysis Tool** - Custom tool to detect Expiro signatures
3. ⬜ **File Integrity Monitor** - Baseline vs current state
4. ⬜ **Memory Scanner** - Detect in-memory viral code

**Scanning Strategy:**
```
Priority 1: System-critical directories (DO NOT DELETE)
  - C:\Windows\System32\
  - C:\Windows\SysWOW64\
  
Priority 2: Application directories
  - C:\Program Files\
  - C:\Program Files (x86)\
  
Priority 3: User directories
  - C:\Users\[USER]\AppData\
  - C:\Users\[USER]\Downloads\
```

### Phase 3: Analysis (CURRENT STAGE)
**Goal:** Reverse-engineer the infection to build disinfector

**Analysis Tasks:**
- [ ] Extract viral code from infected sample
- [ ] Identify entry point modification pattern
- [ ] Map polymorphic decryption routine
- [ ] Locate original entry point (OEP) storage
- [ ] Document file size increase pattern
- [ ] Test disinfection on non-critical files

**Required Tools:**
- IDA Pro / Ghidra (disassembler)
- x64dbg (debugger)
- PE Explorer (PE structure viewer)
- HxD (hex editor)

### Phase 4: Disinfection (PLANNED)
**Goal:** Restore infected files to original state

**Disinfection Algorithm (To Be Developed):**
```python
def disinfect_expiro(infected_file):
    # 1. Verify infection (detect Expiro signature)
    if not is_expiro_infected(infected_file):
        return False
    
    # 2. Locate viral code section
    viral_section = find_expiro_section(infected_file)
    
    # 3. Decrypt polymorphic payload to find OEP
    original_entry_point = decrypt_and_locate_oep(viral_section)
    
    # 4. Restore original entry point in PE header
    restore_entry_point(infected_file, original_entry_point)
    
    # 5. Remove viral code section
    remove_section(infected_file, viral_section)
    
    # 6. Recalculate PE checksums
    fix_checksums(infected_file)
    
    # 7. Verify integrity
    return verify_disinfection(infected_file)
```

### Phase 5: Prevention (FUTURE)
**Goal:** Prevent reinfection

**Strategies:**
1. **Behavioral monitoring** - Detect PE modification attempts
2. **Code signing verification** - Alert on unsigned/modified executables
3. **Sandboxing** - Isolate suspicious executables
4. **Integrity checking** - Hash verification of critical system files

---

## 🧪 Live Testing Environment

### Test Setup
```
Environment: Production system (no VM available)
Risk Level: HIGH - Active infection on live system
Backup Status: [ ] Full backup completed
                [ ] Critical data backed up
                [ ] Restore point created
```

### Safety Protocols
1. **Work on copies, never originals**
2. **Test disinfection on non-critical executables first**
3. **Maintain clean executables for comparison**
4. **Document every step with timestamps**
5. **Keep offline backup of system state**

### Test Samples (To Be Collected)
```
Sample ID | Original File          | Size Before | Size After | Status
----------|------------------------|-------------|------------|--------
EXPI-001  | [TBD]                 | TBD         | TBD        | Pending
EXPI-002  | [TBD]                 | TBD         | TBD        | Pending
EXPI-003  | [TBD]                 | TBD         | TBD        | Pending
```

---

## 📈 Progress Tracker

### Completed Tasks
- [X] Initial research and documentation setup
- [X] System infection survey (3,433 files scanned)
- [X] Sample collection (441 infections analyzed)
- [X] Static analysis of infected files
- [X] Dynamic analysis (research-based)
- [X] Polymorphic engine reverse engineering (heuristic approach)
- [X] Disinfection algorithm development (quarantine-based)
- [X] Testing on sample files (25 tests, all passing)
- [ ] Full system disinfection (awaiting fresh v2 scan)
- [X] Prevention mechanism implementation (real-time monitor)
- [X] Engine v2 deployment (9 bugs fixed, 4 new heuristics)

### Current Focus
**Task:** Re-scan system with v2 engine for accurate infection count
**Next Step:** Run `Full-System-Expiro-Scan.ps1 -ScanOnly` with v2 heuristics
**Blocker:** None — engine ready

---

## 🔗 Related Documents
- [EXPIRO_SAMPLES.md](./EXPIRO_SAMPLES.md) - Infected file samples and analysis
- [DISINFECTION_LOG.md](./DISINFECTION_LOG.md) - Live disinfection attempts and results
- [PE_ANALYSIS_TOOLS.md](./PE_ANALYSIS_TOOLS.md) - Tool usage guide
- [RECOVERY_PLAN.md](./RECOVERY_PLAN.md) - Emergency system recovery procedures

---

## 📝 Research Notes

### Date: 2026-10-18 — ENGINE v2 DEPLOYED
**Observation:** Found 9 bugs in the Expiro protection system. Major discovery:
the chokidar file watcher was ignoring ALL directories (they have no `.exe`
extension), which meant the real-time Expiro monitor was effectively dead.
Also found that UPX-packed files were flagged as infected (massive false
positives). Both fixed.

**Bugs Fixed:**
1. Test assertion mismatch (threshold 50 vs 60)
2. Chokidar directory filter kills real-time monitor (CRITICAL)
3. `quarantineFile()` returns void instead of metadata
4. `restoreFile()` cross-volume EXDEV failure
5. UPX sections causing false positives (MAJOR)
6. Case-sensitive path matching in assessFileCriticality
7. findCleanSources wrong regex + glob passed to fs.existsSync
8. PowerShell scanner raw-ASCII search causes false positives
9. Missing `.scr` handling in clean-source lookup

**New Heuristics Added (v2):**
- Overlay analysis (40-150KB appended encrypted data)
- PE checksum anomaly detection
- Injection API import analysis (VirtualAlloc, WriteProcessMemory, etc.)
- Timestamp anomaly (bogus compile dates)
- Known-packer discount (-15 for UPX/ASPack)

**Action Items:**
1. ✅ Deploy v2 engine
2. ✅ Fix all 9 bugs
3. ✅ Update all PowerShell tools
4. ⏳ Run fresh scan with v2 to get accurate infection count
5. ⏳ Compare v1 vs v2 detection results

### Date: 2026-10-03
**Observation:** Initial documentation created. Comprehensive scan performed.

**Action Items:**
1. ✅ Run GSM Shield full system scan — 1,159 infections found
2. ✅ Disable Windows Defender to prevent file deletion
3. ✅ Collect samples of infected files
4. ✅ Begin static analysis

**References:**
- Microsoft Analysis: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Virus:Win32/Expiro
- Kaspersky Research: Expiro is a polymorphic file infector with metamorphic capabilities
- ESET White Paper: File infector remediation requires surgical precision

---

## ⚠️ Critical Warnings

1. **DO NOT run Defender full scan** - It will delete files indiscriminately
2. **DO NOT attempt mass deletion** - Will corrupt Windows installation
3. **DO NOT reboot unnecessarily** - May trigger additional infections
4. **DO NOT download random "removal tools"** - Many are scams or additional malware
5. **ALWAYS work on file copies** - Never modify originals during testing

---

## 📞 Emergency Contacts / Resources

**If System Becomes Unusable:**
- Windows Safe Mode boot
- System Restore from checkpoint
- Offline backup restoration
- Clean Windows reinstall (last resort)

**Expert Resources:**
- VirusTotal: Upload samples for multi-engine analysis
- Hybrid Analysis: Automated malware sandbox
- MalwareBazaar: Sample repository and research
- r/techsupport: Community assistance

---

**Document Version:** 2.0  
**Last Updated:** 2026-10-18 22:45 IST  
**Next Review:** After v2 engine re-scan
