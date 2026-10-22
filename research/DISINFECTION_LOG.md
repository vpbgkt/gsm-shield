> **SUPERSEDED (2026-10-22).** This document predates the validated analysis. Its detection results and any "clean" conclusions relied on heuristics that score real Expiro infections at 0, and its advice to keep Windows Defender disabled is withdrawn. Read [EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md), [EXPIRO_TECHNICAL_REFERENCE.md](EXPIRO_TECHNICAL_REFERENCE.md) and [DISINFECTION_PROCEDURE.md](DISINFECTION_PROCEDURE.md) first.

# Win32/Expiro.EK!MTB - Disinfection Experiment Log

**Purpose:** Chronicle all disinfection attempts with detailed methodology and results  
**Status:** Pre-Disinfection Phase  
**Last Updated:** 2026-10-03  

---

## 📋 Log Entry Template

```markdown
### Attempt #XXX - [Brief Description]
**Date:** YYYY-MM-DD HH:MM UTC
**Sample:** EXPI-XXX
**Method:** [Description of approach]
**Tools:** [List of tools used]

#### Procedure
1. [Step 1]
2. [Step 2]
3. [...]

#### Results
- Success: [YES/NO/PARTIAL]
- File Executable: [YES/NO]
- File Functional: [YES/NO/UNKNOWN]
- Side Effects: [Any issues observed]

#### Analysis
[What worked, what didn't, lessons learned]

#### Next Steps
[What to try next based on results]
```

---

## 🧪 Disinfection Attempts

### Attempt #000 - Baseline Test (Planned)
**Date:** [To be scheduled]  
**Sample:** EXPI-001  
**Method:** Manual hex editing - Remove added section  
**Tools:** HxD, PE Tools  

#### Procedure (Planned)
1. Open infected file in hex editor
2. Locate added viral section
3. Delete section bytes
4. Update PE header section count
5. Recalculate file size in header
6. Update entry point to original value
7. Recalculate checksum

#### Expected Outcome
- **Hypothesis:** Manual removal may work for simple infections
- **Risk:** File may be non-functional if OEP not correctly restored
- **Validation:** Compare with clean version hash

---

## 🛠️ Disinfection Methodologies

### Method 1: Manual PE Repair
**Complexity:** HIGH  
**Success Rate:** UNKNOWN  
**Prerequisites:** Deep PE format knowledge, hex editor expertise

**Steps:**
1. Parse PE header manually
2. Identify viral section by characteristics
3. Remove section from section table
4. Zero out section bytes or truncate file
5. Restore original entry point
6. Fix PE checksum

**Pros:**
- Full control over process
- Can handle unique variants
- Educational value

**Cons:**
- Error-prone
- Time-consuming
- Requires expertise

---

### Method 2: Automated Disinfection Script
**Complexity:** MEDIUM  
**Success Rate:** UNKNOWN  
**Prerequisites:** Python, pefile library

**Conceptual Code:**
```python
import pefile

def disinfect_expiro(file_path, output_path):
    """
    Automated Expiro disinfection attempt
    """
    # Load PE file
    pe = pefile.PE(file_path)
    
    # Step 1: Identify viral section
    viral_section = None
    for section in pe.sections:
        section_name = section.Name.decode().rstrip('\x00')
        if section_name in ['.expiro', '.virus'] or \
           section.Characteristics & 0x20000000:  # CODE + EXECUTE
            viral_section = section
            break
    
    if not viral_section:
        print("Viral section not found - may not be Expiro")
        return False
    
    # Step 2: Attempt to find original entry point
    # (This is the hard part - requires reverse engineering)
    original_ep = find_original_entry_point(pe, viral_section)
    
    if not original_ep:
        print("Could not locate original entry point")
        return False
    
    # Step 3: Restore entry point
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = original_ep
    
    # Step 4: Remove viral section
    pe.sections.remove(viral_section)
    pe.FILE_HEADER.NumberOfSections -= 1
    
    # Step 5: Write cleaned file
    pe.write(output_path)
    
    return True

def find_original_entry_point(pe, viral_section):
    """
    Heuristic search for original entry point
    This is the research challenge - needs reverse engineering
    """
    # Strategy 1: Look for stored OEP in viral section
    # Strategy 2: Pattern matching for OEP finder code
    # Strategy 3: Execution trace analysis
    
    # To be implemented based on sample analysis
    pass
```

**Development Status:** NOT STARTED  
**Next Steps:** Requires sample analysis first

---

### Method 3: Emulation & OEP Detection
**Complexity:** VERY HIGH  
**Success Rate:** UNKNOWN  
**Prerequisites:** Unicorn Engine, Capstone disassembler

**Approach:**
1. Emulate execution from infected entry point
2. Trace all jumps and calls
3. Detect transition to original code (heuristics)
4. Capture OEP address
5. Use OEP for Method 2

**Challenges:**
- Anti-emulation techniques
- Complex decryption routines
- Accurate emulation environment

---

### Method 4: Signature-Based Section Removal
**Complexity:** MEDIUM  
**Success Rate:** LOW (too simplistic)  
**Prerequisites:** Pattern database

**Approach:**
1. Build database of Expiro section signatures
2. Scan file for known patterns
3. Remove matched sections
4. Hope OEP is predictable

**Why It May Fail:**
- Polymorphic engine changes signatures
- OEP restoration still required
- May damage legitimate code

---

## 📊 Success Metrics

### File Integrity Checks
After each disinfection attempt:

```powershell
# 1. File executability
Test-Path $DisinfectedFile
& $DisinfectedFile  # Does it run?

# 2. Hash comparison (if clean version available)
$cleanHash = (Get-FileHash clean.exe).Hash
$curedHash = (Get-FileHash cured.exe).Hash
if ($cleanHash -eq $curedHash) {
    Write-Host "PERFECT DISINFECTION - Hashes match!"
}

# 3. Functional testing
# Does the application work as expected?

# 4. Re-scan with AV
# Is it still detected as infected?
```

---

## 🎯 Milestones

- [ ] **Milestone 1:** Successfully identify viral section in 1 sample
- [ ] **Milestone 2:** Locate original entry point in 1 sample
- [ ] **Milestone 3:** Create functional disinfected file (even if different hash)
- [ ] **Milestone 4:** Achieve perfect disinfection (matching clean hash)
- [ ] **Milestone 5:** Automate disinfection for multiple samples
- [ ] **Milestone 6:** Integrate disinfection into GSM Shield AV

---

## 🧬 Research Findings

### Finding #001: [To Be Documented]
**Date:** [TBD]  
**Description:** [Observations from attempts]  
**Impact:** [How this affects disinfection strategy]  

---

## 🚫 Failed Approaches

Document what DOESN'T work to save time:

### Failed Approach #001: [Example]
**Method:** [Description]  
**Why It Failed:** [Root cause]  
**Lesson Learned:** [Takeaway]  

---

## ✅ Successful Approaches

Document what WORKS:

### Success #001: [When we get one!]
**Method:** [Description]  
**Sample:** EXPI-XXX  
**Reproducibility:** [Can it work on other samples?]  
**Documentation:** [Detailed steps]  

---

## 🔄 Iteration Strategy

### Current Iteration: 0
**Focus:** Sample collection and static analysis  
**Goal:** Understand infection mechanism  
**Timeline:** 1-2 days  

### Next Iteration: 1 (Planned)
**Focus:** Manual disinfection of first sample  
**Goal:** Proof of concept  
**Timeline:** TBD  

---

## 📈 Progress Tracker

```
Phase 1: Sample Collection        [####------] 40%
Phase 2: Static Analysis          [----------]  0%
Phase 3: Dynamic Analysis         [----------]  0%
Phase 4: Disinfection Development [----------]  0%
Phase 5: Testing & Validation     [----------]  0%
Phase 6: Automation               [----------]  0%
```

---

## 💡 Ideas to Explore

Brainstorming section for potential approaches:

1. **Differential Analysis**
   - Compare infected with clean version byte-by-byte
   - Identify exact modification points
   - Reverse modifications

2. **Memory Dumping**
   - Let virus decrypt itself in memory
   - Dump clean code from memory
   - Rebuild PE file

3. **API Hooking**
   - Hook file write operations
   - Intercept infection attempt
   - Reverse-engineer OEP storage mechanism

4. **Generic Unpacker**
   - Treat Expiro like a packer
   - Use generic unpacking techniques
   - May work for OEP detection

5. **Machine Learning**
   - Train model on clean vs infected sections
   - Classify sections as legitimate or viral
   - Automate section removal

---

## ⚠️ Critical Warnings

**Before Any Disinfection Attempt:**
- [ ] Backup original infected file
- [ ] Work on a copy, never the original
- [ ] Verify you have clean reference version
- [ ] Document file hashes before/after
- [ ] Test in isolated environment first

**Never Attempt On:**
- System-critical files without backup
- Files currently in use
- Only copy of a file
- Production system files

---

## 📞 Emergency Recovery

**If Disinfection Breaks a Critical File:**

```powershell
# Option 1: Restore from backup
Copy-Item "backup\original-infected.exe" "C:\Path\To\File.exe"

# Option 2: System file restore (Windows files only)
sfc /scannow

# Option 3: System restore point
rstrui.exe

# Option 4: Reinstall application
# Option 5: Restore from Windows.old if available
```

---

**Document Version:** 1.0  
**Last Updated:** 2026-10-03  
**Next Review:** After first disinfection attempt
