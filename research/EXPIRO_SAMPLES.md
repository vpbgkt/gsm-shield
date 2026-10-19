# Win32/Expiro.EK!MTB - Sample Collection & Analysis

**Purpose:** Document infected file samples for research and disinfection development  
**Status:** Sample Collection Phase  
**Last Updated:** 2026-10-03  

---

## 📦 Sample Collection Protocol

### Collection Guidelines
1. **Identification:** Use GSM Shield AV or ClamAV to identify infected files
2. **Isolation:** Copy infected files to quarantine/research directory
3. **Documentation:** Record file hash, size, location, and infection timestamp
4. **Backup:** Keep original location path for restoration after disinfection
5. **Safety:** NEVER execute samples directly; use sandboxed environment

### Sample Naming Convention
```
EXPI-[NUMBER]-[ORIGINAL_NAME]-[HASH_FIRST8].exe

Example:
EXPI-001-notepad-A3F2B8C1.exe
EXPI-002-calc-D4E9F1A2.exe
```

---

## 🗂️ Sample Registry

### Sample #001
```yaml
Sample ID: EXPI-001
Status: [ ] Collected [ ] Analyzed [ ] Disinfected [ ] Restored
Original Name: [TBD]
Original Path: [TBD]
Original Size: [TBD] bytes
Infected Size: [TBD] bytes
Size Increase: [TBD] bytes
MD5 Hash: [TBD]
SHA256 Hash: [TBD]
Detection Date: [TBD]
Collection Date: [TBD]

File Header Analysis:
  PE Signature: [TBD]
  Entry Point (Original): [TBD]
  Entry Point (Infected): [TBD]
  New Section Name: [TBD]
  Section Characteristics: [TBD]

Notes:
  - [Add observations here]
```

### Sample #002
```yaml
Sample ID: EXPI-002
Status: [ ] Collected [ ] Analyzed [ ] Disinfected [ ] Restored
[Template - copy from Sample #001]
```

### Sample #003
```yaml
Sample ID: EXPI-003
Status: [ ] Collected [ ] Analyzed [ ] Disinfected [ ] Restored
[Template - copy from Sample #001]
```

---

## 🔍 Analysis Methodology

### Static Analysis Checklist
For each sample, perform:

- [ ] **PE Header Examination**
  - Compare section table with known clean version
  - Identify added/modified sections
  - Note entry point changes
  
- [ ] **Section Analysis**
  - Map section names (.text, .data, .rsrc, .expiro?, etc.)
  - Calculate entropy of each section (high entropy = encryption)
  - Look for code caves or padding abuse
  
- [ ] **Strings Extraction**
  - Search for API calls (CreateFile, WriteFile, VirtualAlloc)
  - Look for embedded URLs or C2 communication
  - Identify debug strings or artifacts
  
- [ ] **Import Table Analysis**
  - Compare with clean version
  - Note any new imports (especially kernel32, ntdll)
  - Check for import address table hooking
  
- [ ] **Code Pattern Recognition**
  - Identify decryption loops
  - Locate original entry point (OEP) finder routine
  - Document polymorphic stub structure

### Dynamic Analysis Checklist
**⚠️ ONLY in isolated VM or sandbox**

- [ ] **Execution Monitoring**
  - Process creation/injection
  - File system modifications
  - Registry changes
  - Network activity
  
- [ ] **Debugging Session**
  - Set breakpoint at entry point
  - Step through decryption routine
  - Locate jump to original code
  - Dump decrypted payload
  
- [ ] **API Call Tracing**
  - Monitor CreateFile calls
  - Track memory allocation
  - Log process enumeration

---

## 🧬 Infection Pattern Analysis

### Common Expiro Signatures (To Be Updated)

```
Signature Pattern 1: [Hex bytes to be documented]
Location: Entry point stub
Purpose: Polymorphic decryptor

Signature Pattern 2: [Hex bytes to be documented]
Location: Added section
Purpose: Main viral code

Signature Pattern 3: [Hex bytes to be documented]
Location: Original entry point storage
Purpose: OEP redirect marker
```

### File Size Pattern
```
Original Size Range | Typical Increase | Percentage
--------------------|------------------|------------
< 100 KB           | [TBD]            | [TBD]%
100-500 KB         | [TBD]            | [TBD]%
500 KB - 1 MB      | [TBD]            | [TBD]%
> 1 MB             | [TBD]            | [TBD]%
```

### Section Name Patterns
Known Expiro section names:
- `.expiro`
- `.virus`
- `.packed`
- `.stub`
- `[Random gibberish]`

To be updated as samples are analyzed.

---

## 🧪 Testing Samples (Non-Critical Files)

Safe executables to intentionally infect for controlled testing:

```
File                | Purpose                    | Safe to Lose?
--------------------|----------------------------|---------------
dummy.exe           | Empty PE file for testing  | YES
test_calc.exe       | Copy of calculator         | YES
old_app_v1.exe      | Obsolete application       | YES
```

**Never use these for testing:**
- System files (cmd.exe, explorer.exe, etc.)
- Currently-installed applications
- Files in C:\Windows\System32\

---

## 📊 Comparative Analysis

### Infected vs Clean Comparison

For accurate disinfection, we need clean reference files:

```
File Name       | Clean Hash (SHA256)                              | Clean Size
----------------|--------------------------------------------------|------------
notepad.exe     | [To be collected from clean system]              | [TBD]
calc.exe        | [To be collected from clean system]              | [TBD]
```

**Clean File Sources:**
1. Windows installation media (ISO)
2. Fresh Windows VM
3. Online hash databases (VirusTotal, NSRL)
4. System file checker (sfc /scannow) before infection

---

## 🗃️ Sample Storage Location

```
research/
├── samples/
│   ├── infected/
│   │   ├── EXPI-001-notepad-A3F2B8C1.exe
│   │   ├── EXPI-002-calc-D4E9F1A2.exe
│   │   └── ...
│   ├── clean/
│   │   ├── notepad-clean.exe
│   │   ├── calc-clean.exe
│   │   └── ...
│   └── disinfected/
│       ├── EXPI-001-CURED.exe
│       ├── EXPI-002-CURED.exe
│       └── ...
```

---

## 📝 Analysis Log Template

### Sample Analysis Session
```markdown
Date: [YYYY-MM-DD HH:MM]
Analyst: [Name]
Sample: EXPI-[NUMBER]

## Initial Observations
[Free-form notes]

## Tools Used
- Tool 1: [Purpose]
- Tool 2: [Purpose]

## Key Findings
1. [Finding 1]
2. [Finding 2]

## Hypotheses
- [Theory about infection mechanism]
- [Potential disinfection approach]

## Next Steps
- [ ] [Action item 1]
- [ ] [Action item 2]
```

---

## 🔬 Disassembly Snippets

Document interesting code patterns discovered:

### Pattern 1: Decryption Loop
```assembly
; [To be populated with actual disassembly]
; Location: [Address]
; Purpose: [Description]
```

### Pattern 2: OEP Finder
```assembly
; [To be populated]
```

---

## 📈 Sample Collection Progress

**Target:** 10+ samples covering different file sizes and types  
**Current:** 0 collected  

**Priority Files to Sample:**
1. [ ] Small system utility (< 100KB)
2. [ ] Medium application (100-500KB)
3. [ ] Large application (> 1MB)
4. [ ] .NET executable (if infected differently)
5. [ ] 32-bit executable
6. [ ] 64-bit executable

---

## ⚠️ Safety Reminders

- **NEVER** execute infected samples on production system
- **ALWAYS** work with copies, never originals
- **VERIFY** file hashes before and after any operation
- **DOCUMENT** every modification attempt
- **BACKUP** samples before disinfection attempts

---

**Document Version:** 1.0  
**Last Updated:** 2026-10-03  
**Next Review:** After first sample collection
