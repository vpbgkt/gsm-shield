> **SUPERSEDED (2026-10-22).** This document predates the validated analysis. Its detection results and any "clean" conclusions relied on heuristics that score real Expiro infections at 0, and its advice to keep Windows Defender disabled is withdrawn. Read [EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md), [EXPIRO_TECHNICAL_REFERENCE.md](EXPIRO_TECHNICAL_REFERENCE.md) and [DISINFECTION_PROCEDURE.md](DISINFECTION_PROCEDURE.md) first.

# PE Analysis Tools - Quick Reference Guide

**Purpose:** Guide to tools for analyzing and disinfecting Win32/Expiro  
**Audience:** Researchers with basic Windows/PE knowledge  
**Last Updated:** 2026-10-03  

---

## 🛠️ Tool Categories

### Free Tools (Recommended)
- ✅ **Readily available**
- ✅ **No license required**
- ✅ **Good for learning**

### Commercial Tools (Optional)
- ⚠️ **May require purchase**
- ⚠️ **Advanced features**
- ⚠️ **Overkill for this project**

---

## 📦 Essential Tool Suite

### 1. HxD Hex Editor (FREE)
**Purpose:** View and edit files at byte level  
**Download:** https://mh-nexus.de/en/hxd/  
**Use Cases:**
- View PE file structure in hex
- Identify viral code sections
- Manual file repair (advanced)

**Basic Usage:**
```
1. Open infected file in HxD
2. View → Data Inspector (shows header info)
3. Search → Find (search for hex patterns)
4. Edit → carefully (make backups first!)
```

**For Expiro Analysis:**
```
1. Open infected .exe
2. Navigate to PE header (offset 0x3C shows PE offset)
3. Find section table (after optional header)
4. Look for suspicious sections (.expiro, high entropy)
5. Compare section count with clean version
```

---

### 2. CFF Explorer (FREE)
**Purpose:** PE file structure viewer and editor  
**Download:** https://ntcore.com/?page_id=388  
**Use Cases:**
- View PE headers visually
- See section tables
- Modify entry points
- Fix checksums

**Basic Usage:**
```
File → Open → Select infected.exe
Left sidebar shows:
  - DOS Header
  - NT Headers
  - File Header
  - Optional Header ← Entry Point here!
  - Sections ← Look for viral sections
  - Import Directory
  - Resource Editor
```

**For Expiro Analysis:**
```
1. Load infected file
2. Check "Optional Header" → Address of Entry Point
3. Compare with clean version (should differ)
4. Check "Sections" → count (infected has extra section)
5. Note viral section characteristics (high entropy, execute flag)
```

**Disinfection Use:**
```
1. Identify original entry point (requires analysis)
2. Optional Header → AddressOfEntryPoint → Edit
3. Sections → Right-click viral section → Delete
4. File Header → NumberOfSections → Decrement
5. Misc. → Recalculate PE Checksum
6. Save (work on copies!)
```

---

### 3. PE-bear (FREE)
**Purpose:** Modern PE viewer with excellent interface  
**Download:** https://github.com/hasherezade/pe-bear-releases  
**Use Cases:**
- Quick PE inspection
- Section analysis
- Import/export viewing
- Resource browsing

**Advantages over CFF:**
- More modern UI
- Better section visualization
- Entropy visualization (detect encryption)

**For Expiro Analysis:**
```
1. Load infected file
2. Section Hdrs tab → view all sections
3. Color coding shows:
   - Green: Code sections
   - Blue: Data sections
   - Red: Unusual/suspicious
4. Entropy column → high entropy = encryption
```

---

### 4. PEiD (FREE, Legacy)
**Purpose:** Packer/compiler detection  
**Download:** Archive sites (no longer maintained)  
**Use Cases:**
- Identify packers/protectors
- Quick file fingerprinting
- Plugin extensible

**For Expiro:**
```
1. Load file
2. May show "Expiro" or "Unknown packer"
3. Gives hints about infection presence
4. Not reliable for polymorphic variants
```

---

### 5. Detect It Easy (DiE) (FREE)
**Purpose:** Modern PEiD replacement  
**Download:** https://github.com/horsicq/Detect-It-Easy  
**Use Cases:**
- Better packer detection
- Actively maintained
- Cross-platform

**For Expiro:**
```
1. Drag file onto DiE
2. Check results
3. May identify compiler, protector, or infection
4. Useful for fingerprinting
```

---

## 🔍 Analysis Tools

### 6. Ghidra (FREE)
**Purpose:** Disassembler and decompiler  
**Download:** https://ghidra-sre.org/  
**Use Cases:**
- Reverse engineering viral code
- Understanding decryption routines
- Finding original entry point

**Learning Curve:** STEEP (but worth it)

**Basic Workflow:**
```
1. Create new project
2. Import infected .exe
3. Analyze → Auto Analysis
4. Navigate to entry point (Address field)
5. View → Decompile (converts assembly to C-like code)
6. Look for:
   - Decryption loops (XOR operations)
   - Jump to OEP (unconditional jump to code section)
   - API calls (CreateFile, WriteFile = infection code)
```

**For Expiro:**
```
1. Start at infected entry point
2. Follow execution flow (step through jumps)
3. Identify decryption routine (usually XOR loop)
4. Find jump to original code (target = original EP)
5. Document OEP address for disinfection
```

---

### 7. IDA Pro (COMMERCIAL - expensive)
**Purpose:** Industry-standard disassembler  
**Alternative:** Ghidra (free and almost as good)  
**Use Cases:**
- Professional malware analysis
- Advanced debugging
- Plugin ecosystem

**For Expiro:** Ghidra is sufficient, save your money.

---

### 8. x64dbg (FREE)
**Purpose:** Native Windows debugger  
**Download:** https://x64dbg.com/  
**Use Cases:**
- Step-by-step execution analysis
- Memory dumping
- API call tracing

**Basic Usage:**
```
1. File → Open → infected.exe
2. Set breakpoint at entry point (F2)
3. Run (F9)
4. Step over (F8) or step into (F7)
5. Watch registers change
6. Dump memory when needed
```

**For Expiro:**
```
1. Load infected file
2. Break at entry point
3. Step through decryption routine
4. Watch for jump to .text section (original code)
5. Dump decrypted memory before jump
6. That address = original entry point!
```

**⚠️ WARNING:** Debugging EXECUTES the virus! Only in isolated environment!

---

### 9. Sysinternals Suite (FREE)
**Purpose:** Windows system utilities  
**Download:** https://docs.microsoft.com/en-us/sysinternals/  
**Tools for Expiro:**

**Process Explorer:**
- View running processes
- See loaded DLLs
- Check for suspicious processes

**Process Monitor:**
- Monitor file system access
- See registry changes
- Track network connections
- **Use Case:** Run infected .exe in sandbox, watch what it does

**Autoruns:**
- View startup programs
- Check for persistence mechanisms
- Disable malicious entries

---

## 🧪 Sandboxing & Testing

### 10. Windows Sandbox (BUILT-IN, Windows 10 Pro+)
**Purpose:** Isolated environment for testing  
**Enable:**
```
Control Panel → Programs → Turn Windows features on/off
→ Check "Windows Sandbox" → Restart
```

**Use:**
```
1. Start → Windows Sandbox
2. Copy infected file into sandbox
3. Execute and observe
4. Close sandbox (everything resets)
```

**Perfect for:** Testing infected executables safely

---

### 11. VirusTotal (ONLINE, FREE)
**Purpose:** Multi-engine scanning  
**Website:** https://www.virustotal.com/  
**Use Cases:**
- Check if file is known malware
- See how many AVs detect it
- View community comments
- Get file hashes

**For Expiro:**
```
1. Upload infected sample
2. Check detection results
3. Read community comments
4. Look at "Details" tab for PE info
5. Check "Behavior" tab for dynamic analysis
```

**⚠️ Privacy Note:** Samples shared with security community

---

### 12. Hybrid Analysis (ONLINE, FREE tier)
**Purpose:** Automated sandbox analysis  
**Website:** https://www.hybrid-analysis.com/  
**Use Cases:**
- Automated behavioral analysis
- See file modifications
- View network traffic
- Get detailed reports

**For Expiro:**
```
1. Upload sample
2. Select Windows environment
3. Wait for analysis
4. Review:
   - Files created/modified
   - Registry changes
   - Network connections
   - Screenshots of execution
```

---

## 🐍 Python Tools for Automation

### 13. pefile (Python Library)
**Purpose:** Parse PE files programmatically  
**Install:** `pip install pefile`  
**Use Cases:**
- Automated PE analysis
- Batch file inspection
- Custom disinfection scripts

**Example Script:**
```python
import pefile

# Load PE file
pe = pefile.PE('infected.exe')

# Print entry point
print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")

# List sections
for section in pe.sections:
    name = section.Name.decode().rstrip('\x00')
    size = section.SizeOfRawData
    entropy = section.get_entropy()
    print(f"Section: {name}, Size: {size}, Entropy: {entropy:.2f}")

# High entropy (>7) suggests encryption
# Look for sections with execute permissions + high entropy
```

**For Expiro Detection:**
```python
def detect_expiro(file_path):
    pe = pefile.PE(file_path)
    
    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')
        entropy = section.get_entropy()
        
        # Heuristic: viral section often has high entropy
        if entropy > 7.0 and section.Characteristics & 0x20000000:
            print(f"Suspicious section: {name} (Entropy: {entropy:.2f})")
            return True
    
    return False
```

---

### 14. YARA (FREE)
**Purpose:** Pattern matching for malware  
**Download:** https://github.com/VirusTotal/yara  
**Use Cases:**
- Create signatures for Expiro variants
- Scan directories for infected files
- Automated detection

**Example Rule:**
```yara
rule Expiro_Generic {
    meta:
        description = "Detects Win32/Expiro file infector"
        author = "CLOUD ENGINEER"
        date = "2026-10-03"
    
    strings:
        $section = ".expiro" ascii
        $mz = "MZ" ascii
        $pe = "PE\x00\x00" ascii
        
        // Add specific byte patterns after analysis
        $pattern1 = { 55 8B EC 83 C4 F0 }  // Example: function prologue
        
    condition:
        $mz at 0 and
        $pe and
        ($section or $pattern1)
}
```

**Usage:**
```powershell
yara rules.yar infected_file.exe
yara -r rules.yar C:\Windows\System32\  # Recursive scan
```

---

## 📊 Comparison & Diffing Tools

### 15. WinMerge / Beyond Compare
**Purpose:** Compare infected vs clean files  
**Use Cases:**
- Byte-level file comparison
- Identify exact modification points
- Spot differences in PE structure

**For Expiro:**
```
1. Get clean version of infected file
2. Open both in comparison tool
3. Look for:
   - Added sections
   - Modified entry point
   - Code cave abuse
```

---

## 🔧 Custom Tool Development

### 16. Expiro Disinfector (TO BE DEVELOPED)
**Language:** Python  
**Dependencies:** pefile, yara  
**Purpose:** Automated disinfection

**Planned Features:**
```python
# expiro_disinfector.py

class ExpiroDisinfector:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = pefile.PE(file_path)
    
    def detect(self):
        """Check if file is infected with Expiro"""
        pass
    
    def find_viral_section(self):
        """Identify the viral code section"""
        pass
    
    def locate_original_entry_point(self):
        """Reverse-engineer to find OEP"""
        pass
    
    def remove_infection(self):
        """Remove viral code and restore original state"""
        pass
    
    def verify(self):
        """Verify disinfection success"""
        pass
```

---

## 📝 Tool Usage Workflow

### Analysis Workflow
```
1. HxD → Quick hex view, check if PE file is intact
2. CFF Explorer → View PE structure, identify viral section
3. PE-bear → Check entropy of sections (detect encryption)
4. VirusTotal → Confirm infection, check detection names
5. Ghidra → Disassemble, understand infection mechanism
6. x64dbg → Debug (in sandbox!), trace to OEP
7. Python + pefile → Automate analysis for multiple samples
```

### Disinfection Workflow
```
1. Backup original file
2. Analyze with tools above
3. Identify:
   - Viral section location
   - Original entry point
   - File modifications
4. Use CFF Explorer:
   - Delete viral section
   - Restore entry point
   - Fix section count
   - Recalculate checksum
5. Verify with comparison tool
6. Test execution in sandbox
7. Scan with AV to confirm clean
```

---

## ⚠️ Safety Reminders

1. **NEVER** execute infected files on production system
2. **ALWAYS** work on copies
3. **USE** sandboxes for dynamic analysis
4. **BACKUP** before any file modification
5. **VERIFY** disinfection success before deploying

---

## 🎓 Learning Resources

### PE Format
- Malware Unicorn PE101
- Microsoft PE Documentation
- Corkami PE visual posters

### Malware Analysis
- Practical Malware Analysis (book)
- Malware Analysis Tutorials by OALabs
- MalwareTech blog

### Reverse Engineering
- OpenSecurityTraining courses
- Ghidra beginner tutorials
- x64dbg documentation

---

**Document Version:** 1.0  
**Last Updated:** 2026-10-03  
**Next Update:** After tool testing with actual samples
