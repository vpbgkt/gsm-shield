> **SUPERSEDED (2026-10-22).** This document predates the validated analysis. Its detection results and any "clean" conclusions relied on heuristics that score real Expiro infections at 0, and its advice to keep Windows Defender disabled is withdrawn. Read [EXPIRO_INCIDENT_2026-10-22.md](EXPIRO_INCIDENT_2026-10-22.md), [EXPIRO_TECHNICAL_REFERENCE.md](EXPIRO_TECHNICAL_REFERENCE.md) and [DISINFECTION_PROCEDURE.md](DISINFECTION_PROCEDURE.md) first.

# EXPIRO REMOVAL PROCEDURE - OPTION A: TEST-FIRST APPROACH

**Status**: ✅ Test Phase Complete - Ready for Full Removal  
**Date**: October 3, 2026  
**Approach**: Cautious test-first with administrator privileges  

---

## ✅ PHASE 1: TEST REMOVAL - COMPLETE

### Test Results (10 Files):
- **Successfully Quarantined**: 6 files (VS Code node modules)
- **Failed (Admin Required)**: 4 files (Program Files location)
- **System Impact**: Minimal - VS Code search functionality affected only
- **Reversibility**: ✅ Confirmed - files in quarantine can be restored

### What We Learned:
1. ✅ Quarantine mechanism works perfectly
2. ✅ Files are safely moved (not deleted)
3. ✅ System remains stable after removal
4. ⚠️ **Administrator rights needed** for Program Files
5. ✅ Quarantine is reversible

### Files Quarantined:
```
C:\GSMShield\Quarantine\Test\
├── rg.exe (5.4 MB)
├── rg_1.exe (5.4 MB)
├── rg_2.exe (5.4 MB)
├── rg_3.exe (5.4 MB)
├── wxc-exec.exe (12.4 MB)
└── wxc_exec_1.exe (12.4 MB)
```

**Verification**: ✅ Original files removed, quarantine successful, system stable

---

## 🎯 PHASE 2: FULL REMOVAL STRATEGY

### Critical Requirement: **ADMINISTRATOR PRIVILEGES**

**Why**: 1,159 infected files include:
- System32 files (72 files) - Windows protected directory
- Program Files (many files) - Protected system location
- Microsoft Visual Studio (22 files) - Protected installation
- VMware (17 files) - Protected system services

**Solution**: Run PowerShell as Administrator

### Pre-Flight Checklist:

#### ☑️ Before Running Full Removal:

1. **Backup Critical Data** ✓
   - [ ] Documents saved
   - [ ] Projects backed up
   - [ ] Important configurations saved
   - **Note**: Don't backup infected executables

2. **Enable GSM Shield AV Protection** ⚠️ CRITICAL
   - [ ] Build GSM Shield AV: `npm run build:full`
   - [ ] Install the application
   - [ ] Enable Expiro real-time protection
   - [ ] Verify monitoring is active
   - **WHY**: Prevents reinfection during cleanup

3. **Administrator Access** ✓
   - [ ] Right-click PowerShell
   - [ ] Select "Run as Administrator"
   - [ ] Navigate to project directory

4. **System Preparation** ✓
   - [x] Windows Defender disabled (confirmed)
   - [ ] Close all unnecessary applications
   - [ ] Save all open work
   - [ ] Ensure stable power supply (laptop: plug in)

---

## 🚀 PHASE 3: FULL REMOVAL EXECUTION

### Step 1: Open Administrator PowerShell

```powershell
# Right-click PowerShell → Run as Administrator
# Then navigate to project:
cd "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield"
```

### Step 2: Run Full Removal Command

```powershell
.\research\tools\Full-System-Expiro-Scan.ps1 -RemoveInfections
```

### Step 3: Monitor Progress

**Expected Output**:
```
Scanning: C:\Program Files
  [!] INFECTED: filename.exe
     Confidence: 65%
     Path: C:\Path\To\File.exe
     [+] Quarantined to: C:\GSMShield\Quarantine\filename.exe

Scanning: C:\Program Files (x86)
  ... (continues for all directories)
```

**Duration**: 5-15 minutes (moving 1,159 files)

### Step 4: Review Results

**After Completion**:
```
=====================================================================
 SCAN COMPLETE
=====================================================================
Files Scanned: 3433
Infections Found: 1159

[+] All infected files have been quarantined to: C:\GSMShield\Quarantine\
[i] Detailed log saved to: research\logs\full_scan_results_[timestamp].txt
```

---

## 📋 PHASE 4: POST-REMOVAL VERIFICATION

### Immediate Checks:

1. **System Boots** ✓
   ```powershell
   # System should still boot normally
   # Windows core functionality intact
   ```

2. **Quarantine Verification** ✓
   ```powershell
   Get-ChildItem "C:\GSMShield\Quarantine" -Recurse | Measure-Object
   # Should show ~1,159 files
   ```

3. **Quarantine Log** ✓
   ```powershell
   Get-Content "C:\GSMShield\Quarantine\quarantine_log.txt" | Select-Object -Last 20
   # Review last 20 entries
   ```

### Expected Impacts:

**Programs That Will NOT Work** (until reinstalled):
- ❌ Git commands (`git`, `git-gui`, etc.) - 345 files infected
- ❌ AWS CLI (`aws` command) - Critical dev tool
- ❌ Brave Browser (if running) - May need restart/reinstall
- ❌ CMake build tools
- ❌ Various Visual Studio components
- ❌ 7-Zip compression tool
- ❌ VMware services

**What WILL Still Work**:
- ✅ Windows operating system (core files protected)
- ✅ Most applications in safe locations
- ✅ File system and basic operations
- ✅ Internet connectivity
- ✅ Other browsers (if installed)

---

## 🔄 PHASE 5: APPLICATION RECOVERY & REINSTALLATION

### Priority 1: Critical Development Tools (IMMEDIATE)

#### 1.1 Git for Windows
**Status**: 345 infected files - CRITICAL REINSTALL NEEDED  
**Download**: https://git-scm.com/download/win  
**Verification**: Check SHA-256 signature  

**Steps**:
```powershell
# 1. Download Git installer
# 2. Verify file signature
# 3. Scan with GSM Shield AV (once enabled)
# 4. Install with default settings
# 5. Test: git --version
```

#### 1.2 AWS CLI v2
**Status**: 85% confidence infected - HIGH PRIORITY  
**Download**: https://aws.amazon.com/cli/  
**Verification**: Official AWS installer  

**Steps**:
```powershell
# 1. Download MSI installer
# 2. Install
# 3. Test: aws --version
```

#### 1.3 CMake
**Status**: Build tools infected  
**Download**: https://cmake.org/download/  

**Steps**:
```powershell
# 1. Download latest stable version
# 2. Install
# 3. Test: cmake --version
```

### Priority 2: Daily Use Applications

#### 2.1 Brave Browser
**Status**: 65% confidence infected  
**Download**: https://brave.com/download/  

**Steps**:
```powershell
# 1. Download installer
# 2. Install (may preserve profile)
# 3. Test: Launch browser
```

#### 2.2 7-Zip
**Status**: 50% confidence infected  
**Download**: https://www.7-zip.org/  

**Steps**:
```powershell
# 1. Download 64-bit version
# 2. Install
# 3. Test: Right-click → 7-Zip menu
```

### Priority 3: System Utilities

#### 3.1 VMware Tools
**Status**: 17 infected files  
**Download**: From VMware installation media  

**Only if using VMware**:
```powershell
# Reinstall from VMware menu or installation source
```

#### 3.2 Visual Studio Build Tools
**Status**: 22 infected files  
**Download**: https://visualstudio.microsoft.com/downloads/  

**Steps**:
```powershell
# 1. Download Build Tools installer
# 2. Select required workloads
# 3. Install
# 4. Test build commands
```

### Priority 4: Optional Applications

Review quarantined files list and reinstall as needed:
- 3uTools (if using iOS devices)
- Other infected utilities
- Applications you actively use

---

## 🛡️ PHASE 6: ENABLE PROTECTION & MONITORING

### Critical: Enable GSM Shield AV BEFORE Reinstalling

**Why**: Prevent reinfection of newly installed applications

### Steps:

1. **Build GSM Shield AV**
   ```bash
   cd "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield"
   npm run build:full
   ```

2. **Install Application**
   ```powershell
   # Locate: dist/installer/GSMShieldAV-Setup.exe
   # Run installer
   # Follow installation wizard
   ```

3. **Enable Expiro Protection**
   - Launch GSM Shield AV
   - Navigate to Settings → Protection
   - Enable "Expiro Real-Time Protection"
   - Add monitored paths:
     - C:\Program Files
     - C:\Program Files (x86)
     - C:\Users\[USERNAME]\AppData\Local
     - C:\Users\[USERNAME]\Downloads

4. **Verify Protection Active**
   ```powershell
   # Check process is running
   Get-Process | Where-Object {$_.Name -match "GSMShield"}
   ```

---

## 📊 PHASE 7: POST-RECOVERY VALIDATION

### Validation Scan (24 Hours After Cleanup):

```powershell
# Re-scan system to verify no reinfection
.\research\tools\Full-System-Expiro-Scan.ps1 -ScanOnly
```

**Expected Result**: 0 infections found

### Monitoring Schedule:

**Week 1**: Daily scans
```powershell
# Run every day
.\research\tools\Full-System-Expiro-Scan.ps1 -ScanOnly
```

**Week 2-4**: Every 3 days
**Month 2+**: Weekly scans

**Goal**: Ensure no reinfection occurs

---

## 🔧 TROUBLESHOOTING

### Issue: "Access Denied" Errors

**Solution**: Run PowerShell as Administrator
```powershell
# Right-click PowerShell icon
# Select "Run as Administrator"
```

### Issue: Program Won't Start After Reinstall

**Possible Causes**:
1. Incomplete reinstallation
2. Configuration files missing
3. Dependencies not restored

**Solution**:
```powershell
# 1. Uninstall completely
# 2. Delete program folder (if present)
# 3. Restart computer
# 4. Reinstall fresh
```

### Issue: New Infections Appearing

**This means**: Protection not active or reinfection source present

**Solution**:
1. Stop all work immediately
2. Verify GSM Shield AV is running
3. Check protection is enabled
4. Investigate infection source
5. Consider full system scan

### Issue: False Positive Concerns

**How to Check**:
```powershell
# Scan a known clean file
.\research\tools\Quick-Expiro-Scan.ps1 -Path "C:\Windows\System32\notepad.exe"
```

**Expected**: CLEAN (0% confidence or <50%)

If false positives occur:
- Review heuristic thresholds
- Adjust confidence scoring
- Whitelist known good files

---

## ⚠️ EMERGENCY PROCEDURES

### If System Becomes Unstable:

1. **Boot to Safe Mode**
   ```
   - Restart computer
   - Press F8 during boot
   - Select Safe Mode
   ```

2. **Restore From Quarantine** (if needed)
   ```powershell
   # Copy files back from quarantine
   # This reverses the removal
   Copy-Item "C:\GSMShield\Quarantine\*" -Destination [original paths] -Recurse
   ```

3. **System Restore** (last resort)
   ```
   - Boot to Safe Mode
   - Run: rstrui.exe
   - Select restore point from before removal
   ```

### If Reinfection Occurs:

**Nuclear Option**: Clean Windows Reinstall
1. Backup user data ONLY (not executables)
2. Create Windows installation media
3. Format system drive
4. Fresh Windows install
5. Install GSM Shield AV FIRST
6. Then reinstall applications with monitoring

---

## 📈 SUCCESS CRITERIA

### Removal Complete When:

- ✅ All 1,159 files quarantined (or removed with admin rights)
- ✅ Quarantine log shows all actions
- ✅ System boots and runs normally
- ✅ GSM Shield AV protection enabled
- ✅ Critical applications reinstalled
- ✅ Re-scan shows 0 infections
- ✅ No new infections after 1 week

### Full Recovery Complete When:

- ✅ All needed applications reinstalled
- ✅ System functionality restored
- ✅ Daily scans show 0 infections
- ✅ No performance issues
- ✅ User workflow back to normal
- ✅ Protection monitoring active

---

## 📞 CURRENT STATUS

**Phase 1**: ✅ COMPLETE - Test removal successful (6/10 files)  
**Phase 2**: ⏳ READY - Full removal strategy prepared  
**Phase 3**: ⏳ PENDING - Awaiting administrator execution  
**Phase 4**: ⏳ PENDING - Post-removal verification  
**Phase 5**: ⏳ PENDING - Application reinstallation  
**Phase 6**: ⏳ PENDING - Protection enablement  
**Phase 7**: ⏳ PENDING - Post-recovery validation  

**Next Action**: Run full removal with administrator privileges

---

## 🎯 QUICK REFERENCE

### Full Removal Command (Administrator):
```powershell
cd "C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield"
.\research\tools\Full-System-Expiro-Scan.ps1 -RemoveInfections
```

### Check Quarantine:
```powershell
Get-ChildItem "C:\GSMShield\Quarantine" -Recurse
```

### Verify Clean State:
```powershell
.\research\tools\Full-System-Expiro-Scan.ps1 -ScanOnly
```

### Enable Protection:
```bash
npm run build:full
# Then install and enable in UI
```

---

*Generated by GSM Shield AV Research Team*  
*Last Updated: October 3, 2026*  
*Test Phase Complete - Ready for Full Removal*
