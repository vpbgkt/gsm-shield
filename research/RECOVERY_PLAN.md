# Win32/Expiro.EK!MTB - Emergency Recovery Plan

**Purpose:** Step-by-step procedures for system recovery if disinfection fails  
**Criticality:** HIGH - Have this ready before attempting any remediation  
**Last Updated:** 2026-10-03  

---

## 🚨 When to Use This Document

Activate emergency recovery if:
- System becomes unbootable
- Critical system files are corrupted beyond repair
- Disinfection attempts cause cascading failures
- Windows core functionality breaks (Explorer, Task Manager, etc.)
- You cannot complete the disinfection safely

---

## 📋 Pre-Flight Checklist

**Complete BEFORE attempting any disinfection:**

### Essential Backups
- [ ] **System Restore Point Created**
  ```powershell
  Checkpoint-Computer -Description "Pre-Expiro-Cleanup" -RestorePointType "MODIFY_SETTINGS"
  ```

- [ ] **Critical Data Backed Up**
  - Documents folder
  - Desktop files
  - Project files (C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield\)
  - Browser bookmarks/passwords
  - Email data (if local)

- [ ] **Windows Installation Media Ready**
  - USB bootable drive OR
  - Windows ISO downloaded OR
  - Recovery partition verified functional

- [ ] **Important Software Installers Available**
  - Essential applications you need
  - License keys documented
  - Configuration files backed up

### Safety Net Verification
```powershell
# Verify restore point exists
Get-ComputerRestorePoint | Select-Object -First 1

# Check free space for backup
Get-Volume C | Select-Object DriveLetter, SizeRemaining

# Test Safe Mode boot (reboot required)
bcdedit /set {default} safeboot minimal
# Then reboot, verify it works, then:
bcdedit /deletevalue {default} safeboot
```

---

## 🛟 Recovery Methods (In Order of Preference)

### Level 1: System Restore (PREFERRED)
**Use When:** System is bootable but unstable  
**Data Loss:** Minimal (recent installs/updates lost)  
**Time Required:** 15-30 minutes  

#### Procedure
1. **Boot to Safe Mode**
   ```
   Settings → Update & Security → Recovery → Advanced Startup → Restart Now
   → Troubleshoot → Advanced Options → Startup Settings → Restart
   → Press F4 for Safe Mode
   ```

2. **Run System Restore**
   ```
   Start → Type "rstrui" → Enter
   → Select "Pre-Expiro-Cleanup" restore point
   → Confirm and wait for restoration
   ```

3. **Verify System Health**
   ```powershell
   # After reboot, run:
   sfc /scannow
   DISM /Online /Cleanup-Image /RestoreHealth
   ```

4. **Re-enable Protection**
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $false
   ```

---

### Level 2: System File Checker + DISM
**Use When:** Specific system files corrupted but OS boots  
**Data Loss:** None  
**Time Required:** 30-60 minutes  

#### Procedure
```powershell
# Step 1: Repair Windows image
DISM /Online /Cleanup-Image /RestoreHealth

# Step 2: Repair system files
sfc /scannow

# Step 3: Check results
Get-Content $env:windir\Logs\CBS\CBS.log | Select-String -Pattern "corrupt"

# Step 4: If specific files listed, restore from Windows media
# Example:
Copy-Item "E:\Windows\System32\corrupt-file.dll" "C:\Windows\System32\" -Force
```

---

### Level 3: In-Place Upgrade (Repair Install)
**Use When:** System boots but many files corrupted  
**Data Loss:** None (apps/files preserved)  
**Time Required:** 1-2 hours  

#### Requirements
- Windows 10/11 ISO matching your version
- Mount ISO or create bootable USB

#### Procedure
1. **Mount Windows ISO**
   ```powershell
   Mount-DiskImage -ImagePath "C:\Path\To\Windows.iso"
   ```

2. **Run Setup**
   ```
   Open mounted drive → Run setup.exe
   → Choose "Upgrade this PC now"
   → Select "Keep personal files and apps"
   → Follow wizard
   ```

3. **Advantages**
   - Replaces all system files
   - Keeps your applications
   - Keeps your data
   - Often fixes Expiro-damaged files

---

### Level 4: Clean Windows Reinstall
**Use When:** All else fails, system unrecoverable  
**Data Loss:** All applications, system settings  
**Time Required:** 2-4 hours + reinstall time  

#### Pre-Reinstall Data Rescue
If system won't boot, use a Linux live USB:

1. **Boot Ubuntu Live USB**
2. **Mount Windows partition**
   ```bash
   sudo mount /dev/sda2 /mnt  # Adjust device as needed
   ```
3. **Copy critical data to external drive**
   ```bash
   cp -r /mnt/Users/CLOUD\ ENGINEER/Desktop /media/backup/
   cp -r /mnt/Users/CLOUD\ ENGINEER/Documents /media/backup/
   ```

#### Clean Install Procedure
```
1. Boot from Windows installation media
2. Select "Install Now"
3. Choose "Custom: Install Windows only (advanced)"
4. Select partition (WARNING: Will erase it)
5. Format partition
6. Install Windows
7. Complete OOBE (Out of Box Experience)
8. Install drivers
9. Restore data from backup
10. Reinstall applications
```

---

## 🔧 Partial Recovery Scenarios

### Scenario A: Windows Won't Boot (Safe Mode Works)
```
1. Boot to Safe Mode
2. Run System Restore
3. If no restore point: Run startup repair
   Troubleshoot → Advanced Options → Startup Repair
```

### Scenario B: Windows Won't Boot (Safe Mode Fails)
```
1. Boot from Windows installation media
2. Repair your computer → Troubleshoot → Advanced Options
3. Try: Startup Repair
4. If fails: System Restore
5. If fails: Command Prompt recovery (see below)
```

### Scenario C: Specific Application Broken
```
1. Uninstall corrupted application
2. Download fresh installer
3. Reinstall (virus won't infect new install if removed)
```

### Scenario D: Explorer.exe Won't Run
```
1. Ctrl+Alt+Del → Task Manager
2. File → Run new task
3. Type: cmd.exe (check "Create with admin privileges")
4. In command prompt:
   sfc /scannow
   # Then restart
```

---

## 🛠️ Command Prompt Recovery Tools

If you boot to recovery environment command prompt:

### Check Disk for Errors
```batch
chkdsk C: /F /R
```

### Rebuild Boot Files
```batch
bootrec /fixmbr
bootrec /fixboot
bootrec /scanos
bootrec /rebuildbcd
```

### Manual System Restore
```batch
rstrui.exe
```

### Copy Files from Windows.old (if exists)
```batch
robocopy C:\Windows.old\Windows\System32 C:\Windows\System32 *.* /E /XO
```

---

## 📦 Critical Files to Preserve

### Before Any Risky Operation, Backup:

**GSM Shield AV Project:**
```
C:\Users\CLOUD ENGINEER\Desktop\premium-vibe\gsm-shield\
```

**Database:**
```
%APPDATA%\GSMShieldAV\gsm-shield.db
```

**Research Files:**
```
[Project]\research\*.md
```

**Configuration:**
```
%APPDATA%\GSMShieldAV\*.json
```

**Quarantined Files (for analysis):**
```
%APPDATA%\GSMShieldAV\quarantine\
```

---

## 🔄 Post-Recovery Checklist

After recovering the system:

- [ ] Verify Windows boots normally
- [ ] Test critical applications (browser, file explorer)
- [ ] Check for remaining infections
  ```powershell
  # Run GSM Shield full scan
  # OR use Windows Defender offline scan
  ```
- [ ] Restore backed-up data
- [ ] Reinstall necessary applications
- [ ] Change all passwords (in case keylogger was present)
- [ ] Enable Windows Update
- [ ] Create new system restore point
- [ ] Document what worked for future reference

---

## 🎯 Prevention After Recovery

**To Prevent Reinfection:**

1. **Update Virus Definitions**
   ```powershell
   Update-MpSignature -UpdateSource MicrosoftUpdateServer
   ```

2. **Enable Real-Time Protection**
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $false
   ```

3. **Scan All External Media**
   - USB drives
   - External hard drives
   - Network shares

4. **Identify Initial Infection Vector**
   - Downloaded file?
   - USB drive?
   - Email attachment?
   - **Block that vector**

5. **Install GSM Shield with Real-Time Protection**
   - Our AV now has working real-time monitoring
   - Will catch Expiro during file modification

---

## 🆘 Emergency Contacts

**If You Need Help:**

1. **Windows Recovery Assistant:**
   ```
   Settings → Update & Security → Troubleshoot → Additional troubleshooters
   ```

2. **Microsoft Support:**
   - https://support.microsoft.com/contactus
   - 1-800-MICROSOFT (US)

3. **Community Help:**
   - r/techsupport on Reddit
   - Bleeping Computer forums
   - Ten Forums Windows support

4. **Professional Help:**
   - Local computer repair shop
   - Remote tech support services
   - Consider if critical data at stake

---

## 📝 Recovery Log Template

**Document each recovery attempt:**

```markdown
## Recovery Attempt - [Date]

### System State Before
- Bootable: YES/NO
- Safe Mode: YES/NO
- Symptoms: [Description]

### Method Used
- Level: [1/2/3/4]
- Procedure: [Which steps followed]

### Outcome
- Success: YES/NO/PARTIAL
- Time Taken: [Duration]
- Issues Encountered: [Problems]

### Data Lost
- [List any data lost]

### Lessons Learned
- [What to do differently next time]
```

---

## ⚠️ Worst Case Scenario

**If All Recovery Methods Fail:**

1. **Accept the data loss**
2. **Perform clean Windows installation**
3. **Restore data from external backups only**
4. **Scan restored data before use**
5. **Rebuild system from scratch**
6. **Learn from the experience**

**Remember:** Data can be recreated, time cannot. If recovery takes longer than reinstallation, choose reinstallation.

---

## 🔐 Post-Incident Security Hardening

After recovery:

1. **Enable BitLocker** (encrypt drive)
2. **Use Standard user account** (not Admin)
3. **Enable Windows Defender Application Guard**
4. **Configure Controlled Folder Access**
5. **Set aggressive Windows Defender settings**
6. **Regular backups** (3-2-1 rule: 3 copies, 2 media types, 1 offsite)

---

**Document Version:** 1.0  
**Last Updated:** 2026-10-03  
**Status:** Ready for use if needed
