# Win32/Expiro Research - Quick Reference Card

**Print this or keep it visible while working**

---

## 🚨 EMERGENCY COMMANDS

### If System Becomes Unstable
```powershell
# Immediate restore
rstrui.exe
```

### If You Need to Abort
```powershell
# Re-enable Defender
Set-MpPreference -DisableRealtimeMonitoring $false

# Restart Windows Update
Set-Service wuauserv -StartupType Automatic
Start-Service wuauserv
```

---

## ⚡ CRITICAL DO'S AND DON'TS

### ❌ NEVER DO:
- Run Defender full scan
- Delete infected files manually
- Reboot without saving work
- Execute .exe files without scanning
- Work without backups

### ✅ ALWAYS DO:
- Work on copies, not originals
- Document every observation
- Backup before any change
- Verify file hashes
- Test in sandbox first

---

## 📋 DAILY WORKFLOW CHECKLIST

### Starting Work Session
- [ ] Verify restore point exists
- [ ] Check backup integrity
- [ ] Review previous session notes
- [ ] Set session goals

### During Research
- [ ] Document findings immediately
- [ ] Save work frequently
- [ ] Test hypotheses systematically
- [ ] Take breaks (clear mind = better analysis)

### Ending Work Session
- [ ] Save all analysis notes
- [ ] Update progress tracker
- [ ] Backup new findings
- [ ] Plan next session goals

---

## 🔍 ANALYSIS QUICK STEPS

### Identify Infected File
```powershell
# Scan with GSM Shield or check manually
# Look for:
#   - Unusual file size increase
#   - Recent modification date
#   - Defender detection
```

### Collect Sample
```powershell
Copy-Item "C:\Path\To\Infected.exe" "research\samples\infected\EXPI-001.exe"
```

### Quick PE Check
```
1. Open in CFF Explorer
2. Check section count (infected has extra)
3. Note entry point value
4. Check for .expiro or suspicious section
```

### Document Sample
```markdown
Edit: EXPIRO_SAMPLES.md
Add entry with:
  - Sample ID
  - Original path
  - File size (before/after)
  - Detection date
  - Initial observations
```

---

## 🛠️ ESSENTIAL TOOLS

### Quick Analysis
- **CFF Explorer** - PE structure viewer
- **HxD** - Hex editor
- **PE-bear** - Section analysis with entropy

### Deep Analysis  
- **Ghidra** - Disassembler (free)
- **x64dbg** - Debugger (⚠️ sandbox only!)
- **VirusTotal** - Online multi-scanner

### Automation
- **Python + pefile** - Batch analysis
- **YARA** - Pattern matching

---

## 📊 FILE SIZE PATTERN

```
Original Size   | Typical Increase
----------------|------------------
< 100 KB        | +40-60 KB
100-500 KB      | +60-100 KB  
> 500 KB        | +80-150 KB
```
*Update as you gather data*

---

## 🔐 HASH VERIFICATION

### Before Modification
```powershell
$hash = (Get-FileHash file.exe -Algorithm SHA256).Hash
Write-Host $hash
# SAVE THIS HASH!
```

### After Modification
```powershell
$newHash = (Get-FileHash file.exe -Algorithm SHA256).Hash
if ($hash -eq $newHash) {
    Write-Host "SUCCESS: File unchanged" -ForegroundColor Green
} else {
    Write-Host "MODIFIED: Hashes differ" -ForegroundColor Yellow
}
```

---

## 🎯 MILESTONES TRACKER

Quick status check:

```
[X] Documentation created
[X] Workspace setup
[ ] Containment complete
[ ] First sample collected
[ ] Static analysis complete
[ ] OEP located in sample
[ ] Test disinfection works
[ ] Full system cleaned
[ ] Prevention implemented
```

---

## 📞 HELP RESOURCES

### Internal
- README.md - Navigation
- IMMEDIATE_ACTIONS.md - Containment
- RECOVERY_PLAN.md - Emergency
- PE_TOOLS_GUIDE.md - Tool help

### External
- VirusTotal.com - Sample analysis
- Hybrid-Analysis.com - Sandbox
- r/malware - Community help
- BleepingComputer - Forums

---

## 💾 BACKUP CHECKLIST

### Before Risky Operations
- [ ] System restore point created
- [ ] Original file copied to backups/
- [ ] Current research saved
- [ ] File hashes documented

### Daily Backup
- [ ] research/ folder backed up
- [ ] New samples copied to external drive
- [ ] Analysis notes saved
- [ ] Progress documented

---

## 🧪 EXPERIMENT LOG FORMAT

```markdown
### Attempt #XXX - [Description]
Date: YYYY-MM-DD HH:MM
Sample: EXPI-XXX
Method: [What you tried]

Result: SUCCESS/FAIL/PARTIAL
Notes: [What happened]
Next: [What to try next]
```

---

## 🔄 PROGRESS REPORTING

### Daily Update
```markdown
Date: YYYY-MM-DD
Phase: [Current phase]
Time Spent: [Hours]

Completed:
- [Task 1]
- [Task 2]

Blockers:
- [Issue if any]

Tomorrow:
- [Next goals]
```

---

## ⚠️ WARNING SIGNS

### Stop Research If:
- System won't boot to Safe Mode
- Critical applications won't run
- Multiple system files corrupted
- Out of restore points
- Too much time investment

**Action:** Follow RECOVERY_PLAN.md

---

## 🎓 LEARNING GOALS

Track your progress:

```
PE Format:           [####------] 40%
Static Analysis:     [##--------] 20%
Dynamic Analysis:    [----------]  0%
Reverse Engineering: [----------]  0%
Disinfection:        [----------]  0%
Tool Development:    [----------]  0%
```

---

## 📈 TIME ESTIMATES

```
Activity              | Est. Time
----------------------|-----------
Containment           | 1 hour
Sample collection     | 2-4 hours
Static analysis       | 1-2 days
Dynamic analysis      | 1-2 days
Disinfection dev      | 2-5 days
Testing               | 1-2 days
System cleanup        | 1 day
Documentation         | Ongoing
```

---

## 🔢 SAMPLE COUNTER

```
Samples Collected:    0 / 10
Samples Analyzed:     0 / 10
Successful Cures:     0 / 10
Failed Attempts:      0
```

---

## 🎯 TODAY'S FOCUS

**Write your daily goal here:**

```
Today I will:
1. [Primary goal]
2. [Secondary goal]
3. [Stretch goal]

Success = [Define success for today]
```

---

## 💡 QUICK TIPS

1. **Take Notes Immediately** - Memory fades fast
2. **One Change at a Time** - Isolate variables
3. **Compare with Clean** - Always have reference
4. **Test Non-Critical First** - Don't risk system files
5. **Ask for Help** - Community is helpful
6. **Take Breaks** - Fresh eyes spot more
7. **Celebrate Wins** - Even small progress counts
8. **Stay Curious** - This is fascinating stuff!

---

**Keep this handy while researching!**

*Last Updated: 2026-10-03*
