# GSM Shield AV - Testing Guide

## ✅ Test Status: ALL PASSING (613/613 tests)

All automated tests have been successfully executed and are passing. This document outlines the testing strategy and provides guidance for manual testing.

---

## 1. Automated Test Coverage

### Test Suite Summary
```
Test Suites: 35 passed
Tests:       613 passed
Duration:    ~27 seconds
```

### Test Types

#### A. Property-Based Tests (PBT) using fast-check v3.x
These tests validate invariants with hundreds of randomly generated inputs:

**Property 1: Whitelist bypass is universal**
- Location: `engine/scanner.property.test.js`
- Validates: Requirements 2.2, 2.3, 7.7, 10.5
- Tests that whitelisted files never invoke ClamAV across all scan modes

**Property 2: User-added entries have correct source and verified flag**
- Location: `whitelist/__tests__/whitelist.property.test.js`
- Validates: Requirement 3.1
- Ensures user entries always have `source='user'` and `verified=0`

**Property 3: Whitelist deduplication**
- Location: `whitelist/__tests__/whitelist.property.test.js`
- Validates: Requirement 3.2
- Tests that duplicate hash insertions are detected and prevented

**Property 4: User-delete is source-scoped**
- Location: `whitelist/__tests__/whitelist.property.test.js`
- Validates: Requirement 3.3
- Ensures bundled/cloud entries cannot be deleted by users

**Property 5: Whitelist search filters correctly**
- Location: `whitelist/__tests__/whitelist.property.test.js`
- Validates: Requirements 3.4, 16.2
- Tests search functionality with arbitrary queries

**Property 6: Cloud upsert preserves user-added entries**
- Location: `whitelist/__tests__/sync.test.js`
- Validates: Requirement 4.2
- Ensures cloud sync never overwrites user entries

**Property 7: Sync timestamp is updated on success**
- Location: `whitelist/__tests__/sync.test.js`
- Validates: Requirement 4.5
- Verifies `last_sync_at` updates after successful sync

**Property 8: SHA-256 hash validation**
- Location: `electron/ipc/__tests__/hash-validator.property.test.js`
- Validates: Requirement 5.4
- Tests hash validator with arbitrary strings

**Property 9: ClamAV output parser correctness**
- Location: `engine/scanner.property.test.js`
- Validates: Requirement 6.3
- Tests parser extracts only FOUND lines from mixed output

**Property 10: Scan record completeness**
- Location: `engine/scanner.property.test.js`
- Validates: Requirement 6.4
- Ensures all 7 required fields are non-null in scan_history

**Property 11: Whitelist cap enforcement under inactive license**
- Location: `whitelist/__tests__/whitelist.property.test.js`
- Validates: Requirements 3.5, 20.3
- Tests user entry count never exceeds 10 without license

**Property 12: Monitor extension filter**
- Location: `monitor/monitor.property.test.js`
- Validates: Requirement 10.2
- Tests file extension filtering logic

**Property 13: Debounce — single invocation per write burst**
- Location: `monitor/monitor.property.test.js`
- Validates: Requirement 10.3
- Ensures scanner called only once after 2s stability

**Property 14: Quarantine path exclusion invariant**
- Location: `monitor/monitor.property.test.js`
- Validates: Requirements 9.2, 10.6
- Tests quarantine directory never watched

**Property 15: Quarantine round trip**
- Location: `engine/quarantine.test.js`
- Validates: Requirements 9.1, 9.3
- Tests quarantine → restore workflow integrity

**Property 16: License grace period boundary**
- Location: `electron/ipc/__tests__/license-grace-period.property.test.js`
- Validates: Requirements 20.2, 20.3
- Tests grace period exactly at 7-day boundary

**Property 17: GET /whitelist returns only verified entries**
- Location: `backend/__tests__/routes.property.test.js`
- Validates: Requirement 24.1
- Tests backend endpoint filtering

**Property 18: POST /submissions inserts with pending status**
- Location: `backend/__tests__/routes.property.test.js`
- Validates: Requirement 24.2
- Tests submission creation logic

**Property 19: Unauthenticated requests are rejected**
- Location: `backend/__tests__/routes.property.test.js`
- Validates: Requirement 24.3
- Tests API key authentication

**Property 20: Watch list empty when real-time protection disabled**
- Location: `monitor/monitor.property.test.js`
- Validates: Requirement 10.8
- Tests monitor disables when protection off

#### B. Unit Tests
Comprehensive coverage of individual module functionality:

- **Database Layer**: Schema creation, migrations, settings seeding
- **Whitelist Subsystem**: Hasher, CRUD operations, checker logic
- **Scan Engine**: ClamAV wrapper, error handling, cancel support
- **Quarantine Module**: Move, restore, delete operations
- **FreshClam Updater**: Definition updates, validation
- **Monitor**: Chokidar watcher, extension filter, debounce
- **License Subsystem**: Machine ID, encrypted storage, Keygen.sh client
- **PowerShell Runner**: Script execution, error handling
- **Tray Manager**: State machine, icon switching
- **IPC Handlers**: All 40+ IPC channels
- **Backend Routes**: Whitelist endpoint, submission validation
- **Zustand Stores**: Derived state, IPC subscriptions

#### C. Integration Tests
End-to-end workflows across multiple modules:

- **Whitelist Handlers**: Full IPC→DB→sync flow
- **Quarantine Handlers**: Complete quarantine lifecycle
- **License Handlers**: Activation→validation→feature gates
- **Keygen.sh Client**: Real API integration (mocked for tests)

#### D. Smoke Tests
Build and packaging verification:

- **Renderer Build**: Vite compilation produces valid artifacts
- **Preload Bridge**: contextBridge exposes all required channels
- **Build Pipeline**: Three-stage build process validation

---

## 2. Running Automated Tests

### Prerequisites
```powershell
# Rebuild native dependencies (required after Node.js version changes)
npm rebuild better-sqlite3
```

### Full Test Suite
```powershell
npm test
```

### Watch Mode (for development)
```powershell
npm test -- --watch
```

### Run Specific Test File
```powershell
npm test -- whitelist/__tests__/whitelist.property.test.js
```

### Run Tests with Coverage
```powershell
npm test -- --coverage
```

---

## 3. Manual Testing Strategy

While automated tests cover most functionality, the following **critical workflows** should be tested manually before release:

### Phase 1: Installation & First Run

**Test 1.1: Clean Installation**
- [x] Run the installer as Administrator
- [x] Verify all wizard steps display correctly
- [ ] Verify desktop shortcut is created (if selected)
- [x] Confirm installation completes without errors

**Test 1.2: Windows Defender Replacement**
- [ ] After first launch, open Windows Security Center
- [ ] Verify "GSM Shield AV" appears as the registered antivirus
- [ ] Verify Windows Defender real-time protection is disabled
- [ ] Check registry entries:
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` = 1
  - `HKLM\SOFTWARE\Microsoft\Security Center\Svc\ProductState` = 266240

**Test 1.3: Database Initialization**
- [ ] Navigate to `%APPDATA%\GSMShieldAV\`
- [ ] Verify `gsm-shield.db` exists
- [ ] Verify `quarantine\` directory exists
- [ ] Check that 20+ pre-built GSM tools are in the whitelist table

**Test 1.4: Tray Icon Behavior**
- [ ] Verify tray icon appears on first launch
- [ ] Right-click tray icon → verify context menu has "Open", "Quick Scan", "Exit"
- [ ] Click "Open" → window appears
- [ ] Click window close (X) → window hides, tray icon remains
- [ ] Click "Exit" from tray → app fully terminates

---

### Phase 2: Core Scanning Functionality

**Test 2.1: Quick Scan**
- [ ] Click "Quick Scan" button on Dashboard or Scanner page
- [ ] Verify progress bar updates
- [ ] Verify current file path displays
- [ ] Verify scan completes without errors
- [ ] Check scan history shows the completed scan

**Test 2.2: Full Scan**
- [ ] Click "Full Scan" button
- [ ] Verify all fixed drives are scanned
- [ ] Test "Cancel" button mid-scan → verify scan stops gracefully
- [ ] Verify scan history shows status as "cancelled"

**Test 2.3: Folder Scan**
- [ ] Click "Folder Scan" → select a folder with mixed files
- [ ] Verify only eligible extensions (`.exe`, `.dll`, `.msi`, `.bat`, etc.) are scanned
- [ ] Verify quarantine folder is excluded from scan

**Test 2.4: File Scan**
- [ ] Click "File Scan" → select a single `.exe` file
- [ ] Verify file is scanned
- [ ] Verify result appears in scan results list

**Test 2.5: Whitelist Bypass (CRITICAL)**
- [ ] Add a known-safe file to the whitelist
- [ ] Run a scan that includes that file
- [ ] Verify ClamAV is **not** invoked for that file (check scan logs or use Process Monitor)
- [ ] Verify whitelisted file does not appear in scan results

**Test 2.6: Threat Detection & Quarantine**
- [ ] Download EICAR test file: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
- [ ] Save as `eicar.com` on Desktop
- [ ] Run Quick Scan
- [ ] Verify threat is detected
- [ ] Verify file is moved to quarantine folder
- [ ] Verify Windows notification appears
- [ ] Verify tray icon turns red/yellow
- [ ] Verify threat appears on Dashboard "Recent Threats" list

---

### Phase 3: Whitelist Management

**Test 3.1: Add User Entry**
- [ ] Go to Whitelist page
- [ ] Click "Add File" → select a `.exe` file
- [ ] Verify file appears in whitelist table with `verified=0` badge
- [ ] Verify entry has `source='user'`
- [ ] Try adding the same file again → verify "already trusted" message

**Test 3.2: Remove User Entry**
- [ ] Select a user-added entry
- [ ] Click "Remove" → verify entry is deleted

**Test 3.3: Remove Bundled Entry (should fail)**
- [ ] Try to remove a bundled GSM tool entry
- [ ] Verify removal is blocked with "forbidden" message

**Test 3.4: Search Functionality**
- [ ] Type "Odin" in the search bar
- [ ] Verify only entries with "Odin" in name or vendor appear
- [ ] Clear search → verify all entries reappear

**Test 3.5: Whitelist Cap (Inactive License)**
- [ ] Without an active license, add 10 user entries
- [ ] Try to add an 11th entry
- [ ] Verify cap message appears prompting license activation

**Test 3.6: Cloud Sync**
- [ ] Click "Sync from Cloud" button
- [ ] Verify progress indicator appears
- [ ] Verify `last_sync_at` timestamp updates after sync
- [ ] Verify new cloud entries appear in table with `source='cloud'` and `verified=1`

**Test 3.7: Community Submission**
- [ ] Click "Submit a Tool" button
- [ ] Fill form: hash (64 hex chars), name, vendor
- [ ] Click Submit
- [ ] Verify "submission pending review" confirmation message

---

### Phase 4: Quarantine Management

**Test 4.1: List Quarantined Files**
- [ ] Go to Quarantine page
- [ ] Verify warning banner is displayed
- [ ] Verify all quarantined files appear in table

**Test 4.2: Restore File**
- [ ] Select a quarantined file where original directory still exists
- [ ] Click "Restore"
- [ ] Verify file returns to original path
- [ ] Verify entry is removed from quarantine table
- [ ] Verify file exists at original path on disk

**Test 4.3: Restore with Missing Original Path**
- [ ] Manually delete the original directory of a quarantined file
- [ ] Click "Restore"
- [ ] Verify folder-picker dialog appears
- [ ] Select alternative destination
- [ ] Verify file is restored to chosen location

**Test 4.4: Delete Permanently**
- [ ] Select a quarantined file
- [ ] Click "Delete Permanently"
- [ ] Verify file is deleted from disk
- [ ] Verify entry is removed from quarantine table
- [ ] Verify file no longer exists in `%APPDATA%\GSMShieldAV\quarantine\`

---

### Phase 5: Real-Time Protection (Monitor)

**Test 5.1: Monitor Enable/Disable**
- [ ] Go to Settings page
- [ ] Toggle "Real-time protection" OFF
- [ ] Verify tray icon turns gray
- [ ] Copy an `.exe` file to Desktop
- [ ] Verify no scan occurs
- [ ] Toggle "Real-time protection" ON
- [ ] Verify tray icon turns green
- [ ] Copy a different `.exe` file to Desktop
- [ ] Verify scan occurs after 2-second debounce

**Test 5.2: Auto-Quarantine**
- [ ] Enable "Auto-quarantine" in Settings
- [ ] Copy EICAR test file to Desktop
- [ ] Wait 2 seconds (debounce delay)
- [ ] Verify threat is automatically moved to quarantine
- [ ] Verify Windows notification appears

**Test 5.3: Custom Monitored Paths**
- [ ] Go to Settings → Monitored Paths
- [ ] Click "Add Path" → select a custom folder
- [ ] Verify path appears in the list
- [ ] Copy an `.exe` file to that folder
- [ ] Verify file is scanned in real-time
- [ ] Click "Remove" on the custom path
- [ ] Verify path is removed from the list

**Test 5.4: Extension Filter**
- [ ] Copy a `.txt` file to monitored directory → verify **no scan**
- [ ] Copy a `.jpg` file → verify **no scan**
- [ ] Copy a `.exe` file → verify **scan occurs**
- [ ] Copy a `.dll` file → verify **scan occurs**

**Test 5.5: Quarantine Directory Exclusion**
- [ ] Verify quarantine folder path is never in the monitored paths list
- [ ] Try to manually add quarantine folder as monitored path
- [ ] Verify it is filtered out and not added

---

### Phase 6: Settings & Configuration

**Test 6.1: Start with Windows**
- [ ] Enable "Start with Windows" toggle
- [ ] Restart the computer
- [ ] Verify GSM Shield AV service starts automatically before login
- [ ] Verify tray icon appears after login
- [ ] Disable toggle → restart → verify service does not start

**Test 6.2: Virus Definition Updates**
- [ ] Go to Settings → Definition Updates section
- [ ] Note current version and last update date
- [ ] Click "Check for Updates"
- [ ] Verify progress indicator appears
- [ ] Verify new version/date appears after successful update
- [ ] Verify scan still works with updated definitions

**Test 6.3: Definition Update Failure Handling**
- [ ] Disconnect from internet
- [ ] Click "Check for Updates"
- [ ] Verify error message is displayed
- [ ] Verify existing definitions are unchanged
- [ ] Verify scanning still works

**Test 6.4: Telemetry Toggle**
- [ ] Toggle "Telemetry" ON/OFF
- [ ] Verify setting is persisted across app restarts

---

### Phase 7: License Management

**Test 7.1: Activate License**
- [ ] Go to License page
- [ ] Note status shows "Inactive"
- [ ] Enter a valid license key
- [ ] Click "Activate"
- [ ] Verify status changes to "Active"
- [ ] Verify expiry date is displayed
- [ ] Verify Machine Fingerprint is shown
- [ ] Verify feature gates are removed:
  - Whitelist cap removed (can add >10 entries)
  - Scan limit removed
  - Real-time protection enabled

**Test 7.2: Invalid License Key**
- [ ] Enter an invalid license key
- [ ] Click "Activate"
- [ ] Verify error message is displayed
- [ ] Verify status remains "Inactive"

**Test 7.3: Grace Period (7 days)**
- [ ] Activate a valid license
- [ ] Disconnect from internet
- [ ] Restart the app within 7 days
- [ ] Verify status shows "Grace" or remains "Active"
- [ ] Verify full functionality is available

**Test 7.4: Grace Period Expired**
- [ ] (Simulate by manually editing `license.enc` file timestamp to >7 days ago)
- [ ] Restart app while offline
- [ ] Verify status changes to "Inactive"
- [ ] Verify feature gates are applied

**Test 7.5: Deactivate License**
- [ ] With an active license, click "Deactivate"
- [ ] Verify status changes to "Inactive"
- [ ] Verify feature gates are re-applied
- [ ] Verify `license.enc` file is deleted

---

### Phase 8: Build & Packaging

**Test 8.1: Three-Stage Build Pipeline**
```powershell
node scripts/build.js
```
- [ ] Verify Stage 1 completes: `renderer/dist/` contains built files
- [ ] Verify Stage 2 completes: `dist/win-unpacked/` directory exists
- [ ] Verify Stage 3 completes: `output/GSMShieldAV-Setup.exe` exists (requires Inno Setup 6)

**Test 8.2: ASAR Integrity**
- [ ] Navigate to `dist/win-unpacked/resources/`
- [ ] Verify `app.asar` exists
- [ ] Verify `clamav/` folder is unpacked (not in ASAR)
- [ ] Verify `scripts/` folder is unpacked (not in ASAR)

**Test 8.3: Keygen.sh Admin Token Security**
```powershell
# Search for admin token patterns in ASAR
npx asar extract dist/win-unpacked/resources/app.asar temp-extract
Select-String -Path temp-extract\* -Pattern "activ-" -Recurse
```
- [ ] Verify **no** admin token patterns appear in output
- [ ] Verify only validation-scoped token usage exists

**Test 8.4: ClamAV Binaries**
- [ ] Navigate to `dist/win-unpacked/resources/clamav/`
- [ ] Verify `clamscan.exe` exists and is >0 KB
- [ ] Verify `freshclam.exe` exists and is >0 KB
- [ ] Verify `main.cvd` exists and is >1 MB
- [ ] Verify `daily.cvd` exists and is >1 MB

**Test 8.5: Installer Execution**
- [ ] Run `output/GSMShieldAV-Setup.exe` as Administrator
- [ ] Verify installer wizard completes
- [ ] Verify app launches successfully after installation

---

### Phase 9: Uninstallation

**Test 9.1: Uninstall Cleanup**
- [ ] Run uninstaller from Control Panel → Programs
- [ ] Verify Windows Defender is re-enabled
- [ ] Verify Windows Security Center no longer lists GSM Shield AV
- [ ] Verify `WinDefend` service is running
- [ ] Verify all registry entries are removed:
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`
  - `HKLM\SOFTWARE\Microsoft\Security Center\Svc` (GSM Shield entries)
- [ ] Verify installation directory is deleted
- [ ] Verify uninstaller prompts to delete AppData folder

**Test 9.2: AppData Retention (optional)**
- [ ] During uninstall, choose "Keep user data"
- [ ] Verify `%APPDATA%\GSMShieldAV\` folder remains
- [ ] Reinstall app
- [ ] Verify whitelist entries are preserved
- [ ] Verify scan history is preserved

---

## 4. Performance Benchmarks

### Expected Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Quick Scan | <30 seconds | Desktop, Downloads, Temp, AppData |
| Full Scan (100GB drive) | <10 minutes | Excluding large media files |
| Whitelist check | <5ms per file | SHA-256 hash + DB lookup |
| Real-time scan trigger | 2 seconds debounce | After file write stabilizes |
| Definition update | <2 minutes | Network-dependent |
| Cloud whitelist sync | <5 seconds | ~1000 entries |
| License validation | <3 seconds | Network-dependent |
| App startup (cold) | <3 seconds | With valid definitions |
| Tray icon state change | <100ms | Instant feedback |

---

## 5. Test Data & Fixtures

### EICAR Test File
Safe malware test file recognized by all antivirus engines:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
Save as `eicar.com` or `eicar.txt` for testing.

### Sample GSM Tools for Whitelist
Real hash values must be collected from actual tool executables:
- Odin3 (Samsung Flash Tool)
- SP Flash Tool (MediaTek)
- Miracle Box
- UFI Box
- Z3X Pro

**Note**: The `whitelist/seed-data.js` currently contains placeholder zero-hashes. Real SHA-256 values must be computed from the actual executables before production release.

---

## 6. Known Test Limitations

### Items NOT Covered by Automated Tests
1. **ClamAV Binary Execution**: Tests mock `child_process.spawn` — real ClamAV execution is manual
2. **PowerShell Script Execution**: Tests mock script calls — real Defender disable/WSC registration is manual
3. **Keygen.sh API**: Integration tests use mocked responses — real API validation is manual
4. **Electron Window Rendering**: Smoke test only verifies build artifacts, not visual rendering
5. **System Tray Icons**: Visual appearance and icon switching are manual
6. **Windows Security Center Registration**: Registry writes and WSC UI reflection are manual
7. **node-windows Service**: Service installation/uninstallation is manual
8. **Inno Setup Installer**: Installer wizard flow is manual

### Test Environment Requirements
- **Windows 10/11**: Required for PowerShell scripts and WSC registration
- **Administrator Privileges**: Required for Defender disable and service registration
- **Internet Connection**: Required for license validation, cloud sync, and definition updates
- **Inno Setup 6**: Required for Stage 3 build (installer compilation)

---

## 7. Continuous Integration Recommendations

### Pre-Commit Hooks
```powershell
# Run tests before every commit
npm test
```

### Pull Request Checks
- All automated tests must pass
- Code coverage must be ≥80% for new code
- Linting must pass (if configured)

### Release Checklist
- [ ] All automated tests passing
- [ ] All Phase 1-9 manual tests completed
- [ ] Build pipeline produces valid installer
- [ ] No Keygen.sh admin token in ASAR
- [ ] ClamAV binaries and definitions bundled
- [ ] Real GSM tool hashes collected and added to seed data
- [ ] Version number updated in `package.json`
- [ ] CHANGELOG.md updated

---

## 8. Debugging Failed Tests

### Common Issues

**Issue: better-sqlite3 module version mismatch**
```
The module was compiled against a different Node.js version
```
**Solution:**
```powershell
npm rebuild better-sqlite3
```

**Issue: Tests timing out**
- Increase Jest timeout in `jest.config.js`:
```js
testTimeout: 30000  // 30 seconds
```

**Issue: Port already in use (backend tests)**
- Kill process using port 3000:
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess | Stop-Process -Force
```

**Issue: Permission denied on quarantine folder**
- Run tests as Administrator (required for some file operations)

---

## 9. Test Maintenance

### Adding New Tests
1. **Property-based tests**: Add to existing `*.property.test.js` files
2. **Unit tests**: Add to `__tests__/` folders alongside the module
3. **Integration tests**: Add to `*.integration.test.js` files
4. **Reference requirements**: Always link tests to requirement IDs in comments

### Updating Tests After Code Changes
- If a requirement changes, search for the requirement ID in test comments
- Update all affected property tests and unit tests
- Re-run full test suite to verify no regressions

---

## 10. Contact & Support

For questions about testing:
- Check this guide first
- Review test comments in source files for requirement traceability
- Consult the Design Document (`design.md`) for architectural context
- Consult the Requirements Document (`requirements.md`) for acceptance criteria

---

**Last Updated**: ${new Date().toISOString().split('T')[0]}
**Test Suite Version**: 1.0.0
**Total Test Coverage**: 613 tests across 35 suites
