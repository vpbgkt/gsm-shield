# How to Build the GSM Shield AV Installer

## Quick Start

### Option 1: Build Everything (Recommended)
```powershell
node scripts/build.js
```
This runs all 3 stages:
1. **Stage 1**: Builds React UI with Vite → `renderer/dist/`
2. **Stage 2**: Packages with Electron Builder → `dist/win-unpacked/`
3. **Stage 3**: Creates installer with Inno Setup → `dist/installer/GSMShieldAV-Setup.exe`

### Option 2: Build Individual Stages
```powershell
# Build only the renderer
node scripts/build.js --stage1

# Package only with Electron Builder
node scripts/build.js --stage2

# Create installer only (requires Stage 2 to be done first)
node scripts/build.js --stage3
```

---

## Prerequisites

### 1. Node.js Dependencies
Already installed ✅

### 2. **Inno Setup 6** (REQUIRED for Stage 3 - Installer Creation)

**If you don't have Inno Setup installed:**

1. Download from: https://jrsoftware.org/isinfo.php
2. Run the installer
3. During installation, make sure to check "Add to PATH" option
4. After installation, open a NEW PowerShell window and verify:
   ```powershell
   iscc
   ```
   Should show: `Inno Setup 6 Command-Line Compiler`

**If Stage 3 is skipped:**
- You'll see a warning: `iscc was not found on PATH`
- Stages 1 & 2 will complete successfully
- You can still run the app from `dist/win-unpacked/GSM Shield AV.exe`
- You just won't have the installer EXE

---

## Where to Find Build Outputs

### After Stage 1 (React Build)
```
renderer/dist/
├── index.html
├── assets/
│   ├── index-[hash].js
│   └── index-[hash].css
└── ...
```

### After Stage 2 (Electron Package)
```
dist/win-unpacked/
├── GSM Shield AV.exe          ← Main executable (you can run this!)
├── resources/
│   ├── app.asar              ← Packaged application code
│   ├── clamav/               ← ClamAV binaries (unpacked)
│   │   ├── clamscan.exe
│   │   ├── freshclam.exe
│   │   ├── main.cvd
│   │   └── daily.cvd
│   └── scripts/              ← PowerShell scripts (unpacked)
│       ├── disable-defender.ps1
│       ├── register-wsc.ps1
│       └── restore-defender.ps1
├── locales/
├── [many DLL files]
└── ...
```

**You can test the app directly from here without creating the installer!**

### After Stage 3 (Installer)
```
dist/installer/
└── GSMShieldAV-Setup.exe     ← Final installer (this is what you distribute!)
```

---

## Testing Without Building Installer

If you want to test the app without creating an installer:

```powershell
# Development mode (hot reload)
npm run dev

# OR run the packaged version after Stage 2
cd dist/win-unpacked
./GSM Shield AV.exe
```

---

## Common Issues

### Issue 1: `iscc` not found
**Symptom**: Stage 3 is skipped with warning message

**Solution**: 
- Install Inno Setup 6 from https://jrsoftware.org/isinfo.php
- Make sure it's added to PATH
- Close and reopen PowerShell
- Run `node scripts/build.js --stage3` again

**Workaround if not in PATH**:
If Inno Setup is installed but not in PATH, run it directly:
```powershell
& "C:\Program Files (x86)\Inno Setup 6\iscc.exe" "installer\setup.iss"
```

### Issue 2: ClamAV binaries missing
**Symptom**: App launches but scanning doesn't work

**Solution**: 
- Ensure `assets/clamav/` folder contains:
  - `clamscan.exe`
  - `freshclam.exe`
  - `main.cvd`
  - `daily.cvd`
- These must be obtained separately (ClamAV Windows binaries)

### Issue 3: renderer/dist/ not found
**Symptom**: Stage 2 fails

**Solution**: 
- Run Stage 1 first: `node scripts/build.js --stage1`
- Or run all stages together: `node scripts/build.js`

### Issue 4: License file missing
**Symptom**: Inno Setup fails with "license.txt not found"

**Solution**: 
- Create `installer/license.txt` with your license agreement text
- Or comment out the line `LicenseFile=license.txt` in `installer/setup.iss`

---

## What Each Stage Does

### Stage 1: React Renderer Build
- **Tool**: Vite
- **Input**: `renderer/src/` (React + TypeScript)
- **Output**: `renderer/dist/` (optimized HTML, JS, CSS bundles)
- **Time**: ~10-20 seconds

### Stage 2: Electron Packaging
- **Tool**: Electron Builder
- **Input**: Electron main process + renderer/dist/
- **Output**: `dist/win-unpacked/` (runnable Windows app)
- **Creates**: ASAR archive with app code
- **Unpacks**: ClamAV binaries and PowerShell scripts (they must remain unpacked)
- **Time**: ~30-60 seconds

### Stage 3: Installer Creation
- **Tool**: Inno Setup 6
- **Input**: `dist/win-unpacked/` directory
- **Output**: `dist/installer/GSMShieldAV-Setup.exe`
- **Creates**: Single-file installer with wizard
- **Includes**: Uninstaller that restores Windows Defender
- **Time**: ~5-10 seconds

---

## Installer Features

When users run `GSMShieldAV-Setup.exe`, they get:

1. **Welcome Screen** - with app name and version
2. **License Agreement** - must accept to continue
3. **Installation Folder Selection** - defaults to `C:\Program Files\GSMShieldAV`
4. **Desktop Shortcut** - optional checkbox (checked by default)
5. **Installation Progress** - copies all files
6. **Completion Screen** - option to launch app immediately

### What the Installer Does
- Copies all app files to Program Files
- Creates Start Menu shortcuts
- Optionally creates Desktop shortcut
- Registers in Windows Programs list
- Requires Administrator privileges (for Defender replacement)

### What the Uninstaller Does
- Stops and removes the background service
- Runs `restore-defender.ps1` to re-enable Windows Defender
- Removes all registry entries
- Deletes installation files
- **Prompts** to optionally delete user data in AppData

---

## File Size Expectations

| Component | Approximate Size |
|-----------|-----------------|
| renderer/dist/ | ~2 MB |
| dist/win-unpacked/ | ~150-200 MB |
| GSMShieldAV-Setup.exe | ~100-150 MB (compressed) |

*Sizes depend on ClamAV binaries and virus definitions*

---

## Distribution

Once you have `dist/installer/GSMShieldAV-Setup.exe`:

1. **Test it first** on a clean VM or test machine
2. **Sign the installer** (optional but recommended for production)
3. **Upload to your distribution server**
4. **Provide download link** to users

Users only need to:
1. Download `GSMShieldAV-Setup.exe`
2. Right-click → "Run as Administrator"
3. Follow the wizard
4. Launch the app

---

## Next Steps After Building

### Before Distribution:
- [ ] Test installer on clean Windows 10/11 machine
- [ ] Verify Windows Defender is replaced successfully
- [ ] Test all scan modes work correctly
- [ ] Verify ClamAV definitions are included
- [ ] Test license activation
- [ ] Test uninstaller restores Defender correctly

### For Production:
- [ ] Replace placeholder hashes in `whitelist/seed-data.js` with real GSM tool hashes
- [ ] Obtain ClamAV Windows binaries and place in `assets/clamav/`
- [ ] Create `installer/license.txt` with your EULA
- [ ] Update version number in `package.json`
- [ ] Consider code signing the installer for Windows SmartScreen
- [ ] Deploy backend to Railway.app
- [ ] Set up Keygen.sh license keys

---

## Quick Reference

```powershell
# Full build (all 3 stages)
node scripts/build.js

# Run packaged app (without installer)
.\dist\win-unpacked\GSM Shield AV.exe

# Run installer
.\dist\installer\GSMShieldAV-Setup.exe

# Clean build (remove all build artifacts)
Remove-Item -Recurse -Force dist, renderer/dist

# Development mode
npm run dev
```

---

**Need Help?** Check `TESTING_GUIDE.md` for manual testing procedures after building.
