# Design Document — GSM Shield AV

## Overview

GSM Shield AV is a Windows-only antivirus desktop application built with Electron 28. It serves GSM phone-repair technicians who need real malware protection that will not destroy the low-level USB flashing tools their trade depends on. The application ships with ClamAV binaries and a pre-built hash whitelist of 20+ known GSM tools, provides real-time Chokidar-based file monitoring, replaces Windows Defender as the registered antivirus via WSC, and enforces licensing through Keygen.sh.

The product is distributed as a single EXE installer produced by Inno Setup 6. The cloud backend (Node.js + Express + PostgreSQL on Railway.app) serves the centrally verified whitelist and accepts community tool submissions.

### Key Design Decisions

- **Whitelist-first scanning**: SHA-256 hash check against SQLite occurs before any ClamAV invocation, ensuring GSM tools are never fed to the scanner.
- **Bundled ClamAV binaries**: `clamscan.exe`, `freshclam.exe`, and all DLLs are embedded in the installer so no separate AV install is needed.
- **User-space monitoring**: Chokidar runs inside the Electron main process (or background service) rather than a kernel driver, avoiding driver-signing complexity.
- **Encrypted license storage**: AES-256 encrypted file in AppData holds the Keygen.sh validation token; no admin token is ever bundled.
- **PowerShell for Defender replacement**: All Windows Security Center and Defender operations run through PS scripts with `ExecutionPolicy Bypass` from the main process.


---

## Architecture

### Monorepo Layout

```
gsm-shield/
├── electron/                    # Electron main process
│   ├── main.js                  # Entry point, BrowserWindow, app lifecycle
│   ├── ipc/
│   │   ├── scan-handlers.js     # IPC handlers for scan operations
│   │   ├── whitelist-handlers.js
│   │   ├── quarantine-handlers.js
│   │   ├── settings-handlers.js
│   │   ├── license-handlers.js
│   │   └── defender-handlers.js
│   ├── tray-manager.js          # Tray icon, context menu, state machine
│   └── first-run.js             # First-run setup orchestrator
│
├── renderer/                    # Vite + React application (renderer process)
│   ├── index.html
│   ├── src/
│   │   ├── main.jsx             # React entrypoint
│   │   ├── App.jsx              # Router shell + sidebar layout
│   │   ├── store/
│   │   │   ├── scanStore.js     # Zustand: scan state, progress, results
│   │   │   ├── whitelistStore.js
│   │   │   ├── quarantineStore.js
│   │   │   ├── settingsStore.js
│   │   │   └── licenseStore.js
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Scanner.jsx
│   │   │   ├── Whitelist.jsx
│   │   │   ├── Quarantine.jsx
│   │   │   ├── Settings.jsx
│   │   │   └── License.jsx
│   │   └── components/          # Shared UI primitives (Button, Table, Badge, etc.)
│   └── vite.config.js
│
├── engine/                      # Scan engine (runs in main process)
│   ├── scanner.js               # ClamAV wrapper
│   ├── updater.js               # FreshClam wrapper
│   └── quarantine.js            # Move / restore / delete logic
│
├── monitor/                     # Real-time FS protection
│   ├── monitor.js               # Chokidar watcher
│   └── service-wrapper.js       # node-windows service entry point
│
├── whitelist/                   # Whitelist subsystem
│   ├── hasher.js                # SHA-256 file hashing
│   ├── db.js                    # SQLite CRUD for whitelist table
│   ├── checker.js               # Pre-scan whitelist check
│   └── sync.js                  # Cloud pull (GET /whitelist)
│
├── license/                     # Licensing subsystem
│   ├── machine-id.js            # Machine fingerprint derivation
│   ├── keygen-client.js         # Keygen.sh API calls
│   └── license-store.js         # AES-256 encrypted token read/write
│
├── defender/                    # Windows Defender replacement
│   ├── scripts/
│   │   ├── disable-defender.ps1
│   │   ├── register-wsc.ps1
│   │   └── restore-defender.ps1
│   └── ps-runner.js             # Node.js caller with ExecutionPolicy Bypass
│
├── database/                    # SQLite schema and migrations
│   ├── schema.sql
│   └── init.js                  # Create + migrate
│
├── backend/                     # Cloud backend (Railway.app)
│   ├── server.js
│   └── routes/
│       ├── whitelist.js         # GET /whitelist
│       └── submissions.js       # POST /submissions
│
├── installer/
│   └── setup.iss                # Inno Setup 6 script
│
├── assets/
│   ├── icons/                   # Tray icons (green, red/yellow, gray)
│   └── clamav/                  # Bundled ClamAV binaries + DLLs + definitions
│
├── package.json
├── electron-builder.yml
└── vite.config.js
```


### Process Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Electron Main Process                      │
│                                                              │
│  main.js  ──► BrowserWindow  ──► IPC Bridge                 │
│     │                                                        │
│     ├──► tray-manager.js   (Tray icon + context menu)       │
│     ├──► first-run.js      (Defender + WSC setup)           │
│     ├──► engine/scanner.js (ClamAV child_process)           │
│     ├──► engine/updater.js (FreshClam child_process)        │
│     ├──► engine/quarantine.js                               │
│     ├──► monitor/monitor.js (Chokidar watcher)              │
│     ├──► whitelist/checker.js → whitelist/db.js             │
│     ├──► whitelist/sync.js  (HTTP → backend)                │
│     ├──► license/keygen-client.js (HTTP → Keygen.sh)        │
│     ├──► license/license-store.js (AES-256 file)            │
│     └──► database/init.js  (better-sqlite3)                 │
│                                                              │
└─────────────────────┬───────────────────────────────────────┘
                      │  contextBridge / ipcRenderer
┌─────────────────────▼───────────────────────────────────────┐
│                  Renderer Process (Vite + React)             │
│                                                              │
│  React Router ──► 6 pages ──► Zustand stores                │
│  window.electronAPI.* calls (contextBridge)                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│           Windows Background Service (node-windows)          │
│                                                              │
│  service-wrapper.js ──► monitor/monitor.js                  │
│    Writes threat events to JSON log in AppData               │
│    (Main process polls log on window open)                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### IPC Communication Pattern

All renderer-to-main communication uses Electron's `contextBridge` pattern. The preload script exposes a typed `window.electronAPI` object. The renderer **never** uses `require('electron')` directly.

```
Renderer  ──ipcRenderer.invoke('channel', args)──►  Main (ipcMain.handle)
Main      ──ipcRenderer.send('channel', data)────►  Renderer (ipcRenderer.on)
```

Push notifications from main to renderer (e.g., real-time threat alerts, scan progress) use `mainWindow.webContents.send(channel, data)`.


---

## Components and Interfaces

### electron/main.js

Responsibilities:
- Creates the `BrowserWindow` (frameless, `titleBarStyle: 'hidden'`, `frame: false`).
- Intercepts the `close` event and hides the window rather than quitting.
- Registers all IPC handlers (delegating to handlers in `electron/ipc/`).
- Initializes the database via `database/init.js` on app ready.
- Calls `first-run.js` orchestrator if `settings.first_run_complete` is `0`.
- Starts the Monitor via `monitor/monitor.js` if real-time protection is enabled in settings.
- Starts the 24-hour whitelist sync timer via `whitelist/sync.js`.

```js
// Key interface
app.on('ready', async () => {
  await initDatabase();
  createWindow();
  createTray();
  await validateLicense();
  if (isFirstRun()) await runFirstRunSetup();
  if (settingsGet('realtime_protection')) startMonitor();
  scheduleWhitelistSync();
});
```

### electron/ipc/ handlers

Each handler file exports a `register(ipcMain)` function.

| File | Channels handled |
|---|---|
| `scan-handlers.js` | `scan:start`, `scan:cancel`, `scan:history` |
| `whitelist-handlers.js` | `whitelist:list`, `whitelist:add`, `whitelist:remove`, `whitelist:sync` |
| `quarantine-handlers.js` | `quarantine:list`, `quarantine:restore`, `quarantine:delete` |
| `settings-handlers.js` | `settings:get`, `settings:set`, `settings:addPath`, `settings:removePath` |
| `license-handlers.js` | `license:status`, `license:activate`, `license:deactivate` |
| `defender-handlers.js` | `defender:runSetup` |

### electron/tray-manager.js

Manages a `Tray` instance with three icon states:

| State | Icon | Trigger |
|---|---|---|
| `protected` | green shield | Monitor active, no pending threats |
| `threat` | red/yellow shield | Threat detected or quarantine non-empty |
| `off` | gray shield | Monitor disabled or license inactive |

Context menu items: "Open" (show window), "Quick Scan" (navigate + scan), "Exit" (app.quit()).

State transitions are driven by IPC messages from the monitor and scanner.

### electron/first-run.js

Orchestrates the first-run setup sequence:
1. Checks `settings.first_run_complete` flag.
2. Calls `defender/ps-runner.js` to run `disable-defender.ps1`.
3. Calls `ps-runner.js` to run `register-wsc.ps1`.
4. On each step failure: logs error, continues remaining steps (per Requirement 21.6).
5. Sets `settings.first_run_complete = 1` on completion.

### renderer/App.jsx

```jsx
// React Router layout shell
<Router>
  <div className="flex h-screen bg-slate-950">
    <Sidebar /> {/* persistent nav with 6 links */}
    <TitleBar /> {/* custom draggable title bar */}
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/scanner" element={<Scanner />} />
      <Route path="/whitelist" element={<Whitelist />} />
      <Route path="/quarantine" element={<Quarantine />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/license" element={<License />} />
    </Routes>
  </div>
</Router>
```

### renderer/store/ (Zustand stores)

**scanStore.js**
```js
{
  status: 'idle' | 'running' | 'cancelled' | 'complete',
  mode: 'quick' | 'full' | 'folder' | 'file' | null,
  currentFile: string,
  progress: number,          // 0–100
  threatsFound: Threat[],
  history: ScanRecord[],
  startScan, cancelScan, updateProgress, addThreat, loadHistory
}
```

**whitelistStore.js**
```js
{
  entries: WhitelistEntry[],
  searchQuery: string,
  filteredEntries: WhitelistEntry[],  // derived
  isSyncing: boolean,
  lastSyncAt: string | null,
  loadEntries, addEntry, removeEntry, startSync, setSearch
}
```

**quarantineStore.js**
```js
{
  entries: QuarantineEntry[],
  loadEntries, restoreEntry, deleteEntry
}
```

**settingsStore.js**
```js
{
  realtimeProtection: boolean,
  autoQuarantine: boolean,
  startWithWindows: boolean,
  monitoredPaths: string[],
  definitionVersion: string,
  lastDefinitionUpdate: string | null,
  telemetryEnabled: boolean,
  loadSettings, setSetting, addMonitoredPath, removeMonitoredPath
}
```

**licenseStore.js**
```js
{
  status: 'active' | 'inactive' | 'grace',
  expiresAt: string | null,
  machineFingerprint: string,
  featureGates: { scanLimit: boolean, whitelistCap: boolean, realtimeDisabled: boolean },
  loadLicense, activateLicense, deactivateLicense
}
```


### engine/scanner.js

Wraps `clamscan.exe` as a Node.js `child_process.spawn`.

```js
// Public interface
scan(targetPath, { onProgress, onThreat, signal }) → Promise<ScanResult>

// Internals
- Resolves clamscanPath from app resources directory
- Spawns: clamscan.exe --no-summary --infected <targetPath>
- Streams stdout line by line
- Parses lines matching /^(.+): (.+) FOUND$/
- Throttles onProgress callbacks to 500ms intervals
- Resolves signal.abort to kill the child process (cancel)
- Returns: { filesScanned, threatsFound, duration, cancelled }
```

Exit code handling:
- `0`: Clean (no threats)
- `1`: Threats found (parsed from stdout)
- `2+`: Error — log + surface to UI, do not crash

### engine/updater.js

Wraps `freshclam.exe`:

```js
updateDefinitions({ onProgress }) → Promise<UpdateResult>
// Spawns: freshclam.exe --stdout --datadir=<bundledDefsPath>
// Parses stdout for progress lines
// On success: verifies .cvd files exist and are non-zero size
// On failure: retains existing definitions, returns error
```

### engine/quarantine.js

```js
quarantineFile(filePath, threatName) → Promise<void>
// 1. Computes SHA-256 hash of file
// 2. Moves file to QUARANTINE_DIR/<uuid>_<basename>
// 3. Inserts record into quarantine table

restoreFile(quarantineId) → Promise<void>
// 1. Looks up original_path in quarantine table
// 2. If original directory exists: moves file back
// 3. If not: throws OriginalPathMissingError for UI prompt
// 4. Deletes quarantine table record

deleteFile(quarantineId) → Promise<void>
// 1. Unlinks file from QUARANTINE_DIR
// 2. Deletes quarantine table record
```

### monitor/monitor.js

```js
// Public interface
startMonitor(watchPaths, { onThreat, onError }) → Watcher
stopMonitor(watcher) → void
updatePaths(watcher, newPaths) → void   // hot-reload watch list
```

Internal logic:
- Creates Chokidar watcher with `persistent: true`, `ignoreInitial: true`, `awaitWriteFinish: { stabilityThreshold: 2000 }`.
- Filters events: only processes files whose extension is in `MONITORED_EXTENSIONS`.
- Calls `checker.isWhitelisted(filePath)` before passing to `scanner.scan()`.
- Always excludes `QUARANTINE_DIR` from watch paths.

### monitor/service-wrapper.js

Entry point for the node-windows service. Runs a minimal event loop:
- Starts `monitor.js` with paths from a JSON config file in AppData.
- On threat detection: appends a JSON record to `AppData/GSMShieldAV/threat-events.json`.
- Does not communicate with the Electron window directly (file-based IPC).

### whitelist/hasher.js

```js
hashFile(filePath) → Promise<string>  // returns hex SHA-256
hashBuffer(buffer) → string
```

Uses Node.js `crypto.createHash('sha256')` with streaming reads for large files.

### whitelist/db.js

```js
listEntries(query?) → WhitelistEntry[]
insertEntry({ hash, name, vendor, source, verified }) → void
deleteEntry(hash) → void   // only deletes if source === 'user'
entryExists(hash) → boolean
upsertCloudEntries(entries[]) → void  // bulk upsert, preserves user entries
```

### whitelist/checker.js

```js
isWhitelisted(filePath) → Promise<boolean>
// 1. hashFile(filePath)
// 2. db.entryExists(hash)
// Returns true if hash found in whitelist
```

### whitelist/sync.js

```js
syncFromCloud() → Promise<SyncResult>
// 1. GET <BACKEND_URL>/whitelist with API key header
// 2. Parses JSON array
// 3. db.upsertCloudEntries(entries)
// 4. Updates settings.last_sync_at
// Returns: { added, updated, timestamp }

scheduleSync()  // Sets up 24h interval timer, calls syncFromCloud on tick
```

### license/machine-id.js

```js
getMachineFingerprint() → Promise<string>
// Uses node-machine-id to get hardware ID
// SHA-256 hashes the result for consistency
```

### license/keygen-client.js

```js
activateLicense(key, fingerprint) → Promise<{ token, expiresAt }>
validateLicense(token) → Promise<{ valid, expiresAt }>
deactivateLicense(token, fingerprint) → Promise<void>
```

Uses validation-scoped Keygen.sh token only. No admin token.

### license/license-store.js

```js
storeLicense({ token, expiresAt, storedAt }) → void
loadLicense() → { token, expiresAt, storedAt } | null
clearLicense() → void
// Encryption: AES-256-GCM with key derived from machine fingerprint + app salt
// Stored at: AppData/GSMShieldAV/license.enc
```

### defender/ps-runner.js

```js
runScript(scriptPath, params?) → Promise<{ exitCode, stdout, stderr }>
// Spawns: powershell.exe -ExecutionPolicy Bypass -NonInteractive -File <scriptPath> [params]
// Never throws on non-zero exit — returns exit code + output for caller to handle
```


---

## Data Models

### SQLite — Local Database (`AppData/GSMShieldAV/gsm-shield.db`)

```sql
-- Table 1: whitelist
CREATE TABLE IF NOT EXISTS whitelist (
  hash       TEXT PRIMARY KEY,          -- SHA-256 hex string (64 chars)
  name       TEXT NOT NULL,             -- Human-readable tool name
  vendor     TEXT NOT NULL DEFAULT '',  -- Vendor / publisher name
  verified   INTEGER NOT NULL DEFAULT 0, -- 1 = verified by GSM Shield, 0 = user-added
  source     TEXT NOT NULL CHECK(source IN ('bundled', 'user', 'cloud')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Table 2: quarantine
CREATE TABLE IF NOT EXISTS quarantine (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  original_path   TEXT NOT NULL,        -- Absolute path before quarantine
  quarantine_path TEXT NOT NULL,        -- Absolute path inside QUARANTINE_DIR
  threat_name     TEXT NOT NULL,        -- ClamAV threat identifier string
  file_hash       TEXT NOT NULL,        -- SHA-256 of quarantined file
  detected_at     TEXT NOT NULL DEFAULT (datetime('now')),
  file_size       INTEGER NOT NULL DEFAULT 0
);

-- Table 3: scan_history
CREATE TABLE IF NOT EXISTS scan_history (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  mode            TEXT NOT NULL CHECK(mode IN ('quick', 'full', 'folder', 'file')),
  target_path     TEXT NOT NULL,        -- Scanned path or 'QUICK'/'FULL' sentinel
  started_at      TEXT NOT NULL,
  ended_at        TEXT,                 -- NULL while scan in progress
  files_scanned   INTEGER NOT NULL DEFAULT 0,
  threats_found   INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'running'
                  CHECK(status IN ('running', 'complete', 'cancelled', 'error'))
);

-- Table 4: settings
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- Default rows inserted on first creation:
-- realtime_protection = '1'
-- auto_quarantine     = '1'
-- start_with_windows  = '0'
-- telemetry_enabled   = '1'
-- last_sync_at        = ''
-- first_run_complete  = '0'
-- monitored_paths     = '[]'   (JSON array)
-- definition_version  = ''
-- last_definition_update = ''

-- Table 5: telemetry
CREATE TABLE IF NOT EXISTS telemetry (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type  TEXT NOT NULL,   -- e.g. 'scan_complete', 'threat_detected'
  payload     TEXT NOT NULL,   -- JSON blob (anonymised)
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  synced      INTEGER NOT NULL DEFAULT 0  -- 1 = already pushed to backend
);
```

**Schema migration mechanism**: `init.js` reads a `user_version` PRAGMA. Each migration is a numbered function that runs SQL and increments `user_version`. Migrations run sequentially before the app performs any DB operation.

### PostgreSQL — Cloud Backend

```sql
-- cloud_whitelist: authoritative verified GSM tool hashes
CREATE TABLE cloud_whitelist (
  hash       VARCHAR(64) PRIMARY KEY,
  name       VARCHAR(255) NOT NULL,
  vendor     VARCHAR(255) NOT NULL DEFAULT '',
  verified   BOOLEAN NOT NULL DEFAULT TRUE,
  source     VARCHAR(20) NOT NULL DEFAULT 'cloud',
  status     VARCHAR(20) NOT NULL DEFAULT 'verified'
             CHECK(status IN ('verified', 'pending', 'rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- submissions: community-submitted tool hashes pending review
CREATE TABLE submissions (
  id         SERIAL PRIMARY KEY,
  hash       VARCHAR(64) NOT NULL,
  name       VARCHAR(255) NOT NULL,
  vendor     VARCHAR(255) NOT NULL DEFAULT '',
  status     VARCHAR(20) NOT NULL DEFAULT 'pending'
             CHECK(status IN ('pending', 'approved', 'rejected')),
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at  TIMESTAMPTZ
);
CREATE INDEX idx_submissions_status ON submissions(status);
```


---

## Key Flows

### 1. Application Startup

```
main.js app:ready
  │
  ├─► database/init.js
  │     ├─ Check if DB file exists
  │     ├─ CREATE TABLE IF NOT EXISTS (all 5 tables)
  │     ├─ Seed settings defaults if first_run
  │     └─ Apply pending migrations (user_version PRAGMA)
  │
  ├─► license/keygen-client.js validateLicense(storedToken)
  │     ├─ If token valid → set licenseStore.status = 'active'
  │     ├─ If API unreachable AND storedAt < 7 days ago → 'grace'
  │     └─ Otherwise → 'inactive', apply feature gates
  │
  ├─► engine/scanner.js checkDefinitions()
  │     ├─ If main.cvd + daily.cvd exist and size > 0 → OK
  │     └─ If missing/corrupted → emit 'definitions:missing' IPC → banner in UI
  │
  ├─► first-run.js (if settings.first_run_complete === '0')
  │     ├─ ps-runner: disable-defender.ps1
  │     ├─ ps-runner: register-wsc.ps1
  │     └─ settings.set('first_run_complete', '1')
  │
  ├─► tray-manager.js createTray()
  │
  └─► monitor/monitor.js (if settings.realtime_protection === '1')
        └─ Start Chokidar watcher on configured paths
```

### 2. File Scan Flow

```
User triggers scan (any mode)
  │
  ├─► scanner.scan(targetPath, options)
  │     │
  │     ├─ For each file in target:
  │     │   ├─► whitelist/checker.isWhitelisted(filePath)
  │     │   │     ├─ hashFile(filePath)
  │     │   │     └─ db.entryExists(hash)
  │     │   │
  │     │   ├─ IF whitelisted → skip (no clamscan invocation)
  │     │   │
  │     │   └─ IF not whitelisted:
  │     │         spawn: clamscan.exe --no-summary --infected <filePath>
  │     │         parse stdout for "FOUND" lines
  │     │         emit onProgress (throttled 500ms)
  │     │         emit onThreat if FOUND
  │     │
  │     └─ Resolve ScanResult { filesScanned, threatsFound, cancelled }
  │
  ├─► scan_history INSERT (mode, target, started_at, ended_at, files, threats, status)
  │
  └─► For each threat:
        IF auto_quarantine enabled:
          quarantine.quarantineFile(filePath, threatName)
          tray-manager.setState('threat')
          mainWindow.webContents.send('threat:detected', { filePath, threatName })
```

### 3. Real-Time Monitor Flow

```
Chokidar 'add' or 'change' event fires
  │
  ├─ Check extension in MONITORED_EXTENSIONS list
  │     IF not in list → ignore
  │
  ├─ awaitWriteFinish stabilityThreshold: 2000ms
  │     (waits 2s after last write to that path)
  │
  ├─► whitelist/checker.isWhitelisted(filePath)
  │     IF whitelisted → ignore
  │
  ├─► scanner.scan(filePath, { signal })
  │     Parses FOUND output
  │
  └─► IF threat found:
        quarantine.quarantineFile(filePath, threatName)
        Electron Notification: "Threat detected: <threatName> in <filename>"
        tray-manager.setState('threat')
        mainWindow.webContents.send('threat:detected', payload)
        Append to AppData/GSMShieldAV/threat-events.json (service mode)
```

### 4. License Activation Flow

```
User enters key → clicks Activate
  │
  ├─► license/machine-id.js getMachineFingerprint()
  │
  ├─► license/keygen-client.js activateLicense(key, fingerprint)
  │     POST https://api.keygen.sh/v1/accounts/<id>/licenses/<key>/actions/validate
  │     Body: { meta: { fingerprint } }
  │
  ├─ IF success:
  │     license-store.storeLicense({ token, expiresAt, storedAt: now() })
  │     licenseStore.status = 'active'
  │     Remove all feature gates immediately (no restart required)
  │     Display success feedback in License page
  │
  └─ IF failure (invalid key, fingerprint mismatch, API error):
        Display descriptive error in License page
        licenseStore.status unchanged
```

### 5. Whitelist Cloud Sync Flow

```
24h timer fires (or user clicks "Sync from Cloud")
  │
  ├─► Check license status — IF inactive → skip
  │
  ├─► whitelist/sync.js syncFromCloud()
  │     GET <BACKEND_URL>/whitelist
  │     Headers: { Authorization: 'Bearer <API_KEY>' }
  │
  ├─ IF 200 OK:
  │     Parse JSON array of { hash, name, vendor, verified, source }
  │     db.upsertCloudEntries(entries)  -- preserves user-source rows
  │     settings.set('last_sync_at', now())
  │     Emit IPC 'whitelist:synced' to renderer
  │
  └─ IF network error / non-200:
        Schedule exponential backoff retry (1h, 2h, 4h, 8h max)
        IF failed > 72 consecutive hours:
          Emit IPC 'whitelist:sync-error' → display banner in UI
```

### 6. Windows Defender Replacement Flow

```
first-run.js orchestrator (requires admin privileges from installer UAC)
  │
  ├─► ps-runner.js → disable-defender.ps1
  │     Set-MpPreference -DisableRealtimeMonitoring $true
  │     Set-MpPreference -DisableBehaviorMonitoring $true
  │     Set-MpPreference -DisableOnAccessProtection $true
  │     IF failure: log error, continue
  │
  ├─► ps-runner.js → register-wsc.ps1
  │     Apply HKLM registry keys:
  │       HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
  │         DisableAntiSpyware = 1
  │     Disable Tamper Protection via registry
  │     Stop-Service WinDefend -Force
  │     Set-Service WinDefend -StartupType Disabled
  │     Write WSC registration keys:
  │       HKLM\SOFTWARE\Microsoft\Security Center\Svc
  │       ProductState = 266240
  │       DisplayName = "GSM Shield AV"
  │     IF failure: log error, continue
  │
  └─► settings.set('first_run_complete', '1')

Uninstall sequence (restore-defender.ps1):
  ├─ Remove GSM Shield AV WSC registry entries
  ├─ Delete DisableAntiSpyware policy key
  ├─ Set-Service WinDefend -StartupType Automatic
  ├─ Start-Service WinDefend
  └─ Set-MpPreference -DisableRealtimeMonitoring $false (restore defaults)
```

### 7. Quarantine Restore / Delete Flow

```
Restore:
  quarantine.restoreFile(id)
  ├─ SELECT original_path, quarantine_path FROM quarantine WHERE id = ?
  ├─ Check if directory of original_path exists
  │   ├─ IF exists: fs.rename(quarantine_path → original_path)
  │   └─ IF not exists: throw OriginalPathMissingError
  │         → UI prompts user to select alternative destination
  └─ DELETE FROM quarantine WHERE id = ?

Delete Permanently:
  quarantine.deleteFile(id)
  ├─ SELECT quarantine_path FROM quarantine WHERE id = ?
  ├─ fs.unlink(quarantine_path)  -- secure delete
  └─ DELETE FROM quarantine WHERE id = ?
```


---

## IPC Contract

All channels use `ipcMain.handle` / `ipcRenderer.invoke` (request-response) unless marked as push (main → renderer one-way via `webContents.send`).

### Scan Channels

| Channel | Direction | Payload | Response |
|---|---|---|---|
| `scan:start` | invoke | `{ mode, targetPath? }` | `{ scanId }` |
| `scan:cancel` | invoke | `{ scanId }` | `{ success }` |
| `scan:history` | invoke | `{ limit? }` | `ScanRecord[]` |
| `scan:progress` | **push** | `{ scanId, currentFile, filesScanned }` | — |
| `scan:threat` | **push** | `{ scanId, filePath, threatName }` | — |
| `scan:complete` | **push** | `{ scanId, result }` | — |

### Whitelist Channels

| Channel | Direction | Payload | Response |
|---|---|---|---|
| `whitelist:list` | invoke | `{ query? }` | `WhitelistEntry[]` |
| `whitelist:add` | invoke | `{ filePath }` | `{ success, duplicate? }` |
| `whitelist:remove` | invoke | `{ hash }` | `{ success, forbidden? }` |
| `whitelist:sync` | invoke | — | `{ added, updated, timestamp }` |
| `whitelist:synced` | **push** | `{ added, updated, timestamp }` | — |
| `whitelist:sync-error` | **push** | `{ message }` | — |
| `whitelist:submit` | invoke | `{ hash, name, vendor }` | `{ success, error? }` |

### Quarantine Channels

| Channel | Direction | Payload | Response |
|---|---|---|---|
| `quarantine:list` | invoke | — | `QuarantineEntry[]` |
| `quarantine:restore` | invoke | `{ id }` | `{ success, needsPath? }` |
| `quarantine:restore-to` | invoke | `{ id, destPath }` | `{ success }` |
| `quarantine:delete` | invoke | `{ id }` | `{ success }` |

### Settings Channels

| Channel | Direction | Payload | Response |
|---|---|---|---|
| `settings:get` | invoke | — | `SettingsMap` |
| `settings:set` | invoke | `{ key, value }` | `{ success }` |
| `settings:addPath` | invoke | `{ path }` | `{ success }` |
| `settings:removePath` | invoke | `{ path }` | `{ success }` |
| `settings:getDefinitionInfo` | invoke | — | `{ version, lastUpdate }` |
| `definitions:update` | invoke | — | streams via push |
| `definitions:progress` | **push** | `{ status, percent }` | — |
| `definitions:complete` | **push** | `{ version, date }` | — |
| `definitions:error` | **push** | `{ message }` | — |
| `definitions:missing` | **push** | `{ detail }` | — |

### License Channels

| Channel | Direction | Payload | Response |
|---|---|---|---|
| `license:status` | invoke | — | `{ status, expiresAt, fingerprint, gates }` |
| `license:activate` | invoke | `{ key }` | `{ success, error? }` |
| `license:deactivate` | invoke | — | `{ success }` |
| `license:updated` | **push** | `{ status, gates }` | — |

### System / Threat Channels

| Channel | Direction | Payload | Response |
|---|---|---|---|
| `threat:detected` | **push** | `{ filePath, threatName, timestamp }` | — |
| `tray:setState` | invoke | `{ state }` | — |
| `window:minimize` | invoke | — | — |
| `window:maximize` | invoke | — | — |
| `window:close` | invoke | — | — |


---

## Tech Stack Versions

### Core Runtime

| Package | Version | Purpose |
|---|---|---|
| `electron` | `28.x` | Desktop shell, IPC, Tray, BrowserWindow |
| `node` | `20.x` (bundled by Electron 28) | JS runtime for main process |

### Renderer

| Package | Version | Purpose |
|---|---|---|
| `react` | `18.3.x` | UI framework |
| `react-dom` | `18.3.x` | React DOM renderer |
| `react-router-dom` | `6.x` | Client-side routing (6 pages) |
| `zustand` | `4.x` | Lightweight state management |
| `tailwindcss` | `3.x` | Utility-first CSS (slate-950 dark theme) |
| `lucide-react` | `0.x` (latest stable) | Icon set (shield, scan, list, settings, etc.) |
| `vite` | `5.x` | Renderer build tool |
| `@vitejs/plugin-react` | `4.x` | Vite React plugin |

### Main Process / Engine

| Package | Version | Purpose |
|---|---|---|
| `better-sqlite3` | `9.x` | Synchronous SQLite driver |
| `chokidar` | `3.x` | Cross-platform FS watcher |
| `node-machine-id` | `1.x` | Hardware fingerprint |
| `node-windows` | `1.x` | Windows service registration |

### Security / Crypto

| Module | Source | Purpose |
|---|---|---|
| `crypto` | Node.js built-in | SHA-256 hashing, AES-256-GCM encryption |

### Backend

| Package | Version | Purpose |
|---|---|---|
| `express` | `4.x` | HTTP server |
| `pg` | `8.x` | PostgreSQL driver |
| `dotenv` | `16.x` | Environment variable loading |

### Build / Packaging

| Tool | Version | Purpose |
|---|---|---|
| `electron-builder` | `24.x` | ASAR + Windows x64 packaging |
| `Inno Setup` | `6.x` | Single EXE installer production |

---

## Build Pipeline

The build follows a strict three-stage sequence:

### Stage 1: Vite — Renderer Compilation

```bash
vite build
```

- Input: `renderer/src/` (React + Tailwind)
- Output: `renderer/dist/` (minified JS bundle + CSS)
- Configuration: `renderer/vite.config.js`
  - `base: './'` (relative paths for Electron file:// protocol)
  - `build.outDir: '../../renderer/dist'`

### Stage 2: electron-builder — Application Packaging

```bash
electron-builder --win --x64
```

- Reads `electron-builder.yml`
- Bundles `renderer/dist/`, `electron/`, `engine/`, `monitor/`, `whitelist/`, `license/`, `defender/`, `database/`, `assets/`
- Produces:
  - `dist/win-unpacked/` — unpacked application directory
  - `dist/win-unpacked/resources/app.asar` — ASAR archive
- ClamAV binaries and definitions are placed in `resources/clamav/` (not ASARed, accessed via `process.resourcesPath`)

Key `electron-builder.yml` settings:
```yaml
appId: com.gsmshield.av
productName: GSM Shield AV
directories:
  output: dist
win:
  target: dir          # unpacked only — Inno Setup handles the final EXE
  requestedExecutionLevel: requireAdministrator
asarUnpack:
  - "resources/clamav/**"
  - "resources/scripts/**"
files:
  - "electron/**"
  - "engine/**"
  - "monitor/**"
  - "whitelist/**"
  - "license/**"
  - "defender/**"
  - "database/**"
  - "renderer/dist/**"
```

### Stage 3: Inno Setup 6 — Installer EXE

```bash
iscc installer/setup.iss
```

- Input: `dist/win-unpacked/`
- Output: `dist/GSMShieldAV-Setup-<version>.exe`
- Wizard steps: Welcome → License Agreement → Install Folder → Desktop Shortcut → Progress → Complete
- Sets `PrivilegesRequired=admin`
- Does NOT run Defender-disable scripts (deferred to first-run in the application)
- Uninstall section: stops service, restores Defender, removes registry entries, optionally removes AppData

```iss
[Setup]
AppName=GSM Shield AV
AppVersion={#AppVersion}
PrivilegesRequired=admin
DefaultDirName={pf}\GSMShieldAV
Compression=lzma2/ultra64
SolidCompression=yes

[Files]
Source: "..\dist\win-unpacked\*"; DestDir: "{app}"; Flags: recursesubdirs

[Run]
; No Defender scripts here — deferred to app first-run

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -NonInteractive -File ""{app}\resources\scripts\restore-defender.ps1"""; \
  RunOnceId: "RestoreDefender"
```


---

## Security Decisions

### AES-256 License Token Storage

The Keygen.sh validation token is stored in `AppData/GSMShieldAV/license.enc` using AES-256-GCM. The encryption key is derived from `MACHINE_FINGERPRINT + APP_SALT` using `crypto.scryptSync`. A random 12-byte IV is prepended to the ciphertext.

Rationale: prevents trivial copying of a license file to a different machine — the decryption key is bound to the hardware fingerprint of the originating machine.

```js
// license-store.js key derivation (pseudocode)
const key = crypto.scryptSync(
  machineFingerprint + APP_SALT,   // APP_SALT is a hardcoded constant, not a secret
  'gsm-shield-salt',
  32
);
// Encrypt: { iv, authTag, ciphertext } → JSON → base64 → write to .enc file
```

### Keygen.sh Token Scope

Only a **validation-scoped** Keygen.sh token is bundled in the Electron application. This token can only:
- Validate a license key against a fingerprint
- Activate/deactivate a machine against a license

It cannot create licenses, list all licenses, revoke licenses, or access account administration. The admin token never touches the client bundle.

### Backend API Key

The backend API key (used by the client for `GET /whitelist` calls) is **read-only** — it can only call the two public endpoints. It is not an admin credential and its compromise does not expose user data or allow writes beyond community submissions (which are moderated).

The key is embedded as a build-time constant in the Electron bundle. Rotation requires a new release build.

### PowerShell Execution

PowerShell scripts run with `-ExecutionPolicy Bypass -NonInteractive`. The Bypass flag is scoped to the spawned process only and does not change the system-wide execution policy. Scripts are stored in `resources/scripts/` and are integrity-checked via the ASAR signature at runtime.

### Quarantine Directory Permissions

The Quarantine_Store directory (`AppData/GSMShieldAV/quarantine/`) is created with restricted ACLs so that only the running application user can read or write files in it. Quarantined files are not executable from their quarantine location.

---

## Error Handling Strategy

### Network Failures

| Subsystem | Behavior on Network Failure |
|---|---|
| Whitelist sync (auto) | Silent retry with exponential back-off (1h, 2h, 4h, 8h). Error shown only after 72h consecutive failure. |
| Whitelist sync (manual) | Show spinner → on failure show descriptive error toast. Previous data remains unchanged. |
| License validation at startup | Check stored token age. If within 7-day grace period, allow full operation. Otherwise apply feature gates. |
| License activation | Show descriptive inline error in License page. No state change. |
| Definition update | Show error message. Existing definitions retained. Scanning remains operational. |
| Tool submission | Show error toast. Form data preserved for retry. |

### Missing ClamAV Binaries

On startup, `scanner.js` verifies `clamscan.exe`, `freshclam.exe`, and both `.cvd` definition files exist under `process.resourcesPath/clamav/`. If any are missing:
- A non-dismissable warning banner is shown in the renderer.
- All scan operations return an error before spawning any process.
- The tray icon switches to gray.
- User is prompted to reinstall.

### Database Migration Failures

If `init.js` catches an error during migration:
- Error is logged to `AppData/GSMShieldAV/error.log` with timestamp, migration ID, and stack trace.
- A non-fatal alert dialog is shown to the user.
- The application continues on the last successfully migrated schema version.
- No data is deleted or corrupted — migrations are run inside SQLite transactions.

```js
// init.js migration pattern
db.transaction(() => {
  migration.up(db);
  db.pragma(`user_version = ${migration.version}`);
})();
// If transaction throws: caught, logged, app continues at previous version
```

### PowerShell Script Failures

`ps-runner.js` never throws. All failures are returned as `{ exitCode, stdout, stderr }`. The `first-run.js` orchestrator:
- Logs each failure with the full stderr output to `error.log`.
- Continues executing the remaining scripts in the sequence.
- Tracks which steps failed and surfaces a summary in the UI after completion.
- Does not re-run failed steps automatically (requires user to manually trigger from Settings).

### Chokidar / Monitor Failures

If Chokidar throws an error on a watched path (e.g., path deleted while watching):
- The error is caught and logged.
- The specific path is removed from the active watch list.
- The remaining paths continue to be watched.
- An IPC message `monitor:path-error` is sent to the renderer to notify the user.
- Real-time protection remains active for all non-erroring paths.

### Quarantine Restore — Missing Original Path

If the original directory of a quarantined file no longer exists when the user clicks Restore:
- `quarantine.restoreFile()` throws `OriginalPathMissingError`.
- The IPC handler catches this and returns `{ success: false, needsPath: true }`.
- The renderer shows a file-picker dialog for an alternative restore destination.
- The IPC channel `quarantine:restore-to` handles the alternative path.


---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

This feature has several subsystems with universal, input-varying logic that is well-suited to property-based testing: the whitelist checker, the SHA-256 validator, the scan record writer, the upsert logic, the license grace-period checker, and the cloud backend validators. Property-based tests will be written using **fast-check** (TypeScript/JavaScript PBT library).

---

### Property 1: Whitelist bypass is universal

*For any* file whose SHA-256 hash exists in the whitelist, the scanner must never invoke `clamscan.exe` for that file, regardless of scan mode (quick, full, folder, file, or monitor event).

**Validates: Requirements 2.2, 2.3, 7.7, 10.5**

---

### Property 2: User-added entries have correct source and verified flag

*For any* file added through the user-add flow, the resulting whitelist record must have `source = 'user'` and `verified = 0`. No other combination is permissible for user-originated entries.

**Validates: Requirements 3.1**

---

### Property 3: Whitelist deduplication

*For any* hash that already exists in the whitelist, attempting to add a file with that same hash must leave the whitelist entry count unchanged and must return a duplicate-detected signal to the caller.

**Validates: Requirements 3.2**

---

### Property 4: User-delete is source-scoped

*For any* whitelist entry whose `source` is `'bundled'` or `'cloud'`, calling the user-delete operation on that entry must be rejected and the entry must remain in the whitelist unchanged.

**Validates: Requirements 3.3**

---

### Property 5: Whitelist search filters correctly

*For any* search query string and any whitelist dataset, every entry returned by the filter must contain the query string as a substring of either its `name` or `vendor` field (case-insensitive). No non-matching entry may appear in the results.

**Validates: Requirements 3.4, 16.2**

---

### Property 6: Cloud upsert preserves user-added entries

*For any* sync payload from the cloud endpoint and any pre-existing whitelist state containing user-added entries, after the upsert operation all user-added entries must still be present with their original `source = 'user'` and `verified = 0` values.

**Validates: Requirements 4.2**

---

### Property 7: Sync timestamp is updated on success

*For any* completed successful sync operation, the value of `settings.last_sync_at` must be a timestamp that is greater than or equal to the timestamp recorded before the sync began.

**Validates: Requirements 4.5**

---

### Property 8: SHA-256 hash validation

*For any* string input, the hash validator must return `true` if and only if the string is exactly 64 characters long and every character is a valid hexadecimal digit (0–9, a–f, A–F). All other strings must return `false`.

**Validates: Requirements 5.4, 24.4**

---

### Property 9: ClamAV output parser correctness

*For any* simulated `clamscan.exe` stdout string, the parser must extract exactly the set of lines matching the pattern `<path>: <threat> FOUND` and must not include any other lines in the threat list.

**Validates: Requirements 6.3**

---

### Property 10: Scan record completeness

*For any* completed scan operation (regardless of mode), the record inserted into `scan_history` must contain non-null values for all required fields: `mode`, `target_path`, `started_at`, `ended_at`, `files_scanned`, `threats_found`, and `status`.

**Validates: Requirements 6.4**

---

### Property 11: Whitelist cap enforcement under inactive license

*For any* sequence of user-add operations on a whitelist while the license is inactive, operations that would bring the total user-added entry count above 10 must be rejected. The count of user-added entries must never exceed 10 while the license remains inactive.

**Validates: Requirements 3.5, 20.3**

---

### Property 12: Monitor extension filter

*For any* file path string, the monitor's extension filter must pass the path to the scanner if and only if its extension (case-insensitive) is one of: `.exe`, `.dll`, `.msi`, `.bat`, `.cmd`, `.vbs`, `.ps1`, `.js`, `.scr`, `.com`, `.zip`, `.rar`, `.7z`. All other extensions must be filtered out.

**Validates: Requirements 10.2**

---

### Property 13: Monitor debounce — single invocation per write burst

*For any* sequence of file write events to the same path arriving within a 2-second window, the scanner must be invoked at most once for that path, and only after 2 seconds have elapsed since the last event in the burst.

**Validates: Requirements 10.3**

---

### Property 14: Quarantine path exclusion invariant

*For any* monitor configuration (any set of watched paths, any set of user-added custom paths), the Quarantine_Store path must never appear in the monitor's active watch list.

**Validates: Requirements 9.2, 10.6**

---

### Property 15: Quarantine round trip

*For any* file path and any threat name, quarantining a file and then restoring it (when the original directory exists) must result in the file being present at its original path and the quarantine table record being removed.

**Validates: Requirements 9.1, 9.3**

---

### Property 16: License grace period boundary

*For any* stored license token with a `storedAt` timestamp, the grace-period check must return `valid` if and only if the elapsed time since `storedAt` is strictly less than 7 days (604800 seconds). Tokens stored exactly at or beyond 7 days must return `invalid`.

**Validates: Requirements 20.2, 20.3**

---

### Property 17: Backend — GET /whitelist returns only verified entries

*For any* state of the `cloud_whitelist` table, the `GET /whitelist` endpoint must return exactly those entries where `status = 'verified'` and must not include entries with any other status value.

**Validates: Requirements 24.1**

---

### Property 18: Backend — POST /submissions inserts with pending status

*For any* valid submission payload `{ hash, name, vendor }` where hash is a 64-character hex string, the `POST /submissions` endpoint must insert a record into the `submissions` table with `status = 'pending'` and must return a 2xx response.

**Validates: Requirements 24.2**

---

### Property 19: Backend — unauthenticated requests are rejected

*For any* API request to any backend endpoint that is missing a valid API key in the Authorization header, the response must have HTTP status 401.

**Validates: Requirements 24.3**

---

### Property 20: Monitor watch list is empty when real-time protection is disabled

*For any* state of the application where real-time protection is disabled, the monitor's active watch path list must be empty — regardless of what custom paths the user has configured.

**Validates: Requirements 10.8**


---

## Testing Strategy

### Dual Testing Approach

Testing coverage is achieved through two complementary layers:

1. **Property-based tests** (fast-check): verify universal invariants across many generated inputs for the pure logic subsystems listed above.
2. **Example-based unit tests** (Jest): verify specific behaviors, UI interactions, startup flows, and edge cases.
3. **Integration tests**: verify OS-level operations (service registration, Defender replacement), backend endpoints, and database interactions with a real SQLite/PostgreSQL instance.
4. **Smoke tests**: verify packaging artifacts (ClamAV binaries present, installer EXE well-formed, no admin token in bundle).

### Property-Based Testing Setup

**Library**: `fast-check` (v3.x)  
**Runner**: Jest  
**Iterations per property**: minimum 100 (fast-check default is 100; increase to 500 for critical path properties)

Each property test file tags tests with a comment referencing the design property:

```js
// Feature: gsm-shield-av, Property 1: Whitelist bypass is universal
it.prop([fc.string(), fc.record({hash: fc.hexaString({minLength: 64, maxLength: 64})})])
  ('whitelisted files skip clamscan', ([filePath, entry]) => {
    // ...
  });
```

Tag format: `Feature: gsm-shield-av, Property {N}: {property_text}`

### Unit Test Coverage by Subsystem

| Subsystem | Test Focus | Type |
|---|---|---|
| `whitelist/checker.js` | Hash-before-scan ordering | Property (P1) |
| `whitelist/db.js` | Source/verified on insert | Property (P2) |
| `whitelist/db.js` | Deduplication | Property (P3) |
| `whitelist/db.js` | Source-scoped delete | Property (P4) |
| `whitelist/db.js` | Search filter correctness | Property (P5) |
| `whitelist/sync.js` | Upsert preserves user entries | Property (P6) |
| `whitelist/sync.js` | Timestamp updated on success | Property (P7) |
| `whitelist/hasher.js` | SHA-256 validation | Property (P8) |
| `engine/scanner.js` | FOUND output parser | Property (P9) |
| `database/init.js` | Scan record completeness | Property (P10) |
| `license/keygen-client.js` | Whitelist cap under inactive license | Property (P11) |
| `monitor/monitor.js` | Extension filter | Property (P12) |
| `monitor/monitor.js` | Debounce single invocation | Property (P13) |
| `monitor/monitor.js` | Quarantine path exclusion | Property (P14) |
| `engine/quarantine.js` | Quarantine round trip | Property (P15) |
| `license/license-store.js` | Grace period boundary | Property (P16) |
| `backend/routes/whitelist.js` | Only verified entries | Property (P17) |
| `backend/routes/submissions.js` | Pending status on insert | Property (P18) |
| `backend/server.js` | 401 on missing API key | Property (P19) |
| `monitor/monitor.js` | Empty watch list when RT off | Property (P20) |
| `database/init.js` | Schema tables created | Example |
| `database/init.js` | Settings defaults seeded | Example |
| `engine/scanner.js` | Non-zero exit code handling | Edge case |
| `engine/scanner.js` | Definition file missing check | Edge case |
| `engine/quarantine.js` | Delete permanently removes file + DB | Example |
| `engine/quarantine.js` | Restore to alt path when original missing | Edge case |
| `whitelist/sync.js` | Retry on network failure | Edge case |
| `license/keygen-client.js` | Activation success flow | Example |
| `license/keygen-client.js` | Activation failure flow | Example |
| All network callers | No crash on timeout | Edge case |

### Integration Tests

- **Service registration**: node-windows installs/uninstalls service; verify Windows service exists via `sc query`.
- **Defender scripts**: Run `disable-defender.ps1` in a test VM; verify registry keys set.
- **Backend endpoints**: Spin up test PostgreSQL; verify `GET /whitelist` and `POST /submissions` with real DB.
- **SQLite migrations**: Apply a series of migrations to a real file; verify schema at each step.

### Smoke Tests

- Verify `clamscan.exe` and `freshclam.exe` exist under `resources/clamav/` after build.
- Verify `main.cvd` and `daily.cvd` exist after build.
- Grep the ASAR bundle for known Keygen.sh admin token patterns — must return empty.
- Verify installer EXE is produced and passes Inno Setup integrity check.

