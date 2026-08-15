# Implementation Plan: GSM Shield AV

## Overview

Build GSM Shield AV as a Windows-only Electron 28 desktop antivirus purpose-built for GSM repair technicians. The implementation follows the monorepo layout defined in the design: Electron main process, Vite + React 18 renderer, bundled ClamAV engine, SQLite local database, Keygen.sh licensing, node-windows background service, PowerShell Defender replacement, Express cloud backend, and an Inno Setup 6 single-EXE installer.

All property-based tests use **fast-check v3.x** with Jest as the runner.

---

## Tasks

- [x] 1. Project scaffolding — Electron 28 + Vite + React 18 monorepo
  - [x] 1.1 Initialise the monorepo with `package.json`, workspace layout, and all root-level config files
    - Create root `package.json` with `workspaces` pointing to `renderer/`
    - Add `electron`, `vite`, `@vitejs/plugin-react`, `electron-builder@24.x`, `concurrently`, `cross-env` to root devDependencies with exact pinned versions
    - Create `vite.config.js` at root and `renderer/vite.config.js` (base `'./'`, outDir `../../renderer/dist`)
    - Create `electron-builder.yml` stub (appId `com.gsmshield.av`, win target `dir`, `requestedExecutionLevel: requireAdministrator`, `asarUnpack` for clamav and scripts)
    - Create `.gitignore` excluding `node_modules`, `dist`, `renderer/dist`
    - _Requirements: 23.1, 23.2_

  - [x] 1.2 Create the full directory skeleton matching the design monorepo layout
    - Create empty placeholder `index.js` files in: `electron/`, `electron/ipc/`, `engine/`, `monitor/`, `whitelist/`, `license/`, `defender/defender/scripts/`, `database/`, `backend/`, `backend/routes/`, `installer/`, `assets/icons/`, `assets/clamav/`
    - Create `renderer/index.html`, `renderer/src/main.jsx`, `renderer/src/App.jsx`
    - Create stub files for all 6 pages: `renderer/src/pages/{Dashboard,Scanner,Whitelist,Quarantine,Settings,License}.jsx`
    - Create stub Zustand store files: `renderer/src/store/{scanStore,whitelistStore,quarantineStore,settingsStore,licenseStore}.js`
    - _Requirements: 13.3, 13.4_

  - [x] 1.3 Implement the Electron main process entry point (`electron/main.js`) and frameless BrowserWindow
    - Create `BrowserWindow` with `frame: false`, `titleBarStyle: 'hidden'`, `width: 1100`, `height: 720`, `backgroundColor: '#020617'` (slate-950)
    - Register the preload script in `BrowserWindow` options: `webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }`
    - Intercept the `close` event: hide window instead of quitting
    - Load renderer from `renderer/dist/index.html` (production) or `http://localhost:5173` (dev)
    - Register `window:minimize`, `window:maximize`, `window:close` IPC channels
    - Wire up app lifecycle: `app.on('ready')` initialises DB, creates tray, validates license, runs first-run if needed, starts monitor if enabled
    - _Requirements: 12.1, 13.1, 13.2_

  - [x] 1.4 Create the React Router shell, sidebar, and custom title bar (`App.jsx`, `Sidebar.jsx`, `TitleBar.jsx`)
    - Install `react-router-dom@6.x`, `zustand@4.x`, `tailwindcss@3.x`, `lucide-react` in `renderer/package.json`
    - Implement `App.jsx` with `<Router>` wrapping `<Sidebar>` + `<TitleBar>` + `<Routes>` for all 6 pages
    - Implement `Sidebar.jsx` with navigation links to Dashboard, Scanner, Whitelist, Quarantine, Settings, License
    - Implement `TitleBar.jsx` with drag region, app name/logo, and minimize/maximize/close controls calling `window.electronAPI.*`
    - Apply dark theme (`bg-slate-950`) and Tailwind utility classes throughout
    - _Requirements: 13.1, 13.2, 13.3, 13.4_

  - [x] 1.5 Implement `electron/preload.js` — contextBridge IPC bridge
    - Create `electron/preload.js` using `contextBridge.exposeInMainWorld('electronAPI', { ... })` to expose all IPC channels to the renderer
    - Expose all **invoke** channels (renderer → main): `scan.start`, `scan.cancel`, `scan.history`, `whitelist.list`, `whitelist.add`, `whitelist.remove`, `whitelist.sync`, `whitelist.submit`, `quarantine.list`, `quarantine.restore`, `quarantine.restoreTo`, `quarantine.delete`, `settings.get`, `settings.set`, `settings.addPath`, `settings.removePath`, `settings.getDefinitionInfo`, `definitions.update`, `license.status`, `license.activate`, `license.deactivate`, `defender.runSetup`, `tray.setState`, `window.minimize`, `window.maximize`, `window.close`
    - Expose all **push listener** methods (main → renderer): `onScanProgress`, `onScanThreat`, `onScanComplete`, `onWhitelistSynced`, `onWhitelistSyncError`, `onDefinitionsProgress`, `onDefinitionsComplete`, `onDefinitionsError`, `onDefinitionsMissing`, `onLicenseUpdated`, `onThreatDetected`, `onDefenderSetupResult`, `onMonitorPathError`
    - Expose corresponding `off*` / `removeListener` methods for each push channel to prevent memory leaks
    - Map each exposed method to the correct IPC channel string from the IPC contract table in the design (e.g., `scan:start`, `scan:progress`, `threat:detected`, etc.)
    - The renderer **must never** use `require('electron')` directly — all IPC goes through `window.electronAPI`
    - _Requirements: 13.1, 13.2, 13.3, 13.4_

  - [x] 1.6 Write smoke test: verify renderer builds and all 6 routes render without crashing
    - Run `vite build` and assert output files exist in `renderer/dist/`
    - _Requirements: 13.3_

  - [x] 1.7 Write integration test: verify contextBridge exposes all required channels
    - For each invoke method on `window.electronAPI`, assert the method is a function and calling it resolves (with mocked ipcRenderer)
    - For each push listener method, assert it registers a listener without throwing
    - Verify all channel names in the preload match the IPC contract table in the design document
    - _Requirements: 13.1, 13.2_


- [x] 2. Database layer — SQLite init, schema, migrations, and settings defaults
  - [x] 2.1 Implement `database/init.js` — create all five tables and seed settings defaults
    - Install `better-sqlite3@9.x` (exact pin)
    - Open or create `AppData/GSMShieldAV/gsm-shield.db`
    - Execute `CREATE TABLE IF NOT EXISTS` for all five tables: `whitelist`, `quarantine`, `scan_history`, `settings`, `telemetry` using the SQL schema defined in the design
    - Seed `settings` default rows (`realtime_protection=1`, `auto_quarantine=1`, `start_with_windows=0`, `telemetry_enabled=1`, `last_sync_at=''`, `first_run_complete=0`, `monitored_paths=[]`, `definition_version=''`, `last_definition_update=''`) only if table is empty
    - _Requirements: 1.1, 1.2, 1.5_

  - [x] 2.2 Implement the migration runner using SQLite `user_version` PRAGMA
    - Read `PRAGMA user_version` on startup
    - Define a migrations array where each entry has `version: N` and an `up(db)` function
    - Run all migrations with version > current `user_version` inside individual SQLite transactions
    - On migration error: log to `AppData/GSMShieldAV/error.log`, show non-fatal alert dialog, continue at last good version
    - Increment `user_version` after each successful migration transaction
    - _Requirements: 1.3, 1.4_

  - [x] 2.3 Implement `electron/ipc/settings-handlers.js` — full settings IPC channel coverage
    - `settings:get` handler: read all rows from the `settings` table and return them as a key-value map (`SettingsMap`)
    - `settings:set` handler: validate the key exists in the known settings keys list, write `UPDATE settings SET value = ? WHERE key = ?`, return `{ success: true }`
    - `settings:addPath` handler: read current `monitored_paths` JSON array from settings, append the new path (deduplicated), write back, call `monitor.updatePaths()` to hot-reload the watcher within 5 seconds
    - `settings:removePath` handler: filter the path from `monitored_paths`, write back, call `monitor.updatePaths()` to hot-reload
    - `settings:getDefinitionInfo` handler: return `{ version, lastUpdate }` from settings table rows `definition_version` and `last_definition_update`
    - `definitions:update` handler: call `updater.updateDefinitions()`; push `definitions:progress`, `definitions:complete`, or `definitions:error` events to renderer via `mainWindow.webContents.send`
    - Service wiring for `start_with_windows`: when key is set to `'1'`, write `service-config.json` and register node-windows service; when set to `'0'`, unregister service
    - On app open: read pending events from `threat-events.json`, push to renderer, then clear the file
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 11.1, 11.2, 11.3, 11.4, 18.1, 18.2, 18.3, 18.4, 18.5, 18.6_

  - [x] 2.4 Write example tests for schema creation and settings seeding
    - Test: all 5 tables exist after `initDatabase()` on a fresh in-memory DB
    - Test: `settings` table contains exactly the 9 default key-value pairs on first creation
    - Test: `initDatabase()` called twice does not duplicate settings rows
    - _Requirements: 1.1, 1.2, 1.5_


- [x] 3. Whitelist subsystem — hasher, SQLite CRUD, pre-built entries, checker, and IPC handlers
  - [x] 3.1 Implement `whitelist/hasher.js` — streaming SHA-256 file hashing
    - Export `hashFile(filePath) → Promise<string>` using `crypto.createHash('sha256')` with a streaming `fs.createReadStream`
    - Export `hashBuffer(buffer) → string` for synchronous in-memory hashing
    - Handle file-not-found and permission errors by rejecting with a descriptive error
    - _Requirements: 2.2, 3.1_

  - [x] 3.2 Implement `whitelist/db.js` — all SQLite CRUD operations for the whitelist table
    - Export `listEntries(query?)`: return all rows, filtered by `name LIKE` or `vendor LIKE` when query provided (case-insensitive)
    - Export `insertEntry({ hash, name, vendor, source, verified })`: insert row; enforce `source IN ('bundled','user','cloud')`
    - Export `deleteEntry(hash)`: delete only if `source = 'user'`; return a `forbidden` flag otherwise
    - Export `entryExists(hash) → boolean`
    - Export `upsertCloudEntries(entries[])`: bulk INSERT OR REPLACE for cloud entries; never touches rows with `source = 'user'`
    - Export `countUserEntries() → number`
    - _Requirements: 2.4, 3.1, 3.2, 3.3, 4.2_

  - [x] 3.3 Seed pre-built GSM tool whitelist entries on first run
    - Create `whitelist/seed-data.js` exporting an array of at least 20 objects (Odin3, SP Flash Tool, Miracle Box, UFI Box, NCK Box, Z3X Pro, Infinity CM2, Chimera Tool, MRT Dongle, EFT Pro Dongle, Hydra Tool, Pandora Box, Volcano Box, GPG Dragon, Sigma Box, Furious Gold, ATF Box, Easy JTAG, Riff Box, Falcon Box) each with `{ hash, name, vendor, verified: 1, source: 'bundled' }`
    - **Important**: The `hash` values in `seed-data.js` are **placeholder zero-hashes** (`'0'.repeat(64)`) at code-generation time. The real SHA-256 values can only be computed once the team physically collects the actual tool executables and runs `hashFile()` against each one. Populating real hashes is a **manual data-collection step outside of code generation** — each placeholder must be replaced by the team before shipping.
    - Call seed insertion from `init.js` only when the whitelist table is empty
    - _Requirements: 2.1, 2.5_

  - [x] 3.4 Implement `whitelist/checker.js` — pre-scan whitelist gate
    - Export `isWhitelisted(filePath) → Promise<boolean>`
    - Call `hashFile(filePath)` then `db.entryExists(hash)`; return true if found
    - Handle file-read errors by returning `false` (do not block scan)
    - _Requirements: 2.2, 2.3, 7.7, 10.5_

  - [x] 3.5 Register whitelist IPC handlers (`electron/ipc/whitelist-handlers.js`)
    - `whitelist:list` → `db.listEntries(query)`
    - `whitelist:add` → hash file, check duplicate, check license cap (≤10 user entries when inactive), `db.insertEntry`; return `{ success, duplicate?, capReached? }`
    - `whitelist:remove` → `db.deleteEntry(hash)`; return `{ success, forbidden? }`
    - `whitelist:submit` → validate 64-char hex, POST to backend `/submissions`, return `{ success, error? }`
    - `whitelist:sync` → delegate to `sync.js syncFromCloud()`
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 5.1, 5.2, 5.3, 5.4_

  - [x] 3.6 Write property tests for whitelist subsystem (Properties 2, 3, 4, 5, 11)
    - **Property 2: User-added entries have correct source and verified flag** — `fc.record({ name: fc.string(), vendor: fc.string() })` → insert via user-add flow, assert `source='user'` and `verified=0`
    - **Validates: Requirements 3.1**
    - **Property 3: Whitelist deduplication** — `fc.hexaString({minLength:64,maxLength:64})` → insert twice, assert entry count unchanged, duplicate signal returned
    - **Validates: Requirements 3.2**
    - **Property 4: User-delete is source-scoped** — `fc.constantFrom('bundled','cloud')` → attempt delete, assert entry remains and `forbidden=true`
    - **Validates: Requirements 3.3**
    - **Property 5: Whitelist search filters correctly** — `fc.string()` query + `fc.array(whitelistEntryArb)` → every returned entry contains query as substring of name or vendor
    - **Validates: Requirements 3.4, 16.2**
    - **Property 11: Whitelist cap enforcement under inactive license** — `fc.array(fileAddArb, {minLength:11})` with inactive license → user entry count never exceeds 10
    - **Validates: Requirements 3.5, 20.3**


- [x] 4. ClamAV scan engine — scanner.js, scan modes, history recording, cancel support
  - [x] 4.1 Implement `engine/scanner.js` — ClamAV child-process wrapper
    - Resolve `clamscanPath` from `path.join(process.resourcesPath, 'clamav', 'clamscan.exe')`
    - Export `scan(targetPath, { onProgress, onThreat, signal }) → Promise<ScanResult>`
    - Spawn `clamscan.exe --no-summary --infected <targetPath>` via `child_process.spawn`
    - Parse stdout line-by-line for `/^(.+): (.+) FOUND$/`; call `onThreat({ filePath, threatName })` per match
    - Throttle `onProgress` callbacks to one call per 500 ms
    - On `signal.abort`: kill child process, resolve `{ ..., cancelled: true }`
    - Handle exit codes: 0 = clean, 1 = threats found (already parsed), ≥2 = error (log + return error result, do not throw)
    - Export `checkDefinitions() → { ok, detail }`: verify `main.cvd` and `daily.cvd` exist and size > 0 under `resourcesPath/clamav/`
    - _Requirements: 6.1, 6.2, 6.3, 6.5, 6.6_

  - [x] 4.2 Implement scan mode logic in `electron/ipc/scan-handlers.js`
    - `scan:start` handler: resolve target paths by mode (quick = Desktop+Downloads+Temp+AppDataRoaming; full = all fixed/removable drives; folder = folder-picker dialog; file = file-picker dialog), excluding `QUARANTINE_DIR`
    - Insert `scan_history` row with `status='running'` before starting scan
    - Push `scan:progress` events to renderer at ≤500 ms intervals
    - Push `scan:threat` events per threat found
    - On completion: update `scan_history` row with `ended_at`, `files_scanned`, `threats_found`, `status='complete'`
    - `scan:cancel` handler: abort signal → update row to `status='cancelled'`
    - `scan:history` handler: return last 10 rows from `scan_history`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 6.4_

  - [x] 4.3 Write property tests for scan engine (Properties 1, 9, 10)
    - **Property 1: Whitelist bypass is universal** — `fc.constantFrom('quick','full','folder','file','monitor')` + whitelisted filePath → assert `clamscan.exe` spawn count is 0
    - **Validates: Requirements 2.2, 2.3, 7.7, 10.5**
    - **Property 9: ClamAV output parser correctness** — `fc.array(fc.oneof(foundLineArb, cleanLineArb, randomLineArb))` → parser extracts exactly the FOUND lines
    - **Validates: Requirements 6.3**
    - **Property 10: Scan record completeness** — `fc.record({ mode, targetPath })` → after scan, all 7 required fields non-null in `scan_history`
    - **Validates: Requirements 6.4**

  - [x] 4.4 Write edge-case tests for scanner error handling
    - Test: non-zero exit code ≥2 returns error result without throwing
    - Test: missing `main.cvd` → `checkDefinitions()` returns `{ ok: false }`
    - _Requirements: 6.5, 6.6_


- [x] 5. Quarantine module — quarantine.js, IPC handlers, quarantine path exclusion
  - [x] 5.1 Implement `engine/quarantine.js` — move, restore, and delete operations
    - Define `QUARANTINE_DIR = path.join(app.getPath('appData'), 'GSMShieldAV', 'quarantine')`
    - `quarantineFile(filePath, threatName)`: hash file, `fs.rename` to `QUARANTINE_DIR/<uuid>_<basename>`, insert into `quarantine` table
    - `restoreFile(id)`: look up `original_path` and `quarantine_path`; if original directory exists → `fs.rename` back; else throw `OriginalPathMissingError`; `DELETE FROM quarantine WHERE id = ?`
    - `deleteFile(id)`: `fs.unlink` quarantine path, `DELETE FROM quarantine WHERE id = ?`
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.6_

  - [x] 5.2 Register quarantine IPC handlers (`electron/ipc/quarantine-handlers.js`)
    - `quarantine:list` → `SELECT * FROM quarantine ORDER BY detected_at DESC`
    - `quarantine:restore` → call `quarantine.restoreFile(id)`; on `OriginalPathMissingError` return `{ success: false, needsPath: true }`
    - `quarantine:restore-to` → `fs.rename` to user-chosen destination, then delete DB record
    - `quarantine:delete` → call `quarantine.deleteFile(id)`
    - Ensure `QUARANTINE_DIR` is always excluded from monitor watch paths
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.6_

  - [x] 5.3 Write property test for quarantine round trip (Property 15)
    - **Property 15: Quarantine round trip** — `fc.record({ filePath: fc.string(), threatName: fc.string() })` with original directory existing → quarantine then restore → file at original path, DB record removed
    - **Validates: Requirements 9.1, 9.3**

  - [x] 5.4 Write example/edge-case tests for quarantine
    - Test: delete permanently removes file from disk and DB
    - Test: restore when original directory missing returns `{ needsPath: true }`
    - _Requirements: 9.4, 9.6_


- [x] 6. FreshClam definition updater — updater.js, progress streaming, validation
  - [x] 6.1 Implement `engine/updater.js` — FreshClam child-process wrapper
    - Resolve `freshclamPath` from `path.join(process.resourcesPath, 'clamav', 'freshclam.exe')`
    - Export `updateDefinitions({ onProgress }) → Promise<UpdateResult>`
    - Spawn `freshclam.exe --stdout --datadir=<bundledDefsPath>`
    - Parse stdout for progress lines and call `onProgress({ status, percent })`
    - On exit 0: verify `main.cvd` and `daily.cvd` exist and are non-zero size; update `settings.definition_version` and `settings.last_definition_update`
    - On failure or non-zero exit: retain existing definitions, return `{ success: false, error }`; never throw
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 23.5_

  - [x] 6.2 Write edge-case tests for definition updater
    - Test: network failure returns `{ success: false }` without throwing and existing `.cvd` files unchanged
    - Test: partial download (zero-size output file) is detected by validation step and rejected
    - _Requirements: 8.4, 23.5_


- [x] 7. Real-time monitor — monitor.js, Chokidar watcher, extension filter, debounce, IPC integration, tray state
  - [x] 7.1 Implement `monitor/monitor.js` — Chokidar-based real-time file watcher
    - Install `chokidar@3.x` (exact pin)
    - Export `startMonitor(watchPaths, { onThreat, onError }) → Watcher`
    - Create Chokidar watcher with `persistent: true`, `ignoreInitial: true`, `awaitWriteFinish: { stabilityThreshold: 2000, pollInterval: 100 }`
    - Filter events: only process files whose extension (lowercase) is in `MONITORED_EXTENSIONS` (`.exe .dll .msi .bat .cmd .vbs .ps1 .js .scr .com .zip .rar .7z`)
    - Always exclude `QUARANTINE_DIR` from watch paths (strip it from `watchPaths` before passing to Chokidar; re-apply on `updatePaths`)
    - On eligible file event: call `checker.isWhitelisted()`, then `scanner.scan()`; on threat call `quarantine.quarantineFile()`, send `threat:detected` push IPC, show Electron notification
    - Export `stopMonitor(watcher)` and `updatePaths(watcher, newPaths)` (hot-reload watch list within 5 seconds)
    - On Chokidar path error: log, remove erroring path, send `monitor:path-error` push IPC
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8_

  - [x] 7.2 Integrate tray icon state machine in `electron/tray-manager.js`
    - Install three tray icon assets: `assets/icons/tray-green.ico`, `tray-red.ico`, `tray-gray.ico`
    - Export `createTray()` that creates a `Tray` instance using the appropriate icon
    - Implement state machine: `protected` (green), `threat` (red/yellow), `off` (gray)
    - Context menu: "Open" (show window), "Quick Scan" (show window + send `scan:start` quick), "Exit" (`app.quit()`)
    - Export `setState(state)` called by monitor, scanner, and license modules
    - When `real-time protection` disabled or license inactive: set state to `off`
    - _Requirements: 12.2, 12.3, 12.4, 12.5, 12.6_

  - [x] 7.3 Write property tests for monitor subsystem (Properties 12, 13, 14, 20)
    - **Property 12: Monitor extension filter** — `fc.string()` file path → filter passes iff extension is in allowed set (case-insensitive)
    - **Validates: Requirements 10.2**
    - **Property 13: Debounce — single invocation per write burst** — `fc.array(fc.integer({min:0,max:1900}), {minLength:2,maxLength:20})` event timestamps within 2s window → scanner called at most once, only after 2s
    - **Validates: Requirements 10.3**
    - **Property 14: Quarantine path exclusion invariant** — `fc.array(fc.string())` watch paths including `QUARANTINE_DIR` → `QUARANTINE_DIR` never present in active watcher paths
    - **Validates: Requirements 9.2, 10.6**
    - **Property 20: Watch list empty when real-time protection disabled** — `fc.boolean()` protection flag off + `fc.array(fc.string())` configured paths → active watch list is empty
    - **Validates: Requirements 10.8**


- [x] 8. License subsystem — machine-id, keygen-client, license-store, startup validation, grace period, feature gates
  - [x] 8.1 Implement `license/machine-id.js` — hardware fingerprint derivation
    - Install `node-machine-id@1.x` (exact pin)
    - Export `getMachineFingerprint() → Promise<string>`
    - Get hardware ID via `machineId()`, SHA-256 hash the result with `crypto.createHash('sha256')`, return 64-char hex string
    - _Requirements: 20.1, 19.1_

  - [x] 8.2 Implement `license/license-store.js` — AES-256-GCM encrypted token storage
    - Store path: `AppData/GSMShieldAV/license.enc`
    - Key derivation: `crypto.scryptSync(machineFingerprint + APP_SALT, 'gsm-shield-salt', 32)` where `APP_SALT` is a hardcoded non-secret constant
    - `storeLicense({ token, expiresAt, storedAt })`: encrypt with AES-256-GCM (random 12-byte IV prepended), write base64 JSON to file
    - `loadLicense() → { token, expiresAt, storedAt } | null`: read, decrypt, parse; return null on any error
    - `clearLicense()`: delete the `.enc` file
    - _Requirements: 19.4, 20.4_

  - [x] 8.3 Implement `license/keygen-client.js` — Keygen.sh API calls (validation-scoped token only)
    - Export `activateLicense(key, fingerprint) → Promise<{ token, expiresAt }>`
    - Export `validateLicense(token) → Promise<{ valid, expiresAt }>`
    - Export `deactivateLicense(token, fingerprint) → Promise<void>`
    - Use `https` built-in module (or `node-fetch` if available) — no admin token; only validation-scoped token
    - Wrap all calls in try/catch; network errors must not throw — return structured error results
    - _Requirements: 19.3, 20.1, 20.4, 25.2_

  - [x] 8.4 Implement startup license validation and feature gate logic in `electron/main.js`
    - On `app:ready`: call `validateLicense(storedToken)`
    - If valid → status `'active'`, clear all feature gates
    - If API unreachable AND `storedAt` < 7 days ago → status `'grace'`, allow full operation
    - If absent/invalid/grace elapsed → status `'inactive'`, apply feature gates: scan limit 50 results / 1 folder, whitelist cap 10 user entries, real-time disabled
    - Emit `license:updated` push IPC to renderer whenever status changes
    - _Requirements: 20.1, 20.2, 20.3, 20.5_

  - [x] 8.5 Register license IPC handlers (`electron/ipc/license-handlers.js`)
    - `license:status` → return `{ status, expiresAt, fingerprint, gates }`
    - `license:activate` → `getMachineFingerprint()`, `keygen-client.activateLicense()`, `license-store.storeLicense()`, update feature gates, push `license:updated`
    - `license:deactivate` → `keygen-client.deactivateLicense()`, `license-store.clearLicense()`, re-apply feature gates, push `license:updated`
    - _Requirements: 19.2, 19.3, 19.4, 19.5_

  - [x] 8.6 Write property test for license grace period boundary (Property 16)
    - **Property 16: License grace period boundary** — `fc.integer({min:0,max:1209600})` seconds since `storedAt` → grace valid iff elapsed < 604800; at or beyond 604800 must return invalid
    - **Validates: Requirements 20.2, 20.3**

  - [x] 8.7 Write example tests for license activation flows
    - Test: activation success → `license.enc` created, `status='active'`, feature gates cleared
    - Test: activation failure (invalid key) → `license.enc` not created, status unchanged
    - _Requirements: 19.3, 19.4_


- [x] 9. Checkpoint — Ensure all tests pass for tasks 1–8
  - Ensure all tests pass, ask the user if questions arise.


- [x] 10. Windows Defender replacement — PowerShell scripts, ps-runner.js, first-run.js orchestrator
  - [x] 10.1 Write PowerShell scripts for Defender disable and WSC registration
    - `defender/scripts/disable-defender.ps1`: `Set-MpPreference -DisableRealtimeMonitoring $true`, `-DisableBehaviorMonitoring $true`, `-DisableOnAccessProtection $true`
    - `defender/scripts/register-wsc.ps1`: set `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1`, disable Tamper Protection via registry, `Stop-Service WinDefend -Force`, `Set-Service WinDefend -StartupType Disabled`, write WSC registry entries (`ProductState = 266240`, `DisplayName = "GSM Shield AV"`)
    - `defender/scripts/restore-defender.ps1`: reverse all changes, `Set-Service WinDefend -StartupType Automatic`, `Start-Service WinDefend`, `Set-MpPreference -DisableRealtimeMonitoring $false`
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.5_

  - [x] 10.2 Implement `defender/ps-runner.js` — safe PowerShell caller
    - Export `runScript(scriptPath, params?) → Promise<{ exitCode, stdout, stderr }>`
    - Spawn `powershell.exe -ExecutionPolicy Bypass -NonInteractive -File <scriptPath> [params]`
    - Never throw on non-zero exit — always resolve with `{ exitCode, stdout, stderr }`
    - _Requirements: 21.1, 21.6_

  - [x] 10.3 Implement `electron/first-run.js` — first-run setup orchestrator
    - Check `settings.first_run_complete === '0'`; if already done, return early
    - Run `ps-runner.runScript(disable-defender.ps1)`: on failure log error to `error.log`, continue
    - Run `ps-runner.runScript(register-wsc.ps1)`: on failure log error, continue
    - After all steps: `settings.set('first_run_complete', '1')`
    - Surface step-failure summary in UI via push IPC `defender:setup-result`
    - Register `defender:runSetup` IPC channel for manual re-trigger from Settings
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.6_


- [x] 11. Whitelist cloud sync — sync.js, 24h schedule, exponential back-off, manual sync IPC
  - [x] 11.1 Implement `whitelist/sync.js` — cloud pull and sync scheduling
    - Export `syncFromCloud() → Promise<{ added, updated, timestamp }>`
    - `GET <BACKEND_URL>/whitelist` with `Authorization: Bearer <API_KEY>` header; parse JSON array
    - Call `db.upsertCloudEntries(entries)`; update `settings.last_sync_at`
    - On network error / non-200: schedule exponential back-off retry (1h → 2h → 4h → 8h max); if failure persists >72 consecutive hours push `whitelist:sync-error` IPC
    - Export `scheduleSync()`: set 24h interval timer calling `syncFromCloud()`; skip if license inactive
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 25.1_

  - [x] 11.2 Write property tests for sync subsystem (Properties 6, 7)
    - **Property 6: Cloud upsert preserves user-added entries** — `fc.array(cloudEntryArb)` sync payload + pre-existing `source='user'` entries → all user entries still present after upsert
    - **Validates: Requirements 4.2**
    - **Property 7: Sync timestamp is updated on success** — `fc.integer({min:0})` pre-sync timestamp → post-sync `last_sync_at` ≥ pre-sync value
    - **Validates: Requirements 4.5**

  - [x] 11.3 Write edge-case test for sync retry on network failure
    - Test: on network error, function does not throw and existing whitelist data is unchanged
    - _Requirements: 4.3, 25.1_


- [x] 12. Community tool submission — POST /submissions IPC handler and SHA-256 validation
  - [x] 12.1 Implement `whitelist:submit` IPC handler with validation and backend call
    - In `electron/ipc/whitelist-handlers.js` handle `whitelist:submit { hash, name, vendor }`
    - Validate `hash` is exactly 64 lowercase hex characters; return `{ success: false, error: 'invalid_hash' }` if not
    - POST to `<BACKEND_URL>/submissions` with `Authorization` header; on 2xx return `{ success: true }`
    - On network error or non-2xx: return `{ success: false, error: descriptiveMessage }`; never throw
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 25.4_

  - [x] 12.2 Write property test for SHA-256 hash validator (Property 8)
    - **Property 8: SHA-256 hash validation** — `fc.string()` arbitrary input → validator returns `true` iff string is exactly 64 chars and all hex digits; all other inputs return `false`
    - **Validates: Requirements 5.4, 24.4**


- [x] 13. Background service — service-wrapper.js, node-windows registration, threat event log, start-with-Windows toggle
  - [x] 13.1 Implement `monitor/service-wrapper.js` — node-windows service entry point
    - Install `node-windows@1.x` (exact pin)
    - Service entry point: read monitored paths from `AppData/GSMShieldAV/service-config.json`
    - Start `monitor.js` watcher on those paths
    - On threat: append JSON record `{ filePath, threatName, timestamp }` to `AppData/GSMShieldAV/threat-events.json`
    - Handle monitor path errors without crashing the service
    - _Requirements: 11.1, 11.3_

  - [x] 13.2 Implement service registration/unregistration in `electron/ipc/settings-handlers.js`
    - `settings:set` for key `start_with_windows=1`: write `service-config.json` with current `monitored_paths`, register service via node-windows
    - `settings:set` for key `start_with_windows=0`: unregister service via node-windows
    - On service registration failure: push error notification IPC, set tray to gray state
    - On app open: read and display any pending events from `threat-events.json`, then clear the file
    - _Requirements: 11.1, 11.2, 11.3, 11.4_


- [x] 14. React UI — all 6 pages fully implemented, Zustand stores, tray context menu wiring
  - [x] 14.1 Implement Zustand stores for all subsystems
    - `scanStore.js`: `{ status, mode, currentFile, progress, threatsFound, history, startScan, cancelScan, updateProgress, addThreat, loadHistory }` — subscribe to push IPC events from the main process using `window.electronAPI.onScanProgress`, `window.electronAPI.onScanThreat`, and `window.electronAPI.onScanComplete`; call the corresponding `off*` methods on store cleanup to prevent memory leaks
    - `whitelistStore.js`: `{ entries, searchQuery, filteredEntries, isSyncing, lastSyncAt, loadEntries, addEntry, removeEntry, startSync, setSearch }` — `filteredEntries` derived from `entries` + `searchQuery`; subscribe to `window.electronAPI.onWhitelistSynced` and `window.electronAPI.onWhitelistSyncError` push events to update sync state without polling
    - `quarantineStore.js`: `{ entries, loadEntries, restoreEntry, deleteEntry }` — subscribe to `window.electronAPI.onThreatDetected` push event to auto-reload entries when a new threat is quarantined in real time
    - `settingsStore.js`: `{ realtimeProtection, autoQuarantine, startWithWindows, monitoredPaths, definitionVersion, lastDefinitionUpdate, telemetryEnabled, loadSettings, setSetting, addMonitoredPath, removeMonitoredPath }` — subscribe to `window.electronAPI.onDefinitionsProgress`, `window.electronAPI.onDefinitionsComplete`, and `window.electronAPI.onDefinitionsError` push events to reflect update progress live; subscribe to `window.electronAPI.onMonitorPathError` to surface path errors in the UI
    - `licenseStore.js`: `{ status, expiresAt, machineFingerprint, featureGates, loadLicense, activateLicense, deactivateLicense }` — subscribe to `window.electronAPI.onLicenseUpdated` push event to apply feature gate changes immediately without requiring a page reload or polling
    - All store subscriptions must register listeners on mount and unregister them on unmount/cleanup using the corresponding `window.electronAPI.off*` or `removeListener` methods
    - _Requirements: 13.4, 14.1, 15.2, 16.2, 17.1, 18.1, 19.1_

  - [x] 14.2 Implement Dashboard page (`renderer/src/pages/Dashboard.jsx`)
    - Status card: real-time protection state, last scan time/date, threats found this session
    - Recent threats list: 5 most recent entries from `quarantineStore`
    - "Quick Scan" button: navigate to `/scanner` + dispatch `startScan('quick')`
    - _Requirements: 14.1, 14.2, 14.3_

  - [x] 14.3 Implement Scanner page (`renderer/src/pages/Scanner.jsx`)
    - Four scan buttons: Quick Scan, Full Scan, Folder Scan (folder-picker), File Scan (file-picker)
    - Progress bar + current file name + Cancel button (visible while scanning)
    - Results list: threat path + threat name per found item
    - Scan history table: last 10 records (mode, start time, duration, files scanned, threats found)
    - _Requirements: 15.1, 15.2, 15.3, 15.4_

  - [x] 14.4 Implement Whitelist page (`renderer/src/pages/Whitelist.jsx`)
    - Table: name, vendor, verified badge, remove action button
    - Real-time search bar wired to `whitelistStore.setSearch`
    - "Add File" button: file-picker → `whitelist:add` IPC
    - "Sync from Cloud" button: `whitelist:sync` IPC + spinner + last sync timestamp display
    - "Submit a Tool" button: opens inline submission form (hash, name, vendor) → `whitelist:submit` IPC
    - License cap prompt when user entry limit reached
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5_

  - [x] 14.5 Implement Quarantine page (`renderer/src/pages/Quarantine.jsx`)
    - Warning banner: "Restoring files may expose the system to malware"
    - Table: file name, threat name, detection date
    - Per-row "Restore" and "Delete Permanently" buttons
    - On `needsPath: true` response: show folder-picker for alternative restore destination
    - _Requirements: 17.1, 17.2, 17.3, 9.5, 9.6_

  - [x] 14.6 Implement Settings page (`renderer/src/pages/Settings.jsx`)
    - Real-time protection toggle → `settings:set realtime_protection`
    - Auto-quarantine toggle → `settings:set auto_quarantine`
    - Start with Windows toggle → `settings:set start_with_windows`
    - Monitored paths list with add/remove controls → `settings:addPath` / `settings:removePath`
    - Definition update section: current version, last update date, "Check for Updates" button with progress indicator
    - Telemetry toggle → `settings:set telemetry_enabled`
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6_

  - [x] 14.7 Implement License page (`renderer/src/pages/License.jsx`)
    - Status display: license status badge, expiry date (when active), Machine Fingerprint string
    - License key input + "Activate" button with inline success/failure feedback
    - "Deactivate" link → `license:deactivate` IPC + clear token
    - Purchase page link for unlicensed users
    - Feature gate UI hints (scan limit, whitelist cap, real-time protection disabled) when inactive
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 20.3, 20.5_

  - [x] 14.8 Write unit tests for Zustand store logic
    - Test: `filteredEntries` derived correctly for various search queries
    - Test: `licenseStore` feature gates applied/cleared on status transition
    - _Requirements: 3.4, 20.3, 20.5_


- [x] 15. Checkpoint — Ensure all tests pass and all 6 UI pages render correctly end-to-end
  - Ensure all tests pass, ask the user if questions arise.


- [x] 16. Cloud backend — Express server, GET /whitelist, POST /submissions, API key auth, PostgreSQL schema
  - [x] 16.1 Implement `backend/server.js` — Express app entry point
    - Install `express@4.x`, `pg@8.x`, `dotenv@16.x` (exact pins)
    - Load `DATABASE_URL` and `API_KEY` from environment via `dotenv`
    - Create PostgreSQL client pool (`pg.Pool`)
    - Mount routes: `GET /whitelist` and `POST /submissions`
    - Apply API key authentication middleware to all routes: check `Authorization: Bearer <API_KEY>` header; return 401 on missing or invalid key
    - _Requirements: 24.3, 24.5_

  - [x] 16.2 Implement `backend/routes/whitelist.js` — GET /whitelist route
    - Query `SELECT hash, name, vendor, verified, source FROM cloud_whitelist WHERE status = 'verified'`
    - Return JSON array; handle DB errors with 500 response
    - Create PostgreSQL schema migration for `cloud_whitelist` and `submissions` tables
    - _Requirements: 24.1, 24.5_

  - [x] 16.3 Implement `backend/routes/submissions.js` — POST /submissions route
    - Parse and validate request body: `hash` must be exactly 64 hex chars, `name` and `vendor` must be non-empty strings; return 422 with descriptive message if invalid
    - Insert `{ hash, name, vendor, status: 'pending' }` into `submissions` table
    - Return 201 on success
    - _Requirements: 24.2, 24.4, 24.5_

  - [x] 16.4 Write property tests for backend routes (Properties 17, 18, 19)
    - **Property 17: GET /whitelist returns only verified entries** — seed table with mixed statuses → endpoint response contains only `status='verified'` rows
    - **Validates: Requirements 24.1**
    - **Property 18: POST /submissions inserts with pending status** — `fc.record({ hash: fc.hexaString({minLength:64,maxLength:64}), name: fc.string({minLength:1}), vendor: fc.string() })` → DB record has `status='pending'`, response is 2xx
    - **Validates: Requirements 24.2**
    - **Property 19: Unauthenticated requests are rejected** — `fc.constantFrom('missing','wrong','empty')` auth header variant → response status is 401
    - **Validates: Requirements 24.3**

  - [x] 16.5 Write edge-case tests for backend validation
    - Test: invalid hash (63 chars, non-hex chars) on POST /submissions returns 422
    - _Requirements: 24.4_


- [x] 17. Build pipeline — electron-builder.yml configuration, Inno Setup 6 setup.iss, three-stage build script
  - [x] 17.1 Finalise `electron-builder.yml` for production packaging
    - Set `appId: com.gsmshield.av`, `productName: GSM Shield AV`
    - `win.target: dir` (unpacked only — Inno Setup produces the final EXE)
    - `win.requestedExecutionLevel: requireAdministrator`
    - `asarUnpack: ["resources/clamav/**", "resources/scripts/**"]`
    - `files` array covering all source directories: `electron/**`, `engine/**`, `monitor/**`, `whitelist/**`, `license/**`, `defender/**`, `database/**`, `renderer/dist/**`
    - `extraResources` mapping for ClamAV binaries and PS scripts into `resources/`
    - _Requirements: 23.2_

  - [x] 17.2 Write `installer/setup.iss` — Inno Setup 6 script
    - `[Setup]` section: `AppName=GSM Shield AV`, `PrivilegesRequired=admin`, `DefaultDirName={pf}\GSMShieldAV`, `Compression=lzma2/ultra64`, `SolidCompression=yes`
    - `[Files]` section: copy all `dist/win-unpacked/*` recursively to `{app}`
    - `[Icons]` section: optional desktop shortcut
    - Wizard steps: Welcome → License Agreement → Install Folder → Desktop Shortcut option → Progress → Complete
    - `[Run]` section: launch app after install (no Defender scripts)
    - `[UninstallRun]` section: run `restore-defender.ps1` via PowerShell with Bypass; stop and remove service; delete registry entries
    - `[UninstallDelete]` section: remove AppData folder with user prompt
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5_

  - [x] 17.3 Write three-stage build script (`scripts/build.js` or `package.json` scripts)
    - Stage 1: `vite build` (renderer compilation to `renderer/dist/`)
    - Stage 2: `electron-builder --win --x64` (unpacked application directory)
    - Stage 3: `iscc installer/setup.iss` (single EXE installer)
    - Script must fail fast on any stage error and report which stage failed
    - _Requirements: 23.1, 23.2, 23.3_

  - [x] 17.4 Write smoke tests for build artifacts
    - Test: `clamscan.exe` and `freshclam.exe` exist under `resources/clamav/` after Stage 2
    - Test: `main.cvd` and `daily.cvd` exist under `resources/clamav/` after Stage 2
    - Test: grep ASAR bundle for Keygen.sh admin token patterns — result must be empty
    - Test: installer EXE produced by Stage 3 has non-zero file size
    - _Requirements: 22.1, 23.3, 20.4_


- [x] 18. Final checkpoint — Ensure all tests pass, build pipeline succeeds, artifacts verified
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP delivery
- Each task references specific requirements for full traceability to the requirements document
- All property-based tests use `fast-check@3.x` with Jest as the runner; minimum 100 iterations per property (500 for critical-path properties 1, 3, 16)
- Unit tests complement property tests — both layers are needed
- Checkpoints at tasks 9, 15, and 18 ensure incremental validation before proceeding to the next phase
- ClamAV binaries, DLLs, and definition files must be placed in `assets/clamav/` at development time and are excluded from ASAR packaging via `asarUnpack`
- The Keygen.sh admin token must never appear in any source file; only validation-scoped tokens are used
- PowerShell scripts run with `-ExecutionPolicy Bypass -NonInteractive`; they require the installer to have granted admin privileges
- The backend is deployed separately to Railway.app and is not part of the Electron build pipeline
- The `hash` values in `whitelist/seed-data.js` are placeholder zero-hashes (`'0'.repeat(64)`) until the team physically collects the real GSM tool executables and computes their actual SHA-256 digests — this is a manual data-collection step that must happen before production release
- The preload script (`electron/preload.js`) is the **sole** bridge between the renderer and the main process; the renderer must never use `require('electron')` directly. All `window.electronAPI` methods map 1:1 to channels in the IPC contract table in the design document


## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["1.3", "1.5", "2.1"] },
    { "id": 3, "tasks": ["1.4", "1.7", "2.2", "3.1"] },
    { "id": 4, "tasks": ["1.6", "2.3", "2.4", "3.2", "3.3"] },
    { "id": 5, "tasks": ["3.4", "3.5", "4.1", "5.1", "6.1", "8.1", "8.2", "8.3"] },
    { "id": 6, "tasks": ["3.6", "4.2", "5.2", "6.2", "8.4", "8.5", "10.1", "11.1", "12.1", "13.1"] },
    { "id": 7, "tasks": ["4.3", "4.4", "5.3", "5.4", "6.3", "7.1", "8.6", "8.7", "10.2", "10.3", "11.2", "11.3", "12.2", "13.2"] },
    { "id": 8, "tasks": ["7.2", "7.3", "14.1"] },
    { "id": 9, "tasks": ["14.2", "14.3", "14.4", "14.5", "14.6", "14.7"] },
    { "id": 10, "tasks": ["14.8"] },
    { "id": 11, "tasks": ["16.1"] },
    { "id": 12, "tasks": ["16.2", "16.3"] },
    { "id": 13, "tasks": ["16.4", "16.5"] },
    { "id": 14, "tasks": ["17.1", "17.2"] },
    { "id": 15, "tasks": ["17.3"] },
    { "id": 16, "tasks": ["17.4"] }
  ]
}
```
