'use strict';

/**
 * electron/preload.js — contextBridge IPC bridge
 *
 * Exposes a typed `window.electronAPI` object to the renderer process.
 * The renderer MUST NEVER use require('electron') directly; all IPC goes
 * through window.electronAPI.
 *
 * Requirements: 13.1, 13.2, 13.3, 13.4
 */

const { contextBridge, ipcRenderer } = require('electron');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Wraps ipcRenderer.invoke so the renderer calls a plain async function.
 * @param {string} channel
 * @returns {(...args: any[]) => Promise<any>}
 */
function invoke(channel) {
  return (...args) => ipcRenderer.invoke(channel, ...args);
}

/**
 * Creates an `on*` listener registration function for a push channel.
 * The callback receives the event payload (event object is stripped).
 * @param {string} channel
 * @returns {(callback: Function) => void}
 */
function onPush(channel) {
  return (callback) => {
    ipcRenderer.on(channel, (_event, ...args) => callback(...args));
  };
}

/**
 * Creates an `off*` / removeListener function for a push channel.
 * Pass the same callback reference that was used with the on* method.
 * @param {string} channel
 * @returns {(callback: Function) => void}
 */
function offPush(channel) {
  return (callback) => {
    ipcRenderer.removeListener(channel, callback);
  };
}

// ─── API surface ──────────────────────────────────────────────────────────────

contextBridge.exposeInMainWorld('electronAPI', {

  // ── Scan — invoke channels ─────────────────────────────────────────────────
  // scan:start  { mode, targetPath? } → { scanId }
  scanStart:    invoke('scan:start'),
  // scan:cancel { scanId } → { success }
  scanCancel:   invoke('scan:cancel'),
  // scan:history { limit? } → ScanRecord[]
  scanHistory:  invoke('scan:history'),

  // ── Whitelist — invoke channels ────────────────────────────────────────────
  // whitelist:list { query? } → WhitelistEntry[]
  whitelistList:   invoke('whitelist:list'),
  // whitelist:add { filePath } → { success, duplicate? }
  whitelistAdd:    invoke('whitelist:add'),
  // whitelist:remove { hash } → { success, forbidden? }
  whitelistRemove: invoke('whitelist:remove'),
  // whitelist:sync — → { added, updated, timestamp }
  whitelistSync:   invoke('whitelist:sync'),
  // whitelist:submit { hash, name, vendor } → { success, error? }
  whitelistSubmit: invoke('whitelist:submit'),

  // ── Quarantine — invoke channels ───────────────────────────────────────────
  // quarantine:list — → QuarantineEntry[]
  quarantineList:      invoke('quarantine:list'),
  // quarantine:restore { id } → { success, needsPath? }
  quarantineRestore:   invoke('quarantine:restore'),
  // quarantine:restore-to { id, destPath } → { success }
  quarantineRestoreTo: invoke('quarantine:restore-to'),
  // quarantine:delete { id } → { success }
  quarantineDelete:    invoke('quarantine:delete'),

  // ── Settings — invoke channels ─────────────────────────────────────────────
  // settings:get — → SettingsMap
  settingsGet:              invoke('settings:get'),
  // settings:set { key, value } → { success }
  settingsSet:              invoke('settings:set'),
  // settings:addPath { path } → { success }
  settingsAddPath:          invoke('settings:addPath'),
  // settings:removePath { path } → { success }
  settingsRemovePath:       invoke('settings:removePath'),
  // settings:getDefinitionInfo — → { version, lastUpdate }
  settingsGetDefinitionInfo: invoke('settings:getDefinitionInfo'),

  // ── Definitions — invoke channel ───────────────────────────────────────────
  // definitions:update — → streams progress via push events
  definitionsUpdate: invoke('definitions:update'),

  // ── License — invoke channels ──────────────────────────────────────────────
  // license:status — → { status, expiresAt, fingerprint, gates }
  licenseStatus:     invoke('license:status'),
  // license:activate { key } → { success, error? }
  licenseActivate:   invoke('license:activate'),
  // license:deactivate — → { success }
  licenseDeactivate: invoke('license:deactivate'),

  // ── System — invoke channels ───────────────────────────────────────────────
  // defender:runSetup — → { success, steps }
  defenderRunSetup: invoke('defender:runSetup'),
  // defender:consent { agreed } → { consent } — records Agree/Decline before setup
  defenderConsent:  invoke('defender:consent'),
  // defender:getConsent — → { consent } (boolean)
  defenderGetConsent: invoke('defender:getConsent'),
  // tray:setState { state } — →
  traySetState:     invoke('tray:setState'),
  // window:minimize — →
  windowMinimize:   invoke('window:minimize'),
  // window:maximize — →
  windowMaximize:   invoke('window:maximize'),
  // window:close — →
  windowClose:      invoke('window:close'),

  // ── Push listeners (main → renderer) ──────────────────────────────────────

  // scan:progress { scanId, currentFile, filesScanned }
  onScanProgress:  onPush('scan:progress'),
  offScanProgress: offPush('scan:progress'),

  // scan:threat { scanId, filePath, threatName }
  onScanThreat:  onPush('scan:threat'),
  offScanThreat: offPush('scan:threat'),

  // scan:complete { scanId, result }
  onScanComplete:  onPush('scan:complete'),
  offScanComplete: offPush('scan:complete'),

  // whitelist:synced { added, updated, timestamp }
  onWhitelistSynced:  onPush('whitelist:synced'),
  offWhitelistSynced: offPush('whitelist:synced'),

  // whitelist:sync-error { message }
  onWhitelistSyncError:  onPush('whitelist:sync-error'),
  offWhitelistSyncError: offPush('whitelist:sync-error'),

  // definitions:progress { status, percent }
  onDefinitionsProgress:  onPush('definitions:progress'),
  offDefinitionsProgress: offPush('definitions:progress'),

  // definitions:complete { version, date }
  onDefinitionsComplete:  onPush('definitions:complete'),
  offDefinitionsComplete: offPush('definitions:complete'),

  // definitions:error { message }
  onDefinitionsError:  onPush('definitions:error'),
  offDefinitionsError: offPush('definitions:error'),

  // definitions:missing { detail }
  onDefinitionsMissing:  onPush('definitions:missing'),
  offDefinitionsMissing: offPush('definitions:missing'),

  // license:updated { status, gates }
  onLicenseUpdated:  onPush('license:updated'),
  offLicenseUpdated: offPush('license:updated'),

  // threat:detected { filePath, threatName, timestamp }
  onThreatDetected:  onPush('threat:detected'),
  offThreatDetected: offPush('threat:detected'),

  // defender:setup-result { steps, errors }
  onDefenderSetupResult:  onPush('defender:setup-result'),
  offDefenderSetupResult: offPush('defender:setup-result'),

  // monitor:path-error { message }
  onMonitorPathError:  onPush('monitor:path-error'),
  offMonitorPathError: offPush('monitor:path-error'),
});
