/**
 * renderer/src/pages/Settings.jsx
 *
 * Settings page — Requirements 18.1, 18.2, 18.3, 18.4, 18.5, 18.6
 *
 * Sections:
 *  - Protection toggles: real-time protection (18.1), auto-quarantine (18.2)
 *  - System toggle: start with Windows (18.3)
 *  - Monitored paths: list with add/remove controls (18.4)
 *  - Definitions: version, last-update date, update button + progress (18.5)
 *  - Privacy toggle: telemetry (18.6)
 */

import React, { useEffect, useState, useRef } from 'react';
import {
  Shield,
  RefreshCw,
  Plus,
  Trash2,
  Settings as SettingsIcon,
  Folder,
  Activity,
} from 'lucide-react';

import useSettingsStore from '../store/settingsStore';

// ── Toggle component ──────────────────────────────────────────────────────────

/**
 * Accessible toggle switch.
 * Off → dark slate background; On → sky-500 background.
 *
 * @param {{ checked: boolean, onChange: (val: boolean) => void, id: string, disabled?: boolean }} props
 */
function Toggle({ checked, onChange, id, disabled = false }) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => !disabled && onChange(!checked)}
      className={[
        'relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent',
        'transition-colors duration-200 ease-in-out',
        'focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900',
        disabled ? 'opacity-50 cursor-not-allowed' : '',
        checked ? 'bg-sky-500' : 'bg-slate-700',
      ].join(' ')}
    >
      <span
        aria-hidden="true"
        className={[
          'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow ring-0',
          'transition-transform duration-200 ease-in-out',
          checked ? 'translate-x-5' : 'translate-x-0',
        ].join(' ')}
      />
    </button>
  );
}

// ── SettingRow ────────────────────────────────────────────────────────────────

/**
 * A labelled row containing a toggle switch.
 *
 * @param {{ id: string, icon: React.ReactNode, label: string, description: string, checked: boolean, onChange: (val:boolean)=>void, disabled?: boolean }} props
 */
function SettingRow({ id, icon, label, description, checked, onChange, disabled }) {
  return (
    <div className="flex items-center justify-between gap-4 py-4">
      <div className="flex items-start gap-3 min-w-0">
        <span className="mt-0.5 shrink-0 text-slate-400">{icon}</span>
        <div className="min-w-0">
          <label
            htmlFor={id}
            className="block text-sm font-medium text-slate-200 cursor-pointer select-none"
          >
            {label}
          </label>
          <p className="text-xs text-slate-500 mt-0.5">{description}</p>
        </div>
      </div>
      <Toggle id={id} checked={checked} onChange={onChange} disabled={disabled} />
    </div>
  );
}

// ── SectionCard ───────────────────────────────────────────────────────────────

/**
 * Wraps a group of settings in a card with a header.
 *
 * @param {{ title: string, icon: React.ReactNode, children: React.ReactNode }} props
 */
function SectionCard({ title, icon, children }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
      {/* Card header */}
      <div className="flex items-center gap-2 px-5 py-3.5 border-b border-slate-800 bg-slate-950/40">
        <span className="text-sky-400">{icon}</span>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
          {title}
        </h2>
      </div>
      <div className="px-5 divide-y divide-slate-800">{children}</div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Settings() {
  // ── Store bindings ────────────────────────────────────────────────────────
  const realtimeProtection    = useSettingsStore((s) => s.realtimeProtection);
  const autoQuarantine        = useSettingsStore((s) => s.autoQuarantine);
  const startWithWindows      = useSettingsStore((s) => s.startWithWindows);
  const telemetryEnabled      = useSettingsStore((s) => s.telemetryEnabled);
  const monitoredPaths        = useSettingsStore((s) => s.monitoredPaths);
  const definitionVersion     = useSettingsStore((s) => s.definitionVersion);
  const lastDefinitionUpdate  = useSettingsStore((s) => s.lastDefinitionUpdate);
  const isUpdatingDefinitions = useSettingsStore((s) => s.isUpdatingDefinitions);
  const updateProgress        = useSettingsStore((s) => s.updateProgress);
  const setSetting            = useSettingsStore((s) => s.setSetting);
  const addMonitoredPath      = useSettingsStore((s) => s.addMonitoredPath);
  const removeMonitoredPath   = useSettingsStore((s) => s.removeMonitoredPath);
  const updateDefinitions     = useSettingsStore((s) => s.updateDefinitions);
  const loadSettings          = useSettingsStore((s) => s.loadSettings);

  // ── Local state ───────────────────────────────────────────────────────────
  /** Whether the "add path" input row is visible */
  const [showAddPath, setShowAddPath]     = useState(false);
  /** Current value of the new-path input */
  const [newPathValue, setNewPathValue]   = useState('');
  /** Which path is being removed (to show spinner) */
  const [removingPath, setRemovingPath]   = useState(null);

  const addInputRef = useRef(null);

  // ── Mount ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  // Focus the add-path input when it becomes visible
  useEffect(() => {
    if (showAddPath && addInputRef.current) {
      addInputRef.current.focus();
    }
  }, [showAddPath]);

  // ── Handlers ─────────────────────────────────────────────────────────────

  function handleToggle(key, value) {
    setSetting(key, value ? '1' : '0');
  }

  async function handleAddPath() {
    const trimmed = newPathValue.trim();
    if (!trimmed) return;
    await addMonitoredPath(trimmed);
    setNewPathValue('');
    setShowAddPath(false);
  }

  function handleAddPathKeyDown(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddPath();
    } else if (e.key === 'Escape') {
      setNewPathValue('');
      setShowAddPath(false);
    }
  }

  async function handleRemovePath(path) {
    setRemovingPath(path);
    try {
      await removeMonitoredPath(path);
    } finally {
      setRemovingPath(null);
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function formatDate(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      return d.toLocaleString(undefined, {
        month:  'short',
        day:    'numeric',
        year:   'numeric',
        hour:   '2-digit',
        minute: '2-digit',
      });
    } catch (_) {
      return iso;
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      {/* Page title */}
      <h1 className="text-2xl font-semibold text-slate-100 tracking-tight flex items-center gap-2">
        <SettingsIcon className="w-6 h-6 text-sky-400" />
        Settings
      </h1>

      {/* ── Protection section (18.1, 18.2) ──────────────────────────── */}
      <SectionCard
        title="Protection"
        icon={<Shield className="w-4 h-4" />}
      >
        {/* Real-time protection (18.1) */}
        <SettingRow
          id="toggle-realtime"
          icon={<Shield className="w-4 h-4" />}
          label="Real-Time Protection"
          description="Continuously monitor the file system and block threats as they appear."
          checked={realtimeProtection}
          onChange={(val) => handleToggle('realtime_protection', val)}
        />

        {/* Auto-quarantine (18.2) */}
        <SettingRow
          id="toggle-autoquarantine"
          icon={<Folder className="w-4 h-4" />}
          label="Auto-Quarantine"
          description="Automatically move detected threats to quarantine without prompting."
          checked={autoQuarantine}
          onChange={(val) => handleToggle('auto_quarantine', val)}
        />
      </SectionCard>

      {/* ── System section (18.3) ────────────────────────────────────── */}
      <SectionCard
        title="System"
        icon={<SettingsIcon className="w-4 h-4" />}
      >
        {/* Start with Windows (18.3) */}
        <SettingRow
          id="toggle-startwithwindows"
          icon={<Activity className="w-4 h-4" />}
          label="Start with Windows"
          description="Launch GSM Shield automatically when you log in to Windows."
          checked={startWithWindows}
          onChange={(val) => handleToggle('start_with_windows', val)}
        />
      </SectionCard>

      {/* ── Monitored Paths section (18.4) ───────────────────────────── */}
      <SectionCard
        title="Monitored Paths"
        icon={<Folder className="w-4 h-4" />}
      >
        <div className="py-4 space-y-3">
          {/* Paths list */}
          {monitoredPaths.length === 0 && !showAddPath ? (
            <p className="text-sm text-slate-500">
              No monitored paths configured. Add a folder to watch it in real time.
            </p>
          ) : (
            <ul className="space-y-1.5">
              {monitoredPaths.map((path) => (
                <li
                  key={path}
                  className="flex items-center justify-between gap-3 rounded-lg bg-slate-800/60 border border-slate-700/60 px-3 py-2"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Folder className="w-4 h-4 text-slate-400 shrink-0" />
                    <span
                      className="text-sm text-slate-200 truncate font-mono"
                      title={path}
                    >
                      {path}
                    </span>
                  </div>
                  <button
                    onClick={() => handleRemovePath(path)}
                    disabled={removingPath === path}
                    aria-label={`Remove ${path} from monitored paths`}
                    className="shrink-0 flex items-center gap-1 text-xs text-slate-500 hover:text-red-400 hover:bg-red-500/10 disabled:opacity-40 disabled:cursor-not-allowed rounded px-2 py-1 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
                  >
                    {removingPath === path ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Trash2 className="w-3.5 h-3.5" />
                    )}
                  </button>
                </li>
              ))}
            </ul>
          )}

          {/* Inline add-path input */}
          {showAddPath && (
            <div className="flex items-center gap-2 mt-2">
              <input
                ref={addInputRef}
                type="text"
                value={newPathValue}
                onChange={(e) => setNewPathValue(e.target.value)}
                onKeyDown={handleAddPathKeyDown}
                placeholder="e.g. C:\Users\You\Documents"
                className="flex-1 rounded-lg bg-slate-800 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm px-3 py-2 font-mono focus:outline-none focus:ring-2 focus:ring-sky-500 transition"
                spellCheck={false}
                autoComplete="off"
              />
              <button
                onClick={handleAddPath}
                disabled={!newPathValue.trim()}
                className="px-3 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 disabled:opacity-40 disabled:cursor-not-allowed text-sm font-medium text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                Add
              </button>
              <button
                onClick={() => {
                  setNewPathValue('');
                  setShowAddPath(false);
                }}
                className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm text-slate-300 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                Cancel
              </button>
            </div>
          )}

          {/* Show add-path row button */}
          {!showAddPath && (
            <button
              onClick={() => setShowAddPath(true)}
              className="flex items-center gap-1.5 text-sm text-sky-400 hover:text-sky-300 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 rounded mt-1"
            >
              <Plus className="w-4 h-4" />
              Add Path
            </button>
          )}
        </div>
      </SectionCard>

      {/* ── Definitions section (18.5) ───────────────────────────────── */}
      <SectionCard
        title="Virus Definitions"
        icon={<RefreshCw className="w-4 h-4" />}
      >
        <div className="py-4 space-y-4">
          {/* Version + last update info */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-500 mb-0.5">Definition Version</p>
              <p className="text-sm font-medium text-slate-200 font-mono">
                {definitionVersion || '—'}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500 mb-0.5">Last Updated</p>
              <p className="text-sm font-medium text-slate-200">
                {formatDate(lastDefinitionUpdate)}
              </p>
            </div>
          </div>

          {/* Update progress bar */}
          {isUpdatingDefinitions && updateProgress && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>{updateProgress.status || 'Updating…'}</span>
                <span>{updateProgress.percent ?? 0}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-slate-700 overflow-hidden">
                <div
                  className="h-full rounded-full bg-sky-500 transition-all duration-300"
                  style={{ width: `${updateProgress.percent ?? 0}%` }}
                />
              </div>
            </div>
          )}

          {/* Updating without specific progress info */}
          {isUpdatingDefinitions && !updateProgress && (
            <div className="flex items-center gap-2 text-sm text-sky-300">
              <RefreshCw className="w-4 h-4 animate-spin shrink-0" />
              Checking for updates…
            </div>
          )}

          {/* Check for Updates button */}
          <button
            onClick={updateDefinitions}
            disabled={isUpdatingDefinitions}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 active:bg-sky-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-semibold text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            <RefreshCw
              className={`w-4 h-4 ${isUpdatingDefinitions ? 'animate-spin' : ''}`}
            />
            {isUpdatingDefinitions ? 'Updating…' : 'Check for Updates'}
          </button>
        </div>
      </SectionCard>

      {/* ── Privacy section (18.6) ───────────────────────────────────── */}
      <SectionCard
        title="Privacy"
        icon={<Activity className="w-4 h-4" />}
      >
        {/* Telemetry (18.6) */}
        <SettingRow
          id="toggle-telemetry"
          icon={<Activity className="w-4 h-4" />}
          label="Send Telemetry"
          description="Share anonymous usage data to help improve GSM Shield. No personal files or paths are ever shared."
          checked={telemetryEnabled}
          onChange={(val) => handleToggle('telemetry_enabled', val)}
        />
      </SectionCard>
    </div>
  );
}
