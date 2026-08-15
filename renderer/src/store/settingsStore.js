/**
 * renderer/src/store/settingsStore.js — Zustand store for settings subsystem
 *
 * All IPC calls go through window.electronAPI (contextBridge).
 * loadSettings maps the flat SettingsMap returned by the main process onto
 * typed state fields.
 * Push listeners (onDefinitionsProgress, onDefinitionsComplete,
 * onDefinitionsError) are registered once on store creation.
 *
 * Requirements: 13.3, 13.4, 18.1
 */

import { create } from 'zustand';

const useSettingsStore = create((set, get) => {
  // ── Register push listeners from main process ──────────────────────────
  if (typeof window !== 'undefined' && window.electronAPI) {
    // definitions:progress { status, percent }
    window.electronAPI.onDefinitionsProgress(({ status, percent } = {}) => {
      set({ updateProgress: { status: status ?? '', percent: percent ?? 0 } });
    });

    // definitions:complete { version, date }
    window.electronAPI.onDefinitionsComplete(({ version, date } = {}) => {
      set({
        isUpdatingDefinitions: false,
        updateProgress: null,
        definitionVersion: version ?? '',
        lastDefinitionUpdate: date ?? new Date().toISOString(),
      });
    });

    // definitions:error { message }
    window.electronAPI.onDefinitionsError(() => {
      set({ isUpdatingDefinitions: false, updateProgress: null });
    });
  }

  return {
    // ── State ────────────────────────────────────────────────────────────
    realtimeProtection: true,
    autoQuarantine: true,
    startWithWindows: false,
    /** @type {string[]} */
    monitoredPaths: [],
    definitionVersion: '',
    /** ISO timestamp or null */
    lastDefinitionUpdate: null,
    telemetryEnabled: true,
    /** True while a definitions update is in progress */
    isUpdatingDefinitions: false,
    /** @type {{ status: string, percent: number } | null} */
    updateProgress: null,

    // ── Actions ──────────────────────────────────────────────────────────

    /**
     * Load all settings from SQLite via IPC and hydrate the store.
     * The main process returns a flat key→value map; boolean values are
     * stored as '1'/'0' strings in SQLite, so we coerce them here.
     */
    loadSettings: async () => {
      try {
        const map = await window.electronAPI.settingsGet();
        if (!map) return;

        // Helper: treat '1' / 1 / true as true
        const bool = (v) => v === true || v === 1 || v === '1';
        // Helper: parse monitored_paths JSON array
        let paths = [];
        try {
          paths = typeof map.monitored_paths === 'string'
            ? JSON.parse(map.monitored_paths)
            : (Array.isArray(map.monitored_paths) ? map.monitored_paths : []);
        } catch (_) {
          paths = [];
        }

        set({
          realtimeProtection:  bool(map.realtime_protection),
          autoQuarantine:      bool(map.auto_quarantine),
          startWithWindows:    bool(map.start_with_windows),
          monitoredPaths:      paths,
          definitionVersion:   map.definition_version ?? '',
          lastDefinitionUpdate: map.last_definition_update || null,
          telemetryEnabled:    bool(map.telemetry_enabled),
        });
      } catch (_) {
        // keep existing settings on error
      }
    },

    /**
     * Persist a single setting key→value via IPC and re-load to stay in
     * sync with the main process.
     * @param {string} key   SQLite settings key (e.g. 'realtime_protection')
     * @param {*}      value New value
     */
    setSetting: async (key, value) => {
      try {
        await window.electronAPI.settingsSet({ key, value });
        await get().loadSettings();
      } catch (_) {
        // no-op; UI can reflect the failure via loadSettings returning stale state
      }
    },

    /**
     * Add a path to the monitored paths list.
     * @param {string} path
     */
    addMonitoredPath: async (path) => {
      try {
        await window.electronAPI.settingsAddPath({ path });
        await get().loadSettings();
      } catch (_) {
        // keep existing paths on error
      }
    },

    /**
     * Remove a path from the monitored paths list.
     * @param {string} path
     */
    removeMonitoredPath: async (path) => {
      try {
        await window.electronAPI.settingsRemovePath({ path });
        await get().loadSettings();
      } catch (_) {
        // keep existing paths on error
      }
    },

    /**
     * Trigger a virus definition update. Sets isUpdatingDefinitions to true;
     * the push listeners handle progress/completion/error transitions.
     */
    updateDefinitions: async () => {
      set({ isUpdatingDefinitions: true, updateProgress: null });
      try {
        await window.electronAPI.definitionsUpdate();
        // Progress/completion handled by onDefinitionsProgress / onDefinitionsComplete
      } catch (_) {
        set({ isUpdatingDefinitions: false, updateProgress: null });
      }
    },
  };
});

export default useSettingsStore;
