/**
 * renderer/src/store/quarantineStore.js — Zustand store for quarantine subsystem
 *
 * All IPC calls go through window.electronAPI (contextBridge).
 *
 * Requirements: 13.3, 13.4, 17.1
 */

import { create } from 'zustand';

const useQuarantineStore = create((set, get) => ({
  // ── State ──────────────────────────────────────────────────────────────
  /**
   * @type {Array<{
   *   id: number,
   *   original_path: string,
   *   quarantine_path: string,
   *   threat_name: string,
   *   file_hash: string,
   *   detected_at: string,
   *   file_size: number
   * }>}
   */
  entries: [],

  // ── Actions ────────────────────────────────────────────────────────────

  /**
   * Load all quarantine entries from SQLite via IPC.
   */
  loadEntries: async () => {
    try {
      const entries = await window.electronAPI.quarantineList();
      set({ entries: entries ?? [] });
    } catch (_) {
      // keep existing entries on error
    }
  },

  /**
   * Restore a quarantined file to its original location.
   * Reloads the entry list on success.
   * @param {number} id  quarantine record ID
   * @returns {Promise<{success:boolean, needsPath?:boolean}>}
   */
  restoreEntry: async (id) => {
    try {
      const result = await window.electronAPI.quarantineRestore({ id });
      if (result?.success) {
        await get().loadEntries();
      }
      return result;
    } catch (err) {
      return { success: false, error: err?.message ?? 'Unknown error' };
    }
  },

  /**
   * Permanently delete a quarantined file and remove its DB record.
   * Reloads the entry list on success.
   * @param {number} id  quarantine record ID
   * @returns {Promise<{success:boolean}>}
   */
  deleteEntry: async (id) => {
    try {
      const result = await window.electronAPI.quarantineDelete({ id });
      if (result?.success) {
        await get().loadEntries();
      }
      return result;
    } catch (err) {
      return { success: false, error: err?.message ?? 'Unknown error' };
    }
  },
}));

export default useQuarantineStore;
