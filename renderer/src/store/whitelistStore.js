/**
 * renderer/src/store/whitelistStore.js — Zustand store for whitelist subsystem
 *
 * All IPC calls go through window.electronAPI (contextBridge).
 * filteredEntries is a derived slice recomputed whenever entries or
 * searchQuery changes.
 * Push listeners (onWhitelistSynced, onWhitelistSyncError) are registered
 * once on store creation if window.electronAPI is available.
 *
 * Requirements: 13.3, 13.4, 16.1
 */

import { create } from 'zustand';

/**
 * Returns entries that match the search query (case-insensitive).
 * Matches against name, vendor, or hash.
 * @param {Array<Object>} entries
 * @param {string} query
 * @returns {Array<Object>}
 */
function applyFilter(entries, query) {
  if (!query) return entries;
  const lower = query.toLowerCase();
  return entries.filter(
    (e) =>
      (e.name ?? '').toLowerCase().includes(lower) ||
      (e.vendor ?? '').toLowerCase().includes(lower) ||
      (e.hash ?? '').toLowerCase().includes(lower)
  );
}

const useWhitelistStore = create((set, get) => {
  // ── Register push listeners from main process ──────────────────────────
  if (typeof window !== 'undefined' && window.electronAPI) {
    // whitelist:synced { added, updated, timestamp }
    window.electronAPI.onWhitelistSynced(({ timestamp } = {}) => {
      set({ isSyncing: false, lastSyncAt: timestamp ?? new Date().toISOString() });
      get().loadEntries();
    });

    // whitelist:sync-error { message }
    window.electronAPI.onWhitelistSyncError(() => {
      set({ isSyncing: false });
    });
  }

  return {
    // ── State ────────────────────────────────────────────────────────────
    /** @type {Array<{hash:string, name:string, vendor:string, source:string, verified:boolean}>} */
    entries: [],
    /** Current search / filter string */
    searchQuery: '',
    /** Derived: entries filtered by searchQuery */
    filteredEntries: [],
    /** Whether a cloud sync is in-flight */
    isSyncing: false,
    /** ISO timestamp of the last successful sync, or null */
    lastSyncAt: null,

    // ── Actions ──────────────────────────────────────────────────────────

    /**
     * Load whitelist entries, optionally filtered server-side by query.
     * Also recomputes the client-side filteredEntries slice.
     * @param {string} [query]
     */
    loadEntries: async (query) => {
      try {
        const entries = await window.electronAPI.whitelistList({ query });
        const currentQuery = get().searchQuery;
        set({
          entries: entries ?? [],
          filteredEntries: applyFilter(entries ?? [], currentQuery),
        });
      } catch (_) {
        // keep existing entries on error
      }
    },

    /**
     * Add a file to the whitelist by path. Main process hashes it.
     * Reloads entries afterwards.
     * @param {string} filePath
     * @returns {Promise<{success:boolean, duplicate?:boolean, capReached?:boolean, error?:string}>}
     */
    addEntry: async (filePath) => {
      try {
        const result = await window.electronAPI.whitelistAdd({ filePath });
        await get().loadEntries();
        return result;
      } catch (err) {
        return { success: false, error: err?.message ?? 'Unknown error' };
      }
    },

    /**
     * Remove a whitelist entry by SHA-256 hash.
     * Only user-source entries may be deleted (main process enforces this).
     * @param {string} hash
     * @returns {Promise<{success:boolean, forbidden?:boolean}>}
     */
    removeEntry: async (hash) => {
      try {
        const result = await window.electronAPI.whitelistRemove({ hash });
        await get().loadEntries();
        return result;
      } catch (err) {
        return { success: false, error: err?.message ?? 'Unknown error' };
      }
    },

    /**
     * Trigger a cloud sync. Updates isSyncing optimistically; the push
     * listener (onWhitelistSynced) handles the success state update.
     * @returns {Promise<void>}
     */
    startSync: async () => {
      set({ isSyncing: true });
      try {
        await window.electronAPI.whitelistSync();
        // Success state is handled by the onWhitelistSynced push listener.
        // If the call itself resolves immediately with a result (non-push
        // path), handle it here too.
      } catch (_) {
        set({ isSyncing: false });
      }
    },

    /**
     * Update the client-side search query and recompute filteredEntries.
     * @param {string} query
     */
    setSearch: (query) => {
      const entries = get().entries;
      set({ searchQuery: query, filteredEntries: applyFilter(entries, query) });
    },
  };
});

export default useWhitelistStore;
