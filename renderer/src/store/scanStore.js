/**
 * renderer/src/store/scanStore.js — Zustand store for scan subsystem
 *
 * All IPC calls go through window.electronAPI (contextBridge).
 * Push listeners (onScanProgress, onScanThreat, onScanComplete) are
 * registered once on store creation.
 *
 * Requirements: 13.3, 13.4, 14.1, 15.1
 */

import { create } from 'zustand';

const useScanStore = create((set, get) => {
  // ── Register push listeners from main process ────────────────────────────
  if (typeof window !== 'undefined' && window.electronAPI) {
    // scan:progress { scanId, currentFile, filesScanned }
    window.electronAPI.onScanProgress((payload) => {
      get().updateProgress(payload);
    });

    // scan:threat { scanId, filePath, threatName }
    window.electronAPI.onScanThreat((threat) => {
      get().addThreat(threat);
    });

    // scan:complete { scanId, result }
    window.electronAPI.onScanComplete(({ result } = {}) => {
      set({
        status: result?.cancelled ? 'cancelled' : 'complete',
        progress: 100,
        currentFile: '',
      });
    });
  }

  return {
    // ── State ──────────────────────────────────────────────────────────────
    /** @type {'idle'|'running'|'cancelled'|'complete'} */
    status: 'idle',
    /** @type {'quick'|'full'|'folder'|'file'|null} */
    mode: null,
    /** Currently-scanning file path */
    currentFile: '',
    /** 0–100 */
    progress: 0,
    /** @type {Array<{scanId:string, filePath:string, threatName:string}>} */
    threatsFound: [],
    /** @type {Array<Object>} scan history records from DB */
    history: [],

    // ── Actions ────────────────────────────────────────────────────────────

    /**
     * Start a scan. Sets state to 'running' optimistically, then invokes IPC.
     * @param {'quick'|'full'|'folder'|'file'} mode
     * @param {string} [targetPath]
     */
    startScan: async (mode, targetPath) => {
      set({
        status: 'running',
        mode,
        currentFile: '',
        progress: 0,
        threatsFound: [],
      });
      try {
        await window.electronAPI.scanStart({ mode, targetPath });
      } catch (err) {
        set({ status: 'idle' });
        throw err;
      }
    },

    /**
     * Cancel the running scan.
     */
    cancelScan: async () => {
      try {
        await window.electronAPI.scanCancel();
      } finally {
        set({ status: 'cancelled' });
      }
    },

    /**
     * Called by the onScanProgress push handler.
     * @param {{ currentFile: string, filesScanned: number }} payload
     */
    updateProgress: ({ currentFile, filesScanned }) => {
      set({ currentFile: currentFile ?? '', progress: filesScanned ?? 0 });
    },

    /**
     * Called by the onScanThreat push handler.
     * @param {{ scanId: string, filePath: string, threatName: string }} threat
     */
    addThreat: (threat) => {
      set((state) => ({ threatsFound: [...state.threatsFound, threat] }));
    },

    /**
     * Load scan history from main process (SQLite).
     * @param {number} [limit=50]
     */
    loadHistory: async (limit = 50) => {
      const records = await window.electronAPI.scanHistory({ limit });
      set({ history: records ?? [] });
    },
  };
});

export default useScanStore;
