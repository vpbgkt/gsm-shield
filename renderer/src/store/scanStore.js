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
    // scan:progress { scanId, currentFile, filesScanned, threatsFound, phase }
    window.electronAPI.onScanProgress((payload) => {
      get().updateProgress(payload);
    });

    // scan:threat { scanId, filePath, threatName, quarantined?, quarantineFailed? }
    window.electronAPI.onScanThreat((threat) => {
      get().addThreat(threat);
    });

    // scan:complete { scanId, result }
    window.electronAPI.onScanComplete(({ result } = {}) => {
      set({
        status: result?.cancelled ? 'cancelled' : 'complete',
        phase: 'done',
        currentFile: '',
        endedAt: Date.now(),
        filesScanned: result?.filesScanned ?? get().filesScanned,
        errorMessage: result?.error ? (result.errorMessage || 'Scan error') : null,
      });
    });
  }

  return {
    // ── State ──────────────────────────────────────────────────────────────
    /** @type {'idle'|'running'|'cancelled'|'complete'} */
    status: 'idle',
    /** @type {'loading'|'scanning'|'done'|null} — finer-grained phase for UX */
    phase: null,
    /** @type {'quick'|'full'|'folder'|'file'|null} */
    mode: null,
    /** Currently-scanning file path */
    currentFile: '',
    /** Count of files scanned so far (live) */
    filesScanned: 0,
    /** Timestamps for elapsed-time display */
    startedAt: null,
    endedAt: null,
    /** Error message if the scan failed */
    errorMessage: null,
    /** 0–100 (indeterminate for directory scans — used as a pulse) */
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
      // For folder/file modes without a preselected path, the main process
      // opens an OS picker BEFORE resolving — do NOT flip to 'running' until
      // that resolves, otherwise the UI shows "Scanning" over the open dialog.
      const needsPicker = (mode === 'folder' || mode === 'file') && !targetPath;

      if (!needsPicker) {
        set({
          status: 'running',
          phase: 'loading',
          mode,
          currentFile: '',
          filesScanned: 0,
          startedAt: Date.now(),
          endedAt: null,
          errorMessage: null,
          progress: 0,
          threatsFound: [],
        });
      }

      try {
        const res = await window.electronAPI.scanStart({ mode, targetPath });
        // Picker path: only now do we know a target was chosen (or cancelled).
        if (needsPicker) {
          if (res && res.cancelled) {
            set({ status: 'idle', phase: null });
            return;
          }
          set({
            status: 'running',
            phase: 'loading',
            mode,
            currentFile: '',
            filesScanned: 0,
            startedAt: Date.now(),
            endedAt: null,
            errorMessage: null,
            progress: 0,
            threatsFound: [],
          });
        }
      } catch (err) {
        set({ status: 'idle', phase: null });
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
     * @param {{ currentFile?: string, filesScanned?: number, threatsFound?: number, phase?: string }} payload
     */
    updateProgress: ({ currentFile, filesScanned, phase }) => {
      set({
        currentFile: currentFile ?? '',
        filesScanned: filesScanned ?? 0,
        phase: phase ?? 'scanning',
      });
    },

    /**
     * Called by the onScanThreat push handler. De-duplicates by filePath so a
     * follow-up quarantine status update replaces the existing entry rather
     * than adding a duplicate row.
     * @param {{ scanId: string, filePath: string, threatName: string, quarantined?: boolean, quarantineFailed?: boolean }} threat
     */
    addThreat: (threat) => {
      set((state) => {
        const idx = state.threatsFound.findIndex((t) => t.filePath === threat.filePath);
        if (idx >= 0) {
          const next = state.threatsFound.slice();
          next[idx] = { ...next[idx], ...threat };
          return { threatsFound: next };
        }
        return { threatsFound: [...state.threatsFound, threat] };
      });
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
