/**
 * renderer/src/store/expiroStore.js — Zustand store for Expiro Heuristic Shield & Scanner
 *
 * Exposes UI state and actions for Win32/Expiro detection, surgical disinfection,
 * threshold tuning, and real-time protection statistics.
 */

import { create } from 'zustand';

const useExpiroStore = create((set, get) => {
  // Register push listeners from main process
  if (typeof window !== 'undefined' && window.electronAPI) {
    if (window.electronAPI.onExpiroScanProgress) {
      window.electronAPI.onExpiroScanProgress((progress) => {
        set({
          scannedCount: progress.scanned || 0,
          totalCount: progress.total || 0,
          currentFile: progress.currentFile || '',
        });
      });
    }

    if (window.electronAPI.onExpiroDisinfectProgress) {
      window.electronAPI.onExpiroDisinfectProgress((progress) => {
        set({
          disinfectProgress: progress,
        });
      });
    }

    if (window.electronAPI.onExpiroBlocked) {
      window.electronAPI.onExpiroBlocked((threat) => {
        set((state) => ({
          recentBlocks: [threat, ...state.recentBlocks.slice(0, 9)],
        }));
      });
    }

    if (window.electronAPI.onExpiroDetected) {
      window.electronAPI.onExpiroDetected((threat) => {
        set((state) => ({
          recentDetections: [threat, ...state.recentDetections.slice(0, 9)],
        }));
      });
    }
  }

  return {
    // ── State ──────────────────────────────────────────────────────────────
    status: 'idle', // 'idle' | 'scanning' | 'complete' | 'error'
    currentFile: '',
    scannedCount: 0,
    totalCount: 0,
    threshold: 60,
    detections: [],
    recentBlocks: [],
    recentDetections: [],
    stats: null,
    disinfecting: false,
    disinfectingPath: null,
    disinfectionNotice: null,
    disinfectProgress: null,
    lastScanDuration: null,
    errorMessage: null,

    // ── Actions ────────────────────────────────────────────────────────────

    clearNotice: () => set({ disinfectionNotice: null }),

    /**
     * Load current heuristic configuration from main process
     */
    loadConfig: async () => {
      try {
        if (!window.electronAPI?.expiroGetConfig) return;
        const res = await window.electronAPI.expiroGetConfig();
        if (res && res.success && res.detectionThreshold) {
          set({ threshold: res.detectionThreshold });
        }
      } catch (err) {
        console.error('[expiroStore] Failed to load config:', err);
      }
    },

    /**
     * Set heuristic sensitivity threshold
     */
    setThreshold: async (newThreshold) => {
      try {
        if (!window.electronAPI?.expiroSetThreshold) return;
        const res = await window.electronAPI.expiroSetThreshold({ threshold: newThreshold });
        if (res && res.success) {
          set({ threshold: res.threshold });
        }
      } catch (err) {
        console.error('[expiroStore] Failed to update threshold:', err);
      }
    },

    /**
     * Load Expiro real-time shield statistics
     */
    loadStats: async () => {
      try {
        if (!window.electronAPI?.expiroGetStats) return;
        const res = await window.electronAPI.expiroGetStats();
        if (res && res.success) {
          set({ stats: res.stats });
        }
      } catch (err) {
        console.error('[expiroStore] Failed to load stats:', err);
      }
    },

    /**
     * Scan a directory recursively for PE files with Expiro heuristics
     */
    scanDirectory: async (dirPath) => {
      const startTime = Date.now();
      set({
        status: 'scanning',
        currentFile: dirPath,
        scannedCount: 0,
        totalCount: 0,
        detections: [],
        errorMessage: null,
      });

      try {
        if (!window.electronAPI?.expiroScanDirectory) {
          throw new Error('Expiro directory scan IPC not available');
        }
        const res = await window.electronAPI.expiroScanDirectory({ dirPath });
        const elapsed = Math.round((Date.now() - startTime) / 1000);

        if (res && res.success) {
          const infected = (res.results || []).filter((r) => r.isInfected !== false);
          set({
            status: 'complete',
            currentFile: '',
            scannedCount: res.totalFiles || res.summary?.total || 0,
            detections: infected,
            lastScanDuration: elapsed,
          });
          return res;
        } else {
          set({
            status: 'error',
            errorMessage: res?.error || 'Scan failed',
          });
          return res;
        }
      } catch (err) {
        set({
          status: 'error',
          errorMessage: err.message,
        });
        return { success: false, error: err.message };
      }
    },

    /**
     * Cancel an active Expiro scan
     */
    cancelScan: async () => {
      try {
        if (window.electronAPI?.expiroCancelScan) {
          await window.electronAPI.expiroCancelScan();
        }
        set({
          status: 'idle',
          currentFile: '',
          errorMessage: 'Scan cancelled by user',
        });
      } catch (err) {
        console.error('[expiroStore] Failed to cancel scan:', err);
      }
    },

    /**
     * Scan a single file with Expiro heuristics
     */
    scanFile: async (filePath) => {
      set({
        status: 'scanning',
        currentFile: filePath,
        scannedCount: 0,
        totalCount: 1,
        detections: [],
        errorMessage: null,
      });

      try {
        if (!window.electronAPI?.expiroScanFile) {
          throw new Error('Expiro scan IPC not available');
        }
        const res = await window.electronAPI.expiroScanFile({ filePath });

        if (res && res.success && res.result) {
          const infected = res.result.isInfected ? [res.result] : [];
          set({
            status: 'complete',
            currentFile: '',
            scannedCount: 1,
            totalCount: 1,
            detections: infected,
          });
          return res;
        } else {
          set({
            status: 'error',
            errorMessage: res?.error || 'File scan failed',
          });
          return res;
        }
      } catch (err) {
        set({
          status: 'error',
          errorMessage: err.message,
        });
        return { success: false, error: err.message };
      }
    },

    /**
     * Disinfect a single file (quarantine or clean source replacement)
     */
    disinfectFile: async (filePath, detection) => {
      set({ disinfecting: true, disinfectingPath: filePath, disinfectionNotice: null });
      try {
        if (!window.electronAPI?.expiroDisinfectFile) {
          throw new Error('Expiro disinfection IPC not available');
        }
        const res = await window.electronAPI.expiroDisinfectFile({ filePath, detection });
        if (res && res.success && res.result?.success) {
          // Expiro cannot be repaired in place; the only outcomes are a verified
          // same-build replacement or neutralized quarantine + vendor reinstall.
          const actionText =
            res.result?.action === 'restored'
              ? 'Replaced with a verified clean copy of the same build'
              : 'Quarantined (neutralized, cannot run). Reinstall the application from the vendor';

          set((state) => ({
            detections: state.detections.filter((d) => d.filePath !== filePath),
            disinfectionNotice: {
              type: 'success',
              message: `${actionText}: ${filePath}`,
            },
          }));
        } else {
          const failureMsg = res.result?.recommendation || res.result?.error || res?.error || 'Disinfection operation failed';
          set({
            disinfectionNotice: {
              type: res.result?.action === 'system_protected' ? 'warning' : 'error',
              message: failureMsg,
            },
          });
        }
        return res;
      } catch (err) {
        set({
          disinfectionNotice: {
            type: 'error',
            message: err.message,
          },
        });
        return { success: false, error: err.message };
      } finally {
        set({ disinfecting: false, disinfectingPath: null });
      }
    },

    /**
     * Disinfect all detected files
     */
    disinfectAll: async () => {
      const currentDetections = get().detections;
      if (!currentDetections.length) return;

      set({ disinfecting: true, disinfectingPath: 'ALL', disinfectionNotice: null });
      try {
        if (!window.electronAPI?.expiroDisinfectBatch) {
          throw new Error('Expiro batch disinfection IPC not available');
        }
        const res = await window.electronAPI.expiroDisinfectBatch({ detections: currentDetections });
        if (res && res.success) {
          const result = res.result || {};
          const successful = result.successful || 0;
          const failed = result.failed || 0;

          if (failed > 0 && successful === 0) {
            const rec = result.details?.find((d) => d.recommendation)?.recommendation;
            set({
              disinfectionNotice: {
                type: 'warning',
                message: rec || `${failed} file(s) could not be modified directly (protected system files or locked).`,
              },
            });
          } else if (failed > 0) {
            const failedPaths = new Set(result.details?.filter((d) => !d.success).map((d) => d.filePath) || []);
            set((state) => ({
              detections: state.detections.filter((d) => failedPaths.has(d.filePath)),
              disinfectionNotice: {
                type: 'warning',
                message: `Processed: ${successful} disinfected/isolated, ${failed} protected system file(s) skipped.`,
              },
            }));
          } else {
            set({
              detections: [],
              disinfectionNotice: {
                type: 'success',
                message: `Processed ${successful} threat(s) successfully without deleting host programs.`,
              },
            });
          }
        }
        return res;
      } catch (err) {
        set({
          disinfectionNotice: {
            type: 'error',
            message: err.message,
          },
        });
        return { success: false, error: err.message };
      } finally {
        set({ disinfecting: false, disinfectingPath: null });
      }
    },

    resetScan: () => {
      set({
        status: 'idle',
        currentFile: '',
        scannedCount: 0,
        totalCount: 0,
        detections: [],
        errorMessage: null,
      });
    },
  };
});

export default useExpiroStore;
