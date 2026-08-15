/**
 * renderer/src/store/licenseStore.js — Zustand store for license subsystem
 *
 * All IPC calls go through window.electronAPI (contextBridge).
 * Registers an onLicenseUpdated push listener so that status/gate changes
 * from the main process are reflected immediately (e.g. after background
 * validation or deactivation).
 *
 * Requirements: 13.3, 13.4, 19.1
 */

import { create } from 'zustand';

const useLicenseStore = create((set, get) => {
  // ── Register push listener from main process ──────────────────────────
  if (typeof window !== 'undefined' && window.electronAPI) {
    // license:updated { status, gates }
    window.electronAPI.onLicenseUpdated(({ status, gates } = {}) => {
      set((state) => ({
        status:       status ?? state.status,
        featureGates: gates  ?? state.featureGates,
      }));
    });
  }

  return {
    // ── State ────────────────────────────────────────────────────────────
    /**
     * @type {'active'|'inactive'|'grace'}
     * inactive = no valid license
     * grace    = license unreachable but within 7-day grace window
     * active   = fully validated
     */
    status: 'inactive',
    /** ISO timestamp or null */
    expiresAt: null,
    /** Machine fingerprint string from main process */
    machineFingerprint: '',
    /**
     * Feature gates enforced when license is inactive.
     *   scanLimit:        true = scan count limited
     *   whitelistCap:     true = whitelist entries capped
     *   realtimeDisabled: true = real-time protection disabled
     */
    featureGates: {
      scanLimit: true,
      whitelistCap: true,
      realtimeDisabled: true,
    },
    /** True while an activation request is in-flight */
    isActivating: false,
    /** Error message from the last failed activation, or null */
    activationError: null,

    // ── Actions ──────────────────────────────────────────────────────────

    /**
     * Load current license status from main process (reads stored token,
     * validates against Keygen.sh if online).
     * Response: { status, expiresAt, fingerprint, gates }
     */
    loadLicense: async () => {
      try {
        const data = await window.electronAPI.licenseStatus();
        if (!data) return;
        set({
          status:             data.status      ?? 'inactive',
          expiresAt:          data.expiresAt   ?? null,
          machineFingerprint: data.fingerprint ?? '',
          featureGates:       data.gates       ?? {
            scanLimit: true,
            whitelistCap: true,
            realtimeDisabled: true,
          },
        });
      } catch (_) {
        // keep existing license state on error
      }
    },

    /**
     * Activate a license key against Keygen.sh.
     * @param {string} key  License key entered by the user
     * @returns {Promise<{success:boolean, error?:string}>}
     */
    activateLicense: async (key) => {
      set({ isActivating: true, activationError: null });
      try {
        const result = await window.electronAPI.licenseActivate({ key });
        if (result?.success) {
          // Re-load to get updated status, expiresAt, gates
          await get().loadLicense();
        } else {
          set({ activationError: result?.error ?? 'Activation failed' });
        }
        set({ isActivating: false });
        return result;
      } catch (err) {
        const error = err?.message ?? 'Unknown error';
        set({ isActivating: false, activationError: error });
        return { success: false, error };
      }
    },

    /**
     * Deactivate the current license (removes stored token).
     * @returns {Promise<{success:boolean}>}
     */
    deactivateLicense: async () => {
      try {
        const result = await window.electronAPI.licenseDeactivate();
        if (result?.success) {
          set({
            status:    'inactive',
            expiresAt: null,
            featureGates: {
              scanLimit: true,
              whitelistCap: true,
              realtimeDisabled: true,
            },
          });
        }
        return result;
      } catch (err) {
        return { success: false, error: err?.message ?? 'Unknown error' };
      }
    },
  };
});

export default useLicenseStore;
