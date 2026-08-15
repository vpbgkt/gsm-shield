'use strict';

/**
 * electron/ipc/license-handlers.js
 *
 * Registers all license-related IPC channels:
 *   license:status      — return { status, expiresAt, fingerprint, gates }
 *   license:activate    — getMachineFingerprint(), keygen-client.activateLicense(),
 *                          license-store.storeLicense(), update feature gates, push license:updated
 *   license:deactivate  — keygen-client.deactivateLicense(), license-store.clearLicense(),
 *                          re-apply feature gates, push license:updated
 *
 * Requirements: 19.2, 19.3, 19.4, 19.5
 */

// ─── Feature Gate Definitions ─────────────────────────────────────────────────

/**
 * Feature gates applied when license is inactive.
 * Requirement 20.3: When license is inactive, apply the following restrictions:
 *   - Scanning limited to 1 folder with max 50 results
 *   - User-added whitelist entries capped at 10
 *   - Real-time protection disabled
 */
const INACTIVE_FEATURE_GATES = {
  scanLimit: true,           // Limit scanning to 50 results / 1 folder
  whitelistCap: true,        // Cap user whitelist entries at 10
  realtimeDisabled: true,    // Disable real-time protection
};

/**
 * Feature gates when license is active (no restrictions).
 * Requirement 20.5: Remove all feature gates when license is active.
 */
const ACTIVE_FEATURE_GATES = {
  scanLimit: false,
  whitelistCap: false,
  realtimeDisabled: false,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Calculate whether the grace period is still valid.
 * Grace period: 7 days (604800 seconds) from storedAt timestamp.
 * Requirement 20.2: 7-day grace period when API is unreachable.
 *
 * @param {string} storedAt - ISO 8601 timestamp when license was stored
 * @returns {boolean} True if within grace period, false otherwise
 */
function isWithinGracePeriod(storedAt) {
  if (!storedAt) return false;
  
  try {
    const storedTime = new Date(storedAt).getTime();
    const now = Date.now();
    const elapsed = (now - storedTime) / 1000; // Convert to seconds
    const GRACE_PERIOD_SECONDS = 7 * 24 * 60 * 60; // 7 days
    
    return elapsed < GRACE_PERIOD_SECONDS;
  } catch (_) {
    return false;
  }
}

/**
 * Determine the current license status and feature gates.
 * Requirement 20.1, 20.2, 20.3: Validate license and apply grace period logic.
 *
 * @param {Object} deps - Dependencies
 * @param {Function} deps.getLicenseStore - Get license-store module
 * @param {Function} deps.getKeygenClient - Get keygen-client module
 * @param {Function} deps.getMachineId - Get machine-id module
 * @returns {Promise<Object>} Status object { status, expiresAt, fingerprint, gates }
 */
async function determineLicenseStatus({ getLicenseStore, getKeygenClient, getMachineId }) {
  try {
    const licenseStore = getLicenseStore();
    const keygenClient = getKeygenClient();
    const machineId = getMachineId();
    
    // Get machine fingerprint
    const fingerprint = await machineId.getMachineFingerprint();
    
    // Load stored license
    const storedLicense = licenseStore.loadLicense(fingerprint);
    
    // No stored license → inactive
    if (!storedLicense || !storedLicense.token) {
      return {
        status: 'inactive',
        expiresAt: null,
        fingerprint,
        gates: INACTIVE_FEATURE_GATES,
      };
    }
    
    // Validate with Keygen.sh API
    const validationResult = await keygenClient.validateLicense(storedLicense.token);
    
    // API reachable and license valid → active
    if (validationResult.success && validationResult.valid) {
      return {
        status: 'active',
        expiresAt: validationResult.expiresAt || storedLicense.expiresAt,
        fingerprint,
        gates: ACTIVE_FEATURE_GATES,
      };
    }
    
    // API unreachable (network error) → check grace period
    // Requirement 20.2: If API unreachable AND storedAt < 7 days ago → grace
    if (validationResult.error === 'NETWORK_ERROR' || validationResult.error === 'TIMEOUT') {
      if (isWithinGracePeriod(storedLicense.storedAt)) {
        return {
          status: 'grace',
          expiresAt: storedLicense.expiresAt,
          fingerprint,
          gates: ACTIVE_FEATURE_GATES, // Full operation during grace period
        };
      }
    }
    
    // API reachable but license invalid, or grace period elapsed → inactive
    return {
      status: 'inactive',
      expiresAt: null,
      fingerprint,
      gates: INACTIVE_FEATURE_GATES,
    };
    
  } catch (error) {
    console.error('[license-handlers] determineLicenseStatus failed:', error.message);
    
    // On error, default to inactive with restricted gates
    let fingerprint = 'unknown';
    try {
      const machineId = getMachineId();
      fingerprint = await machineId.getMachineFingerprint();
    } catch (_) {
      // Ignore fingerprint errors
    }
    
    return {
      status: 'inactive',
      expiresAt: null,
      fingerprint,
      gates: INACTIVE_FEATURE_GATES,
    };
  }
}

// ─── Main registration function ───────────────────────────────────────────────

/**
 * Register all license IPC handlers.
 *
 * @param {Electron.IpcMain} ipcMain
 * @param {Object} deps
 * @param {() => object} deps.getLicenseStore  - license/license-store.js module
 * @param {() => object} deps.getKeygenClient  - license/keygen-client.js module
 * @param {() => object} deps.getMachineId     - license/machine-id.js module
 * @param {() => Electron.BrowserWindow | null} deps.getMainWindow - Main window getter
 */
function register(ipcMain, { getLicenseStore, getKeygenClient, getMachineId, getMainWindow }) {
  // ── license:status ───────────────────────────────────────────────────────────
  // Returns current license status, expiry date, machine fingerprint, and feature gates.
  // Requirement 19.2: Display license status in License page.
  ipcMain.handle('license:status', async () => {
    try {
      return await determineLicenseStatus({
        getLicenseStore,
        getKeygenClient,
        getMachineId,
      });
    } catch (error) {
      console.error('[license-handlers] license:status failed:', error.message);
      return {
        status: 'inactive',
        expiresAt: null,
        fingerprint: 'unknown',
        gates: INACTIVE_FEATURE_GATES,
      };
    }
  });

  // ── license:activate ─────────────────────────────────────────────────────────
  // Activate a license key for this machine.
  // Requirements: 19.3, 19.4, 20.5
  ipcMain.handle('license:activate', async (_event, { key }) => {
    try {
      const licenseStore = getLicenseStore();
      const keygenClient = getKeygenClient();
      const machineId = getMachineId();
      const win = getMainWindow();
      
      // 1. Get machine fingerprint
      // Requirement 19.3: Activate with key and machine fingerprint
      let fingerprint;
      try {
        fingerprint = await machineId.getMachineFingerprint();
      } catch (fpError) {
        return {
          success: false,
          error: 'FINGERPRINT_ERROR',
          message: `Failed to generate machine fingerprint: ${fpError.message}`,
        };
      }
      
      // 2. Activate license with Keygen.sh
      // Requirement 19.3: Call keygen-client.activateLicense()
      const activationResult = await keygenClient.activateLicense(key, fingerprint);
      
      if (!activationResult.success) {
        // Activation failed - return error to renderer
        return {
          success: false,
          error: activationResult.error || 'ACTIVATION_FAILED',
          message: activationResult.message || 'Failed to activate license',
        };
      }
      
      // 3. Store encrypted license token
      // Requirement 19.4: Store encrypted token in AppData
      const licenseData = {
        token: activationResult.token,
        expiresAt: activationResult.expiresAt,
        storedAt: new Date().toISOString(),
      };
      
      try {
        licenseStore.storeLicense(licenseData, fingerprint);
      } catch (storeError) {
        return {
          success: false,
          error: 'STORAGE_ERROR',
          message: `Failed to store license: ${storeError.message}`,
        };
      }
      
      // 4. Update feature gates
      // Requirement 20.5: Remove all feature gates immediately when license becomes active
      const newStatus = {
        status: 'active',
        expiresAt: activationResult.expiresAt,
        fingerprint,
        gates: ACTIVE_FEATURE_GATES,
      };
      
      // 5. Push license:updated event to renderer
      // Requirement 19.5: Notify renderer of license status change
      if (win && !win.isDestroyed()) {
        win.webContents.send('license:updated', newStatus);
      }
      
      return {
        success: true,
        status: newStatus,
        message: 'License activated successfully',
      };
      
    } catch (error) {
      console.error('[license-handlers] license:activate failed:', error.message);
      return {
        success: false,
        error: 'UNEXPECTED_ERROR',
        message: `Unexpected error during activation: ${error.message}`,
      };
    }
  });

  // ── license:deactivate ───────────────────────────────────────────────────────
  // Deactivate the current license and re-apply feature gates.
  // Requirement 19.5: Deactivate via Keygen.sh and clear stored license.
  ipcMain.handle('license:deactivate', async () => {
    try {
      const licenseStore = getLicenseStore();
      const keygenClient = getKeygenClient();
      const machineId = getMachineId();
      const win = getMainWindow();
      
      // 1. Get machine fingerprint
      let fingerprint;
      try {
        fingerprint = await machineId.getMachineFingerprint();
      } catch (fpError) {
        // Continue with deactivation even if fingerprint fails
        fingerprint = 'unknown';
      }
      
      // 2. Load stored license to get token
      const storedLicense = licenseStore.loadLicense(fingerprint);
      
      if (storedLicense && storedLicense.token) {
        // 3. Deactivate with Keygen.sh
        // Requirement 19.5: Call keygen-client.deactivateLicense()
        const deactivationResult = await keygenClient.deactivateLicense(
          storedLicense.token,
          fingerprint
        );
        
        // Log if deactivation failed, but continue to clear local license
        if (!deactivationResult.success) {
          console.warn('[license-handlers] Keygen.sh deactivation failed:', deactivationResult.message);
        }
      }
      
      // 4. Clear stored license
      // Requirement 19.4: Clear encrypted license file
      licenseStore.clearLicense();
      
      // 5. Re-apply feature gates
      // Requirement 20.3: Apply feature gates when license becomes inactive
      const newStatus = {
        status: 'inactive',
        expiresAt: null,
        fingerprint,
        gates: INACTIVE_FEATURE_GATES,
      };
      
      // 6. Push license:updated event to renderer
      // Requirement 19.5: Notify renderer of license status change
      if (win && !win.isDestroyed()) {
        win.webContents.send('license:updated', newStatus);
      }
      
      return {
        success: true,
        status: newStatus,
        message: 'License deactivated successfully',
      };
      
    } catch (error) {
      console.error('[license-handlers] license:deactivate failed:', error.message);
      return {
        success: false,
        error: 'UNEXPECTED_ERROR',
        message: `Unexpected error during deactivation: ${error.message}`,
      };
    }
  });
}

module.exports = { register };
