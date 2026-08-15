/**
 * electron/ipc/__tests__/license-grace-period.property.test.js
 *
 * Property-Based Test — Property 16: License grace period boundary
 *
 * **Validates: Requirements 20.2, 20.3**
 *
 * Property:
 *   For any elapsed time in [0, 1209600] seconds since `storedAt`:
 *   - If elapsed < 604800 AND the API is unreachable (NETWORK_ERROR) → status MUST be 'grace'
 *     (full feature access, no gates applied)
 *   - If elapsed >= 604800 AND the API is unreachable (NETWORK_ERROR) → status MUST be 'inactive'
 *     (feature gates applied: scanLimit, whitelistCap, realtimeDisabled all true)
 *
 * Grace period boundary: exactly 604800 seconds (7 days) is treated as inactive
 * (elapsed >= 604800 → inactive).
 */

'use strict';

const fc = require('fast-check');
const { register } = require('../license-handlers');

// ─── Mock helpers (mirrors license-handlers.test.js patterns) ─────────────────

function createMockIpcMain() {
  const handlers = new Map();
  return {
    handle: jest.fn((channel, handler) => {
      handlers.set(channel, handler);
    }),
    _invoke: (channel, event, ...args) => {
      const handler = handlers.get(channel);
      if (!handler) throw new Error(`No handler registered for ${channel}`);
      return handler(event, ...args);
    },
    _handlers: handlers,
  };
}

/**
 * Build a fresh set of mocks wired for a specific elapsed time.
 *
 * @param {number} elapsedSeconds - seconds since the license was stored
 * @returns {{ ipcMain, deps }}
 */
function buildMocksForElapsed(elapsedSeconds) {
  // storedAt is exactly elapsedSeconds in the past
  const storedAt = new Date(Date.now() - elapsedSeconds * 1000).toISOString();

  // license-store: returns a stored license with the computed storedAt
  const mockLicenseStore = {
    loadLicense: jest.fn(() => ({
      token: 'network-error-token',
      expiresAt: '2025-12-31T23:59:59Z',
      storedAt,
    })),
    storeLicense: jest.fn(),
    clearLicense: jest.fn(),
  };

  // keygen-client: always responds with NETWORK_ERROR (API unreachable)
  const mockKeygenClient = {
    validateLicense: jest.fn(async () => ({
      success: false,
      error: 'NETWORK_ERROR',
      message: 'Failed to connect to Keygen.sh',
    })),
    activateLicense: jest.fn(),
    deactivateLicense: jest.fn(),
  };

  // machine-id: fixed fingerprint
  const mockMachineId = {
    getMachineFingerprint: jest.fn(async () => 'fixed-fingerprint-prop16'),
  };

  const deps = {
    getLicenseStore: () => mockLicenseStore,
    getKeygenClient: () => mockKeygenClient,
    getMachineId: () => mockMachineId,
    getMainWindow: () => null,
  };

  const ipcMain = createMockIpcMain();
  register(ipcMain, deps);

  return { ipcMain, deps };
}

// ─── Constants ────────────────────────────────────────────────────────────────

const GRACE_PERIOD_SECONDS = 604800; // 7 days

const ACTIVE_GATES = { scanLimit: false, whitelistCap: false, realtimeDisabled: false };
const INACTIVE_GATES = { scanLimit: true, whitelistCap: true, realtimeDisabled: true };

// ─── Property 16 ─────────────────────────────────────────────────────────────

describe('Property 16 — License grace period boundary', () => {
  /**
   * **Validates: Requirements 20.2, 20.3**
   *
   * For any elapsed seconds in [0, 1209600] (0 → 14 days):
   *   elapsed < 604800  → API unreachable → status === 'grace',  gates === ACTIVE_GATES
   *   elapsed >= 604800 → API unreachable → status === 'inactive', gates === INACTIVE_GATES
   */
  it('grace status iff elapsed < 604800; inactive at and beyond boundary (numRuns: 200)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 1209600 }),
        async (elapsedSeconds) => {
          const { ipcMain } = buildMocksForElapsed(elapsedSeconds);
          const result = await ipcMain._invoke('license:status', {});

          if (elapsedSeconds < GRACE_PERIOD_SECONDS) {
            // Requirement 20.2: within grace period → 'grace' with full feature access
            expect(result.status).toBe('grace');
            expect(result.gates).toEqual(ACTIVE_GATES);
          } else {
            // Requirement 20.3: grace period elapsed → 'inactive' with gates applied
            expect(result.status).toBe('inactive');
            expect(result.gates).toEqual(INACTIVE_GATES);
          }
        }
      ),
      {
        numRuns: 200,
        verbose: true,
      }
    );
  });

  // ─── Targeted boundary spot-checks ────────────────────────────────────────

  it('1 second before boundary (604799s) → grace', async () => {
    const { ipcMain } = buildMocksForElapsed(GRACE_PERIOD_SECONDS - 1);
    const result = await ipcMain._invoke('license:status', {});
    expect(result.status).toBe('grace');
    expect(result.gates).toEqual(ACTIVE_GATES);
  });

  it('exactly at boundary (604800s) → inactive', async () => {
    const { ipcMain } = buildMocksForElapsed(GRACE_PERIOD_SECONDS);
    const result = await ipcMain._invoke('license:status', {});
    expect(result.status).toBe('inactive');
    expect(result.gates).toEqual(INACTIVE_GATES);
  });

  it('1 second past boundary (604801s) → inactive', async () => {
    const { ipcMain } = buildMocksForElapsed(GRACE_PERIOD_SECONDS + 1);
    const result = await ipcMain._invoke('license:status', {});
    expect(result.status).toBe('inactive');
    expect(result.gates).toEqual(INACTIVE_GATES);
  });

  it('just stored (0s elapsed) → grace', async () => {
    const { ipcMain } = buildMocksForElapsed(0);
    const result = await ipcMain._invoke('license:status', {});
    expect(result.status).toBe('grace');
    expect(result.gates).toEqual(ACTIVE_GATES);
  });

  it('14 days elapsed (1209600s) → inactive', async () => {
    const { ipcMain } = buildMocksForElapsed(1209600);
    const result = await ipcMain._invoke('license:status', {});
    expect(result.status).toBe('inactive');
    expect(result.gates).toEqual(INACTIVE_GATES);
  });
});
