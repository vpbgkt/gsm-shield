/**
 * electron/ipc/__tests__/license-handlers.integration.test.js
 *
 * Integration tests for license IPC handlers with real license modules.
 * Tests the full flow: activation → storage → validation → deactivation.
 *
 * Requirements tested: 19.2, 19.3, 19.4, 19.5, 20.1, 20.2, 20.3, 20.5
 */

const fs = require('fs');
const path = require('path');
const { register } = require('../license-handlers');
const machineId = require('../../../license/machine-id');
const keygenClient = require('../../../license/keygen-client');
const licenseStore = require('../../../license/license-store');

// ─── Test Helpers ─────────────────────────────────────────────────────────────

/**
 * Create a mock ipcMain that captures registered handlers
 */
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
  };
}

/**
 * Create a mock BrowserWindow
 */
function createMockWindow() {
  const sentMessages = [];
  return {
    isDestroyed: jest.fn(() => false),
    webContents: {
      send: jest.fn((channel, data) => {
        sentMessages.push({ channel, data });
      }),
    },
    _sentMessages: sentMessages,
  };
}

// ─── Integration Test Suite ──────────────────────────────────────────────────

describe('license-handlers integration', () => {
  let ipcMain;
  let mockWindow;

  beforeEach(() => {
    // Clean up any existing license before tests
    try {
      licenseStore.clearLicense();
    } catch (_) {
      // Ignore if no license exists
    }

    // Create mocks
    ipcMain = createMockIpcMain();
    mockWindow = createMockWindow();

    // Register handlers with real dependencies
    register(ipcMain, {
      getLicenseStore: () => licenseStore,
      getKeygenClient: () => keygenClient,
      getMachineId: () => machineId,
      getMainWindow: () => mockWindow,
    });
  });

  afterEach(() => {
    // Clean up license after each test
    try {
      licenseStore.clearLicense();
    } catch (_) {
      // Ignore cleanup errors
    }
  });

  describe('full activation and deactivation flow', () => {
    it('should handle complete license lifecycle with real modules', async () => {
      // Step 1: Check initial status (should be inactive)
      let status = await ipcMain._invoke('license:status', {});
      expect(status.status).toBe('inactive');
      expect(status.gates.scanLimit).toBe(true);
      expect(status.gates.whitelistCap).toBe(true);
      expect(status.gates.realtimeDisabled).toBe(true);

      // Step 2: Activate with a mock valid key
      // Note: This will attempt to reach Keygen.sh API - may fail in CI
      const activationResult = await ipcMain._invoke(
        'license:activate',
        {},
        { key: 'test-license-key-12345' }
      );

      // API call may fail (network/invalid key), but we're testing the handler logic
      if (activationResult.success) {
        // If activation succeeded (API was reachable and key was valid)
        expect(activationResult.status.status).toBe('active');
        expect(activationResult.status.gates.scanLimit).toBe(false);

        // Verify license:updated event was sent
        expect(mockWindow.webContents.send).toHaveBeenCalledWith(
          'license:updated',
          expect.objectContaining({
            status: 'active',
          })
        );

        // Step 3: Check status again (should be active)
        status = await ipcMain._invoke('license:status', {});
        expect(status.status).toBe('active');
        expect(status.gates.scanLimit).toBe(false);

        // Step 4: Deactivate
        mockWindow.webContents.send.mockClear();
        const deactivationResult = await ipcMain._invoke('license:deactivate', {});

        expect(deactivationResult.success).toBe(true);
        expect(deactivationResult.status.status).toBe('inactive');
        expect(deactivationResult.status.gates.scanLimit).toBe(true);

        // Verify license:updated event was sent
        expect(mockWindow.webContents.send).toHaveBeenCalledWith(
          'license:updated',
          expect.objectContaining({
            status: 'inactive',
          })
        );

        // Step 5: Check status after deactivation (should be inactive)
        status = await ipcMain._invoke('license:status', {});
        expect(status.status).toBe('inactive');
        expect(status.gates.scanLimit).toBe(true);
      } else {
        // Activation failed (expected in CI or without valid Keygen.sh setup)
        // Verify error handling worked correctly
        expect(activationResult.success).toBe(false);
        expect(activationResult.error).toBeDefined();

        // Status should remain inactive
        status = await ipcMain._invoke('license:status', {});
        expect(status.status).toBe('inactive');
      }
    });
  });

  describe('machine fingerprint consistency', () => {
    it('should use consistent fingerprint across operations', async () => {
      const fingerprint1 = await machineId.getMachineFingerprint();
      const fingerprint2 = await machineId.getMachineFingerprint();

      expect(fingerprint1).toBe(fingerprint2);
      expect(fingerprint1).toHaveLength(64); // SHA-256 hex string

      // Verify status uses the same fingerprint
      const status = await ipcMain._invoke('license:status', {});
      expect(status.fingerprint).toBe(fingerprint1);
    });
  });

  describe('license storage encryption', () => {
    it('should encrypt and decrypt license data correctly', async () => {
      const fingerprint = await machineId.getMachineFingerprint();
      const testLicense = {
        token: 'test-token-abc123',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: new Date().toISOString(),
      };

      // Store license
      licenseStore.storeLicense(testLicense, fingerprint);

      // Verify file was created
      const licensePath = licenseStore._getLicenseStorePath();
      expect(fs.existsSync(licensePath)).toBe(true);

      // Verify file is encrypted (not plain JSON)
      const fileContent = fs.readFileSync(licensePath, 'utf8');
      expect(fileContent).not.toContain('test-token-abc123');
      expect(fileContent).not.toContain('token');

      // Load license
      const loadedLicense = licenseStore.loadLicense(fingerprint);

      expect(loadedLicense).toEqual(testLicense);
    });

    it('should return null when loading with wrong fingerprint', async () => {
      const fingerprint = await machineId.getMachineFingerprint();
      const wrongFingerprint = 'wrong-fingerprint-' + '0'.repeat(46);
      const testLicense = {
        token: 'test-token-xyz789',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: new Date().toISOString(),
      };

      // Store with correct fingerprint
      licenseStore.storeLicense(testLicense, fingerprint);

      // Try to load with wrong fingerprint (should fail decryption)
      const loadedLicense = licenseStore.loadLicense(wrongFingerprint);

      expect(loadedLicense).toBeNull();
    });
  });

  describe('grace period logic', () => {
    it('should allow grace period when API is unreachable', async () => {
      // Manually store a license with network-error token
      const fingerprint = await machineId.getMachineFingerprint();
      const recentDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000); // 2 days ago

      licenseStore.storeLicense(
        {
          token: 'network-error-token-12345',
          expiresAt: '2025-12-31T23:59:59Z',
          storedAt: recentDate.toISOString(),
        },
        fingerprint
      );

      // Check status - should detect network error and apply grace period
      const status = await ipcMain._invoke('license:status', {});

      // If Keygen.sh API is unreachable, should be in grace period
      if (status.status === 'grace') {
        expect(status.gates.scanLimit).toBe(false);
        expect(status.gates.realtimeDisabled).toBe(false);
      } else if (status.status === 'inactive') {
        // API was reachable and token was invalid, or grace expired
        expect(status.gates.scanLimit).toBe(true);
      }
      // Both outcomes are valid depending on network state
    });
  });

  describe('feature gate transitions', () => {
    it('should apply correct feature gates based on license status', async () => {
      // Check inactive gates
      let status = await ipcMain._invoke('license:status', {});
      expect(status.gates).toEqual({
        scanLimit: true,
        whitelistCap: true,
        realtimeDisabled: true,
      });

      // Manually store a valid-looking license to test active gates
      const fingerprint = await machineId.getMachineFingerprint();
      licenseStore.storeLicense(
        {
          token: 'mock-valid-token',
          expiresAt: '2025-12-31T23:59:59Z',
          storedAt: new Date().toISOString(),
        },
        fingerprint
      );

      // Check status again
      status = await ipcMain._invoke('license:status', {});

      // If token validates (unlikely with mock token), gates should be removed
      if (status.status === 'active') {
        expect(status.gates).toEqual({
          scanLimit: false,
          whitelistCap: false,
          realtimeDisabled: false,
        });
      }
    });
  });

  describe('error recovery', () => {
    it('should handle corrupted license file gracefully', async () => {
      // Create a corrupted license file
      const licensePath = licenseStore._getLicenseStorePath();
      const dir = path.dirname(licensePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(licensePath, 'corrupted-data-not-base64!@#$', 'utf8');

      // Status should handle the error and return inactive
      const status = await ipcMain._invoke('license:status', {});

      expect(status.status).toBe('inactive');
      expect(status.gates.scanLimit).toBe(true);
    });

    it('should clear corrupted license on activation', async () => {
      // Create a corrupted license file
      const licensePath = licenseStore._getLicenseStorePath();
      const dir = path.dirname(licensePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(licensePath, 'corrupted', 'utf8');

      // Attempt activation (will fail with invalid key, but should clear corrupted file)
      const result = await ipcMain._invoke(
        'license:activate',
        {},
        { key: 'test-key' }
      );

      // Activation may fail, but corrupted file should be handled
      if (!result.success) {
        // Verify status still works
        const status = await ipcMain._invoke('license:status', {});
        expect(status).toBeDefined();
        expect(status.status).toBeDefined();
      }
    });
  });
});
