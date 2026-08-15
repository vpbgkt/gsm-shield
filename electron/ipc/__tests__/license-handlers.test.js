/**
 * electron/ipc/__tests__/license-handlers.test.js
 *
 * Unit tests for license IPC handlers.
 * Tests license:status, license:activate, and license:deactivate channels.
 *
 * Requirements tested: 19.2, 19.3, 19.4, 19.5, 20.1, 20.2, 20.3, 20.5
 */

const { register } = require('../license-handlers');

// ─── Mock Dependencies ────────────────────────────────────────────────────────

/**
 * Create a mock ipcMain that captures registered handlers
 */
function createMockIpcMain() {
  const handlers = new Map();
  return {
    handle: jest.fn((channel, handler) => {
      handlers.set(channel, handler);
    }),
    // Helper to invoke a registered handler
    _invoke: (channel, event, ...args) => {
      const handler = handlers.get(channel);
      if (!handler) throw new Error(`No handler registered for ${channel}`);
      return handler(event, ...args);
    },
    _handlers: handlers,
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

/**
 * Create mock license-store module
 */
function createMockLicenseStore() {
  let storedLicense = null;
  
  return {
    storeLicense: jest.fn((licenseData, fingerprint) => {
      storedLicense = { ...licenseData, fingerprint };
    }),
    loadLicense: jest.fn((fingerprint) => {
      if (storedLicense && storedLicense.fingerprint === fingerprint) {
        return {
          token: storedLicense.token,
          expiresAt: storedLicense.expiresAt,
          storedAt: storedLicense.storedAt,
        };
      }
      return null;
    }),
    clearLicense: jest.fn(() => {
      storedLicense = null;
    }),
    _getStored: () => storedLicense, // Test helper
  };
}

/**
 * Create mock keygen-client module
 */
function createMockKeygenClient() {
  return {
    activateLicense: jest.fn(async (key, fingerprint) => {
      if (key === 'VALID-KEY') {
        return {
          success: true,
          token: 'valid-token-123',
          expiresAt: '2025-12-31T23:59:59Z',
        };
      } else if (key === 'INVALID-KEY') {
        return {
          success: false,
          error: 'INVALID_KEY',
          message: 'License key is invalid',
        };
      } else if (key === 'NETWORK-ERROR-KEY') {
        return {
          success: false,
          error: 'NETWORK_ERROR',
          message: 'Failed to connect to Keygen.sh',
        };
      }
      return {
        success: false,
        error: 'UNKNOWN',
        message: 'Unknown error',
      };
    }),
    validateLicense: jest.fn(async (token) => {
      if (token === 'valid-token-123') {
        return {
          success: true,
          valid: true,
          expiresAt: '2025-12-31T23:59:59Z',
        };
      } else if (token === 'expired-token') {
        return {
          success: true,
          valid: false,
          error: 'EXPIRED',
          message: 'License has expired',
        };
      } else if (token === 'network-error-token') {
        return {
          success: false,
          error: 'NETWORK_ERROR',
          message: 'Failed to connect to Keygen.sh',
        };
      }
      return {
        success: true,
        valid: false,
        error: 'INVALID',
        message: 'License is not valid',
      };
    }),
    deactivateLicense: jest.fn(async (token, fingerprint) => {
      if (token === 'valid-token-123') {
        return { success: true };
      }
      return {
        success: false,
        error: 'DEACTIVATION_FAILED',
        message: 'Failed to deactivate',
      };
    }),
  };
}

/**
 * Create mock machine-id module
 */
function createMockMachineId() {
  return {
    getMachineFingerprint: jest.fn(async () => {
      return 'test-fingerprint-abc123';
    }),
  };
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('license-handlers', () => {
  let ipcMain;
  let mockWindow;
  let mockLicenseStore;
  let mockKeygenClient;
  let mockMachineId;
  let deps;

  beforeEach(() => {
    // Create fresh mocks for each test
    ipcMain = createMockIpcMain();
    mockWindow = createMockWindow();
    mockLicenseStore = createMockLicenseStore();
    mockKeygenClient = createMockKeygenClient();
    mockMachineId = createMockMachineId();

    deps = {
      getLicenseStore: () => mockLicenseStore,
      getKeygenClient: () => mockKeygenClient,
      getMachineId: () => mockMachineId,
      getMainWindow: () => mockWindow,
    };

    // Register handlers
    register(ipcMain, deps);
  });

  describe('license:status', () => {
    it('should return inactive status when no license is stored', async () => {
      // Requirement 19.2: Display license status
      const result = await ipcMain._invoke('license:status', {});

      expect(result).toMatchObject({
        status: 'inactive',
        expiresAt: null,
        fingerprint: 'test-fingerprint-abc123',
        gates: {
          scanLimit: true,
          whitelistCap: true,
          realtimeDisabled: true,
        },
      });
    });

    it('should return active status when license is valid', async () => {
      // Store a valid license first
      mockLicenseStore.storeLicense(
        {
          token: 'valid-token-123',
          expiresAt: '2025-12-31T23:59:59Z',
          storedAt: new Date().toISOString(),
        },
        'test-fingerprint-abc123'
      );

      // Requirement 20.1: Validate license at startup
      const result = await ipcMain._invoke('license:status', {});

      expect(result).toMatchObject({
        status: 'active',
        expiresAt: '2025-12-31T23:59:59Z',
        fingerprint: 'test-fingerprint-abc123',
        gates: {
          scanLimit: false,
          whitelistCap: false,
          realtimeDisabled: false,
        },
      });
    });

    it('should return grace status when API is unreachable and within 7 days', async () => {
      // Store a license that was stored recently (within grace period)
      const recentDate = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000); // 3 days ago
      mockLicenseStore.storeLicense(
        {
          token: 'network-error-token',
          expiresAt: '2025-12-31T23:59:59Z',
          storedAt: recentDate.toISOString(),
        },
        'test-fingerprint-abc123'
      );

      // Requirement 20.2: Grace period when API unreachable
      const result = await ipcMain._invoke('license:status', {});

      expect(result).toMatchObject({
        status: 'grace',
        fingerprint: 'test-fingerprint-abc123',
        gates: {
          scanLimit: false,
          whitelistCap: false,
          realtimeDisabled: false,
        },
      });
    });

    it('should return inactive status when grace period has elapsed', async () => {
      // Store a license that was stored 8 days ago (beyond grace period)
      const oldDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000); // 8 days ago
      mockLicenseStore.storeLicense(
        {
          token: 'network-error-token',
          expiresAt: '2025-12-31T23:59:59Z',
          storedAt: oldDate.toISOString(),
        },
        'test-fingerprint-abc123'
      );

      // Requirement 20.2, 20.3: Apply feature gates after grace period
      const result = await ipcMain._invoke('license:status', {});

      expect(result).toMatchObject({
        status: 'inactive',
        expiresAt: null,
        gates: {
          scanLimit: true,
          whitelistCap: true,
          realtimeDisabled: true,
        },
      });
    });

    it('should return inactive status when license is expired', async () => {
      // Store an expired license
      mockLicenseStore.storeLicense(
        {
          token: 'expired-token',
          expiresAt: '2020-01-01T00:00:00Z',
          storedAt: new Date().toISOString(),
        },
        'test-fingerprint-abc123'
      );

      const result = await ipcMain._invoke('license:status', {});

      expect(result).toMatchObject({
        status: 'inactive',
        expiresAt: null,
        gates: {
          scanLimit: true,
          whitelistCap: true,
          realtimeDisabled: true,
        },
      });
    });
  });

  describe('license:activate', () => {
    it('should successfully activate a valid license key', async () => {
      // Requirement 19.3: License activation with key and fingerprint
      const result = await ipcMain._invoke('license:activate', {}, { key: 'VALID-KEY' });

      expect(result.success).toBe(true);
      expect(result.status).toMatchObject({
        status: 'active',
        expiresAt: '2025-12-31T23:59:59Z',
        fingerprint: 'test-fingerprint-abc123',
        gates: {
          scanLimit: false,
          whitelistCap: false,
          realtimeDisabled: false,
        },
      });

      // Requirement 19.4: Store encrypted license token
      expect(mockLicenseStore.storeLicense).toHaveBeenCalledWith(
        expect.objectContaining({
          token: 'valid-token-123',
          expiresAt: '2025-12-31T23:59:59Z',
        }),
        'test-fingerprint-abc123'
      );
    });

    it('should push license:updated event after successful activation', async () => {
      // Requirement 19.5: Notify renderer of license status change
      await ipcMain._invoke('license:activate', {}, { key: 'VALID-KEY' });

      expect(mockWindow.webContents.send).toHaveBeenCalledWith(
        'license:updated',
        expect.objectContaining({
          status: 'active',
          gates: {
            scanLimit: false,
            whitelistCap: false,
            realtimeDisabled: false,
          },
        })
      );
    });

    it('should return error when license key is invalid', async () => {
      const result = await ipcMain._invoke('license:activate', {}, { key: 'INVALID-KEY' });

      expect(result.success).toBe(false);
      expect(result.error).toBe('INVALID_KEY');
      expect(result.message).toContain('invalid');

      // Should not store anything
      expect(mockLicenseStore.storeLicense).not.toHaveBeenCalled();
    });

    it('should return error when network fails during activation', async () => {
      const result = await ipcMain._invoke('license:activate', {}, { key: 'NETWORK-ERROR-KEY' });

      expect(result.success).toBe(false);
      expect(result.error).toBe('NETWORK_ERROR');

      // Should not store anything
      expect(mockLicenseStore.storeLicense).not.toHaveBeenCalled();
    });

    it('should handle machine fingerprint errors gracefully', async () => {
      // Mock fingerprint failure
      mockMachineId.getMachineFingerprint.mockRejectedValueOnce(
        new Error('Hardware ID not accessible')
      );

      const result = await ipcMain._invoke('license:activate', {}, { key: 'VALID-KEY' });

      expect(result.success).toBe(false);
      expect(result.error).toBe('FINGERPRINT_ERROR');
      expect(result.message).toContain('fingerprint');
    });

    it('should immediately remove feature gates after activation', async () => {
      // Requirement 20.5: Remove gates immediately without restart
      const result = await ipcMain._invoke('license:activate', {}, { key: 'VALID-KEY' });

      expect(result.success).toBe(true);
      expect(result.status.gates).toEqual({
        scanLimit: false,
        whitelistCap: false,
        realtimeDisabled: false,
      });
    });
  });

  describe('license:deactivate', () => {
    beforeEach(() => {
      // Store a valid license first
      mockLicenseStore.storeLicense(
        {
          token: 'valid-token-123',
          expiresAt: '2025-12-31T23:59:59Z',
          storedAt: new Date().toISOString(),
        },
        'test-fingerprint-abc123'
      );
    });

    it('should successfully deactivate license', async () => {
      // Requirement 19.5: Deactivate via Keygen.sh and clear stored license
      const result = await ipcMain._invoke('license:deactivate', {});

      expect(result.success).toBe(true);
      expect(result.status).toMatchObject({
        status: 'inactive',
        expiresAt: null,
        gates: {
          scanLimit: true,
          whitelistCap: true,
          realtimeDisabled: true,
        },
      });

      // Verify Keygen.sh API was called
      expect(mockKeygenClient.deactivateLicense).toHaveBeenCalledWith(
        'valid-token-123',
        'test-fingerprint-abc123'
      );

      // Verify local license was cleared
      expect(mockLicenseStore.clearLicense).toHaveBeenCalled();
    });

    it('should re-apply feature gates after deactivation', async () => {
      // Requirement 20.3: Apply feature gates when license becomes inactive
      const result = await ipcMain._invoke('license:deactivate', {});

      expect(result.success).toBe(true);
      expect(result.status.gates).toEqual({
        scanLimit: true,
        whitelistCap: true,
        realtimeDisabled: true,
      });
    });

    it('should push license:updated event after deactivation', async () => {
      // Requirement 19.5: Notify renderer of license status change
      await ipcMain._invoke('license:deactivate', {});

      expect(mockWindow.webContents.send).toHaveBeenCalledWith(
        'license:updated',
        expect.objectContaining({
          status: 'inactive',
          gates: {
            scanLimit: true,
            whitelistCap: true,
            realtimeDisabled: true,
          },
        })
      );
    });

    it('should clear local license even if Keygen.sh deactivation fails', async () => {
      // Store an invalid token that will fail deactivation
      mockLicenseStore.clearLicense.mockClear();
      mockLicenseStore.storeLicense(
        {
          token: 'invalid-token',
          expiresAt: '2025-12-31T23:59:59Z',
          storedAt: new Date().toISOString(),
        },
        'test-fingerprint-abc123'
      );

      const result = await ipcMain._invoke('license:deactivate', {});

      // Should still succeed locally
      expect(result.success).toBe(true);
      expect(mockLicenseStore.clearLicense).toHaveBeenCalled();
    });

    it('should handle missing stored license gracefully', async () => {
      // Clear the stored license first
      mockLicenseStore.clearLicense();

      const result = await ipcMain._invoke('license:deactivate', {});

      // Should still succeed (nothing to deactivate)
      expect(result.success).toBe(true);
      expect(result.status.status).toBe('inactive');
    });
  });

  describe('event emission', () => {
    it('should not push events when window is destroyed', async () => {
      mockWindow.isDestroyed.mockReturnValue(true);

      await ipcMain._invoke('license:activate', {}, { key: 'VALID-KEY' });

      expect(mockWindow.webContents.send).not.toHaveBeenCalled();
    });

    it('should not push events when window is null', async () => {
      deps.getMainWindow = () => null;

      // Re-register with null window
      const newIpcMain = createMockIpcMain();
      register(newIpcMain, deps);

      await newIpcMain._invoke('license:activate', {}, { key: 'VALID-KEY' });

      // No error should be thrown
    });
  });

  describe('error handling', () => {
    it('should return inactive status when license store fails', async () => {
      mockLicenseStore.loadLicense.mockImplementation(() => {
        throw new Error('Storage error');
      });

      const result = await ipcMain._invoke('license:status', {});

      expect(result.status).toBe('inactive');
      expect(result.gates).toEqual({
        scanLimit: true,
        whitelistCap: true,
        realtimeDisabled: true,
      });
    });

    it('should return error when license storage fails during activation', async () => {
      mockLicenseStore.storeLicense.mockImplementation(() => {
        throw new Error('Failed to write file');
      });

      const result = await ipcMain._invoke('license:activate', {}, { key: 'VALID-KEY' });

      expect(result.success).toBe(false);
      expect(result.error).toBe('STORAGE_ERROR');
      expect(result.message).toContain('store license');
    });
  });
});
