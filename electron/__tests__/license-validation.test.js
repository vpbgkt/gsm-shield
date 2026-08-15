/**
 * electron/__tests__/license-validation.test.js
 * 
 * Tests for license validation and feature gate logic in main.js
 * 
 * Requirements verified:
 * - 20.1: License validation at startup
 * - 20.2: Grace period handling (7 days)
 * - 20.3: Feature gates for inactive licenses
 * - 20.5: Immediate feature gate removal on activation
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Mock Electron modules
const mockTmpDir = path.join(os.tmpdir(), 'gsm-shield-test');

jest.mock('electron', () => ({
  app: {
    on: jest.fn(),
    isQuitting: false,
    getPath: jest.fn(() => mockTmpDir),
  },
  BrowserWindow: jest.fn().mockImplementation(() => ({
    loadURL: jest.fn(),
    loadFile: jest.fn(),
    once: jest.fn(),
    on: jest.fn(),
    show: jest.fn(),
    hide: jest.fn(),
    webContents: {
      send: jest.fn(),
      openDevTools: jest.fn(),
    },
  })),
  ipcMain: {
    handle: jest.fn(),
    on: jest.fn(),
  },
}));

// Mock license modules
const mockValidateLicense = jest.fn();
const mockLoadLicense = jest.fn();
const mockGetMachineFingerprint = jest.fn();

jest.mock('../../license/keygen-client', () => ({
  validateLicense: mockValidateLicense,
}));

jest.mock('../../license/license-store', () => ({
  loadLicense: mockLoadLicense,
}));

jest.mock('../../license/machine-id', () => ({
  getMachineFingerprint: mockGetMachineFingerprint,
}));

// Mock database modules
jest.mock('../../database/init', () => ({
  initDatabase: jest.fn(),
}));

jest.mock('../../database', () => ({
  getDb: jest.fn(),
}));

// Mock other modules that main.js might import
jest.mock('../tray-manager', () => ({
  createTray: jest.fn(),
}), { virtual: true });

jest.mock('../first-run', () => ({
  runFirstRunSetup: jest.fn(),
  isFirstRun: jest.fn().mockResolvedValue(false),
}), { virtual: true });

jest.mock('../ipc/whitelist-handlers', () => ({
  register: jest.fn(),
}), { virtual: true });

jest.mock('../ipc/settings-handlers', () => ({
  register: jest.fn(),
}), { virtual: true });

jest.mock('../ipc/quarantine-handlers', () => ({
  register: jest.fn(),
}), { virtual: true });

jest.mock('../../monitor/monitor', () => ({
  startMonitor: jest.fn(),
}), { virtual: true });

jest.mock('../../whitelist/sync', () => ({
  scheduleSync: jest.fn(),
}), { virtual: true });

jest.mock('better-sqlite3', () => {
  return jest.fn().mockImplementation(() => ({
    prepare: jest.fn().mockReturnValue({
      get: jest.fn().mockReturnValue({ value: '0' }),
    }),
    close: jest.fn(),
  }));
});

describe('License Validation and Feature Gates', () => {
  let originalConsoleLog;
  let originalConsoleError;

  beforeAll(() => {
    // Suppress console output during tests
    originalConsoleLog = console.log;
    originalConsoleError = console.error;
    console.log = jest.fn();
    console.error = jest.fn();
  });

  afterAll(() => {
    // Restore console
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockGetMachineFingerprint.mockResolvedValue('test-fingerprint-123');
  });

  describe('validateStoredLicense', () => {
    test('should set status to inactive when no stored license exists', async () => {
      // Arrange
      mockLoadLicense.mockReturnValue(null);

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert
      expect(state.status).toBe('inactive');
      expect(state.gates.scanLimit).toBe(true);
      expect(state.gates.whitelistCap).toBe(true);
      expect(state.gates.realtimeDisabled).toBe(true);
      expect(mockValidateLicense).not.toHaveBeenCalled();
    });

    test('should set status to active when license is valid', async () => {
      // Arrange
      const storedLicense = {
        token: 'valid-token-123',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: new Date().toISOString(),
      };
      mockLoadLicense.mockReturnValue(storedLicense);
      mockValidateLicense.mockResolvedValue({
        success: true,
        valid: true,
        expiresAt: '2025-12-31T23:59:59Z',
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert
      expect(state.status).toBe('active');
      expect(state.gates.scanLimit).toBe(false);
      expect(state.gates.whitelistCap).toBe(false);
      expect(state.gates.realtimeDisabled).toBe(false);
      expect(mockValidateLicense).toHaveBeenCalledWith('valid-token-123');
    });

    test('should set status to grace when API unreachable and within 7 days', async () => {
      // Arrange - stored 3 days ago (within grace period)
      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
      const storedLicense = {
        token: 'test-token',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: threeDaysAgo.toISOString(),
      };
      mockLoadLicense.mockReturnValue(storedLicense);
      mockValidateLicense.mockResolvedValue({
        success: false,
        error: 'NETWORK_ERROR',
        message: 'Failed to connect to Keygen.sh',
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert
      expect(state.status).toBe('grace');
      expect(state.gates.scanLimit).toBe(false);
      expect(state.gates.whitelistCap).toBe(false);
      expect(state.gates.realtimeDisabled).toBe(false);
    });

    test('should set status to inactive when API unreachable and grace period elapsed', async () => {
      // Arrange - stored 8 days ago (grace period elapsed)
      const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
      const storedLicense = {
        token: 'test-token',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: eightDaysAgo.toISOString(),
      };
      mockLoadLicense.mockReturnValue(storedLicense);
      mockValidateLicense.mockResolvedValue({
        success: false,
        error: 'NETWORK_ERROR',
        message: 'Failed to connect to Keygen.sh',
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert
      expect(state.status).toBe('inactive');
      expect(state.gates.scanLimit).toBe(true);
      expect(state.gates.whitelistCap).toBe(true);
      expect(state.gates.realtimeDisabled).toBe(true);
    });

    test('should set status to inactive when license is invalid', async () => {
      // Arrange
      const storedLicense = {
        token: 'invalid-token',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: new Date().toISOString(),
      };
      mockLoadLicense.mockReturnValue(storedLicense);
      mockValidateLicense.mockResolvedValue({
        success: true,
        valid: false,
        error: 'EXPIRED',
        message: 'License has expired',
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert
      expect(state.status).toBe('inactive');
      expect(state.gates.scanLimit).toBe(true);
      expect(state.gates.whitelistCap).toBe(true);
      expect(state.gates.realtimeDisabled).toBe(true);
    });

    test('should handle grace period boundary at exactly 7 days', async () => {
      // Arrange - stored exactly 7 days ago (604800000 milliseconds)
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const storedLicense = {
        token: 'test-token',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: sevenDaysAgo.toISOString(),
      };
      mockLoadLicense.mockReturnValue(storedLicense);
      mockValidateLicense.mockResolvedValue({
        success: false,
        error: 'NETWORK_ERROR',
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert - at exactly 7 days, should be inactive (>= threshold)
      expect(state.status).toBe('inactive');
      expect(state.gates.scanLimit).toBe(true);
    });

    test('should handle unexpected errors by applying inactive gates', async () => {
      // Arrange
      mockLoadLicense.mockImplementation(() => {
        throw new Error('Unexpected file system error');
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert - safety measure: apply inactive gates
      expect(state.status).toBe('inactive');
      expect(state.gates.scanLimit).toBe(true);
      expect(state.gates.whitelistCap).toBe(true);
      expect(state.gates.realtimeDisabled).toBe(true);
    });
  });

  describe('Feature Gates', () => {
    test('should apply all three feature gates when inactive', async () => {
      // Arrange
      mockLoadLicense.mockReturnValue(null);

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert - Requirement 20.3: scan limit, whitelist cap, real-time disabled
      expect(state.gates).toEqual({
        scanLimit: true,
        whitelistCap: true,
        realtimeDisabled: true,
      });
    });

    test('should clear all feature gates when active', async () => {
      // Arrange
      const storedLicense = {
        token: 'valid-token',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: new Date().toISOString(),
      };
      mockLoadLicense.mockReturnValue(storedLicense);
      mockValidateLicense.mockResolvedValue({
        success: true,
        valid: true,
        expiresAt: '2025-12-31T23:59:59Z',
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert - Requirement 20.5: clear all gates immediately
      expect(state.gates).toEqual({
        scanLimit: false,
        whitelistCap: false,
        realtimeDisabled: false,
      });
    });

    test('should clear all feature gates during grace period', async () => {
      // Arrange
      const oneDayAgo = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000);
      const storedLicense = {
        token: 'test-token',
        expiresAt: '2025-12-31T23:59:59Z',
        storedAt: oneDayAgo.toISOString(),
      };
      mockLoadLicense.mockReturnValue(storedLicense);
      mockValidateLicense.mockResolvedValue({
        success: false,
        error: 'NETWORK_ERROR',
      });

      // Act
      const { validateStoredLicense, getLicenseState } = require('../main');
      await validateStoredLicense();
      const state = getLicenseState();

      // Assert - grace period allows full operation
      expect(state.gates).toEqual({
        scanLimit: false,
        whitelistCap: false,
        realtimeDisabled: false,
      });
    });
  });
});
