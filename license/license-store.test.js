const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const {
  storeLicense,
  loadLicense,
  clearLicense,
  _deriveKey,
  _getLicenseStorePath
} = require('./license-store');

// Test constants
const TEST_MACHINE_FINGERPRINT = 'test-machine-fingerprint-12345';
const TEST_LICENSE_DATA = {
  token: 'test-keygen-token-xyz',
  expiresAt: '2025-12-31T23:59:59Z',
  storedAt: '2024-01-15T10:30:00Z'
};

describe('license-store', () => {
  let originalAppDataPath;
  
  beforeEach(() => {
    // Clean up any existing test license file
    clearLicense();
  });
  
  afterEach(() => {
    // Clean up after tests
    clearLicense();
  });

  describe('storeLicense', () => {
    test('should store license data successfully', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const storePath = _getLicenseStorePath();
      expect(fs.existsSync(storePath)).toBe(true);
      
      // Verify file contains base64 data
      const content = fs.readFileSync(storePath, 'utf8');
      expect(content.length).toBeGreaterThan(0);
      expect(() => Buffer.from(content, 'base64')).not.toThrow();
    });

    test('should throw error when token is missing', () => {
      const invalidData = { ...TEST_LICENSE_DATA };
      delete invalidData.token;
      
      expect(() => {
        storeLicense(invalidData, TEST_MACHINE_FINGERPRINT);
      }).toThrow('Invalid license data: missing required fields');
    });

    test('should throw error when expiresAt is missing', () => {
      const invalidData = { ...TEST_LICENSE_DATA };
      delete invalidData.expiresAt;
      
      expect(() => {
        storeLicense(invalidData, TEST_MACHINE_FINGERPRINT);
      }).toThrow('Invalid license data: missing required fields');
    });

    test('should throw error when storedAt is missing', () => {
      const invalidData = { ...TEST_LICENSE_DATA };
      delete invalidData.storedAt;
      
      expect(() => {
        storeLicense(invalidData, TEST_MACHINE_FINGERPRINT);
      }).toThrow('Invalid license data: missing required fields');
    });

    test('should throw error when machine fingerprint is missing', () => {
      expect(() => {
        storeLicense(TEST_LICENSE_DATA, '');
      }).toThrow('Machine fingerprint is required');
    });

    test('should create AppData directory if it does not exist', () => {
      const storePath = _getLicenseStorePath();
      const appDataDir = path.dirname(storePath);
      
      // Remove directory if it exists
      if (fs.existsSync(appDataDir)) {
        if (fs.existsSync(storePath)) {
          fs.unlinkSync(storePath);
        }
        // Only remove if empty to avoid deleting real data
        try {
          fs.rmdirSync(appDataDir);
        } catch (e) {
          // Directory not empty, skip
        }
      }
      
      // Store should create directory
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      expect(fs.existsSync(appDataDir)).toBe(true);
      expect(fs.existsSync(storePath)).toBe(true);
    });

    test('should use AES-256-GCM encryption with 12-byte IV', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const storePath = _getLicenseStorePath();
      const base64Data = fs.readFileSync(storePath, 'utf8');
      const combined = Buffer.from(base64Data, 'base64');
      
      // Verify structure: IV (12 bytes) + auth tag (16 bytes) + ciphertext (>= 0 bytes)
      expect(combined.length).toBeGreaterThanOrEqual(28);
      
      const iv = combined.slice(0, 12);
      expect(iv.length).toBe(12);
    });

    test('should use random IV for each encryption', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      const storePath = _getLicenseStorePath();
      const data1 = fs.readFileSync(storePath, 'utf8');
      
      clearLicense();
      
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      const data2 = fs.readFileSync(storePath, 'utf8');
      
      // Different IVs should result in different ciphertexts
      expect(data1).not.toBe(data2);
    });
  });

  describe('loadLicense', () => {
    test('should load and decrypt license data successfully', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const loaded = loadLicense(TEST_MACHINE_FINGERPRINT);
      
      expect(loaded).not.toBeNull();
      expect(loaded.token).toBe(TEST_LICENSE_DATA.token);
      expect(loaded.expiresAt).toBe(TEST_LICENSE_DATA.expiresAt);
      expect(loaded.storedAt).toBe(TEST_LICENSE_DATA.storedAt);
    });

    test('should return null when file does not exist', () => {
      const loaded = loadLicense(TEST_MACHINE_FINGERPRINT);
      expect(loaded).toBeNull();
    });

    test('should return null when machine fingerprint is wrong', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const loaded = loadLicense('wrong-fingerprint');
      expect(loaded).toBeNull();
    });

    test('should return null when machine fingerprint is missing', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const loaded = loadLicense('');
      expect(loaded).toBeNull();
    });

    test('should return null when file is corrupted', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const storePath = _getLicenseStorePath();
      fs.writeFileSync(storePath, 'corrupted-data', 'utf8');
      
      const loaded = loadLicense(TEST_MACHINE_FINGERPRINT);
      expect(loaded).toBeNull();
    });

    test('should return null when file is too short', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const storePath = _getLicenseStorePath();
      // Write data shorter than IV + auth tag (28 bytes)
      fs.writeFileSync(storePath, Buffer.from('short').toString('base64'), 'utf8');
      
      const loaded = loadLicense(TEST_MACHINE_FINGERPRINT);
      expect(loaded).toBeNull();
    });

    test('should return null when decrypted JSON is invalid', () => {
      // Store valid data first
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const storePath = _getLicenseStorePath();
      
      // Manually create encrypted data with invalid JSON
      const key = _deriveKey(TEST_MACHINE_FINGERPRINT);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      
      const invalidJson = 'not-valid-json';
      let encrypted = cipher.update(invalidJson, 'utf8');
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const authTag = cipher.getAuthTag();
      
      const combined = Buffer.concat([iv, authTag, encrypted]);
      fs.writeFileSync(storePath, combined.toString('base64'), 'utf8');
      
      const loaded = loadLicense(TEST_MACHINE_FINGERPRINT);
      expect(loaded).toBeNull();
    });

    test('should return null when license data is missing required fields', () => {
      // Store valid data first
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const storePath = _getLicenseStorePath();
      
      // Manually create encrypted data with incomplete license object
      const key = _deriveKey(TEST_MACHINE_FINGERPRINT);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      
      const incompleteData = JSON.stringify({ token: 'test' }); // missing expiresAt, storedAt
      let encrypted = cipher.update(incompleteData, 'utf8');
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const authTag = cipher.getAuthTag();
      
      const combined = Buffer.concat([iv, authTag, encrypted]);
      fs.writeFileSync(storePath, combined.toString('base64'), 'utf8');
      
      const loaded = loadLicense(TEST_MACHINE_FINGERPRINT);
      expect(loaded).toBeNull();
    });
  });

  describe('clearLicense', () => {
    test('should delete license file successfully', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      const storePath = _getLicenseStorePath();
      expect(fs.existsSync(storePath)).toBe(true);
      
      clearLicense();
      
      expect(fs.existsSync(storePath)).toBe(false);
    });

    test('should not throw when file does not exist', () => {
      expect(() => clearLicense()).not.toThrow();
    });

    test('should be idempotent', () => {
      storeLicense(TEST_LICENSE_DATA, TEST_MACHINE_FINGERPRINT);
      
      clearLicense();
      clearLicense();
      
      const storePath = _getLicenseStorePath();
      expect(fs.existsSync(storePath)).toBe(false);
    });
  });

  describe('deriveKey', () => {
    test('should derive deterministic key from fingerprint', () => {
      const key1 = _deriveKey(TEST_MACHINE_FINGERPRINT);
      const key2 = _deriveKey(TEST_MACHINE_FINGERPRINT);
      
      expect(key1.equals(key2)).toBe(true);
    });

    test('should derive 32-byte key for AES-256', () => {
      const key = _deriveKey(TEST_MACHINE_FINGERPRINT);
      expect(key.length).toBe(32);
    });

    test('should derive different keys for different fingerprints', () => {
      const key1 = _deriveKey('fingerprint-1');
      const key2 = _deriveKey('fingerprint-2');
      
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('getLicenseStorePath', () => {
    test('should return path in AppData/Roaming/GSMShieldAV', () => {
      const storePath = _getLicenseStorePath();
      const expected = path.join(os.homedir(), 'AppData', 'Roaming', 'GSMShieldAV', 'license.enc');
      
      expect(storePath).toBe(expected);
    });
  });

  describe('round-trip encryption/decryption', () => {
    test('should correctly round-trip various license data', () => {
      const testCases = [
        {
          token: 'short',
          expiresAt: '2025-01-01T00:00:00Z',
          storedAt: '2024-01-01T00:00:00Z'
        },
        {
          token: 'very-long-token-with-many-characters-' + 'x'.repeat(200),
          expiresAt: '2099-12-31T23:59:59Z',
          storedAt: '2024-06-15T12:34:56Z'
        },
        {
          token: 'token-with-special-chars-!@#$%^&*()_+-=[]{}|;:,.<>?',
          expiresAt: '2026-03-15T08:30:00Z',
          storedAt: '2024-03-15T08:30:00Z'
        }
      ];
      
      for (const testData of testCases) {
        clearLicense();
        
        storeLicense(testData, TEST_MACHINE_FINGERPRINT);
        const loaded = loadLicense(TEST_MACHINE_FINGERPRINT);
        
        expect(loaded).not.toBeNull();
        expect(loaded.token).toBe(testData.token);
        expect(loaded.expiresAt).toBe(testData.expiresAt);
        expect(loaded.storedAt).toBe(testData.storedAt);
      }
    });
  });
});
