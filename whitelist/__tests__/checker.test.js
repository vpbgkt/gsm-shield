'use strict';

/**
 * Unit tests for whitelist/checker.js
 *
 * Tests the isWhitelisted function to ensure:
 * - Returns true when file hash exists in whitelist
 * - Returns false when file hash does not exist
 * - Returns false (not throw) on file-read errors (ENOENT, EACCES, etc.)
 */

// Mock electron before requiring any module that pulls it in.
// app.getPath reads process.env.GSM_TEST_APPDATA so each test suite gets
// an isolated database directory.
jest.mock('electron', () => ({
  app: {
    getPath: (key) => {
      if (key === 'appData') {
        return process.env.GSM_TEST_APPDATA || require('os').tmpdir();
      }
      return require('os').tmpdir();
    },
  },
  dialog: { showErrorBox: jest.fn() },
}));

const { initDatabase, closeDatabase } = require('../../database/init');
const { isWhitelisted } = require('../checker');
const { hashFile } = require('../hasher');
const { entryExists, insertEntry } = require('../db');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Create a temporary directory for test files
let testDir;

beforeAll(() => {
  // Use a unique appData directory for this test suite to avoid DB cross-contamination
  const newDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsm-checker-test-'));
  process.env.GSM_TEST_APPDATA = newDir;

  testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'checker-test-'));
  initDatabase();
});

afterAll(() => {
  closeDatabase();
  delete process.env.GSM_TEST_APPDATA;
  // Clean up test directory
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
});

describe('isWhitelisted', () => {
  test('returns true when file hash exists in whitelist', async () => {
    // Create a test file
    const testFilePath = path.join(testDir, 'whitelisted-file.txt');
    fs.writeFileSync(testFilePath, 'This file should be whitelisted');

    // Get its hash and add to whitelist
    const hash = await hashFile(testFilePath);
    insertEntry({
      hash,
      name: 'Test Whitelisted File',
      vendor: 'Test Vendor',
      source: 'user',
      verified: 0,
    });

    // Verify it exists
    expect(entryExists(hash)).toBe(true);

    // Check isWhitelisted returns true
    const result = await isWhitelisted(testFilePath);
    expect(result).toBe(true);
  });

  test('returns false when file hash does not exist in whitelist', async () => {
    // Create a test file that is not whitelisted
    const testFilePath = path.join(testDir, 'non-whitelisted-file.txt');
    fs.writeFileSync(testFilePath, 'This file is not whitelisted');

    // Check isWhitelisted returns false
    const result = await isWhitelisted(testFilePath);
    expect(result).toBe(false);
  });

  test('returns false when file does not exist (ENOENT)', async () => {
    // Try to check a non-existent file
    const nonExistentPath = path.join(testDir, 'does-not-exist.txt');

    // Should not throw, should return false
    const result = await isWhitelisted(nonExistentPath);
    expect(result).toBe(false);
  });

  test('returns false on permission denied errors (EACCES)', async () => {
    // Create a file with restricted permissions (Unix-like systems)
    const testFilePath = path.join(testDir, 'no-permission.txt');
    fs.writeFileSync(testFilePath, 'Cannot read this');

    try {
      // Remove read permissions
      fs.chmodSync(testFilePath, 0o000);

      // Should not throw, should return false
      const result = await isWhitelisted(testFilePath);
      expect(result).toBe(false);
    } finally {
      // Restore permissions for cleanup
      try {
        fs.chmodSync(testFilePath, 0o644);
      } catch (err) {
        // Ignore cleanup errors
      }
    }
  });

  test('handles various file content types correctly', async () => {
    // Create files with different content
    const textFile = path.join(testDir, 'text.txt');
    const binaryFile = path.join(testDir, 'binary.bin');

    fs.writeFileSync(textFile, 'Plain text content');
    fs.writeFileSync(binaryFile, Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]));

    // Add text file to whitelist
    const textHash = await hashFile(textFile);
    insertEntry({
      hash: textHash,
      name: 'Text File',
      source: 'user',
    });

    // Text file should be whitelisted
    expect(await isWhitelisted(textFile)).toBe(true);

    // Binary file should not be whitelisted
    expect(await isWhitelisted(binaryFile)).toBe(false);
  });
});
