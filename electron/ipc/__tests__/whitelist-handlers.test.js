'use strict';

/**
 * electron/ipc/__tests__/whitelist-handlers.test.js
 *
 * Unit tests for whitelist IPC handlers.
 * Tests Requirements 3.1, 3.2, 3.3, 3.5, 5.1, 5.2, 5.3, 5.4.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const Database = require('better-sqlite3');
const { register } = require('../whitelist-handlers');

describe('Whitelist IPC Handlers', () => {
  let db;
  let dbPath;
  let ipcMain;
  let handlers;
  let mockHasher;
  let mockWhitelistDb;
  let mockSync;
  let mockLicense;

  beforeEach(() => {
    // Create an in-memory SQLite database for testing
    dbPath = path.join(os.tmpdir(), `test-whitelist-${Date.now()}.db`);
    db = new Database(dbPath);

    // Create whitelist table schema
    db.exec(`
      CREATE TABLE IF NOT EXISTS whitelist (
        hash       TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        vendor     TEXT NOT NULL DEFAULT '',
        verified   INTEGER NOT NULL DEFAULT 0,
        source     TEXT NOT NULL CHECK(source IN ('bundled', 'user', 'cloud')),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // Mock IPC handler registry
    handlers = {};
    ipcMain = {
      handle: jest.fn((channel, handler) => {
        handlers[channel] = handler;
      }),
    };

    // Mock dependencies
    mockHasher = {
      hashFile: jest.fn(),
    };

    mockWhitelistDb = {
      listEntries: jest.fn(),
      entryExists: jest.fn(),
      insertEntry: jest.fn(),
      deleteEntry: jest.fn(),
      countUserEntries: jest.fn(),
    };

    mockSync = {
      syncFromCloud: jest.fn(),
    };

    mockLicense = jest.fn(() => ({ status: 'active' }));

    // Register handlers with mocks
    register(ipcMain, {
      getDb: () => db,
      getHasher: () => mockHasher,
      getWhitelistDb: () => mockWhitelistDb,
      getSync: () => mockSync,
      getLicense: mockLicense,
    });
  });

  afterEach(() => {
    if (db) {
      db.close();
    }
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
  });

  // ─── whitelist:list tests ───────────────────────────────────────────────────

  describe('whitelist:list', () => {
    it('should return all entries when no query provided', async () => {
      const mockEntries = [
        { hash: 'abc123', name: 'Tool1', vendor: 'Vendor1', source: 'bundled', verified: 1 },
        { hash: 'def456', name: 'Tool2', vendor: 'Vendor2', source: 'user', verified: 0 },
      ];
      mockWhitelistDb.listEntries.mockReturnValue(mockEntries);

      const result = await handlers['whitelist:list']({}, {});

      expect(mockWhitelistDb.listEntries).toHaveBeenCalledWith(undefined);
      expect(result).toEqual(mockEntries);
    });

    it('should pass query to listEntries when provided', async () => {
      mockWhitelistDb.listEntries.mockReturnValue([]);

      await handlers['whitelist:list']({}, { query: 'odin' });

      expect(mockWhitelistDb.listEntries).toHaveBeenCalledWith('odin');
    });

    it('should return empty array on error', async () => {
      mockWhitelistDb.listEntries.mockImplementation(() => {
        throw new Error('Database error');
      });

      const result = await handlers['whitelist:list']({}, {});

      expect(result).toEqual([]);
    });
  });

  // ─── whitelist:add tests ────────────────────────────────────────────────────

  describe('whitelist:add', () => {
    it('should hash file, check duplicate, and insert entry (Requirement 3.1)', async () => {
      const testFilePath = '/path/to/tool.exe';
      const testHash = 'a'.repeat(64);

      mockHasher.hashFile.mockResolvedValue(testHash);
      mockWhitelistDb.entryExists.mockReturnValue(false);
      mockWhitelistDb.countUserEntries.mockReturnValue(5);

      const result = await handlers['whitelist:add']({}, { filePath: testFilePath });

      expect(mockHasher.hashFile).toHaveBeenCalledWith(testFilePath);
      expect(mockWhitelistDb.entryExists).toHaveBeenCalledWith(testHash);
      expect(mockWhitelistDb.insertEntry).toHaveBeenCalledWith({
        hash: testHash,
        name: 'tool.exe',
        vendor: '',
        source: 'user',
        verified: 0,
      });
      expect(result.success).toBe(true);
      expect(result.hash).toBe(testHash);
    });

    it('should return duplicate flag when file already exists (Requirement 3.2)', async () => {
      const testFilePath = '/path/to/tool.exe';
      const testHash = 'b'.repeat(64);

      mockHasher.hashFile.mockResolvedValue(testHash);
      mockWhitelistDb.entryExists.mockReturnValue(true);

      const result = await handlers['whitelist:add']({}, { filePath: testFilePath });

      expect(result.success).toBe(false);
      expect(result.duplicate).toBe(true);
      expect(mockWhitelistDb.insertEntry).not.toHaveBeenCalled();
    });

    it('should enforce 10-entry cap when license is inactive (Requirement 3.5)', async () => {
      const testFilePath = '/path/to/tool.exe';
      const testHash = 'c'.repeat(64);

      mockHasher.hashFile.mockResolvedValue(testHash);
      mockWhitelistDb.entryExists.mockReturnValue(false);
      mockWhitelistDb.countUserEntries.mockReturnValue(10); // At cap
      mockLicense.mockReturnValue({ status: 'inactive' });

      const result = await handlers['whitelist:add']({}, { filePath: testFilePath });

      expect(result.success).toBe(false);
      expect(result.capReached).toBe(true);
      expect(mockWhitelistDb.insertEntry).not.toHaveBeenCalled();
    });

    it('should allow adding entries beyond 10 when license is active', async () => {
      const testFilePath = '/path/to/tool.exe';
      const testHash = 'd'.repeat(64);

      mockHasher.hashFile.mockResolvedValue(testHash);
      mockWhitelistDb.entryExists.mockReturnValue(false);
      mockWhitelistDb.countUserEntries.mockReturnValue(15); // Beyond cap
      mockLicense.mockReturnValue({ status: 'active' });

      const result = await handlers['whitelist:add']({}, { filePath: testFilePath });

      expect(result.success).toBe(true);
      expect(mockWhitelistDb.insertEntry).toHaveBeenCalled();
    });

    it('should handle file hashing errors', async () => {
      const testFilePath = '/nonexistent/tool.exe';

      mockHasher.hashFile.mockRejectedValue(new Error('File not found'));

      const result = await handlers['whitelist:add']({}, { filePath: testFilePath });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to hash file');
    });
  });

  // ─── whitelist:remove tests ─────────────────────────────────────────────────

  describe('whitelist:remove', () => {
    it('should delete user entry successfully (Requirement 3.3)', async () => {
      const testHash = 'e'.repeat(64);

      mockWhitelistDb.deleteEntry.mockReturnValue({ success: true });

      const result = await handlers['whitelist:remove']({}, { hash: testHash });

      expect(mockWhitelistDb.deleteEntry).toHaveBeenCalledWith(testHash);
      expect(result.success).toBe(true);
    });

    it('should return forbidden when trying to delete bundled/cloud entry (Requirement 3.3)', async () => {
      const testHash = 'f'.repeat(64);

      mockWhitelistDb.deleteEntry.mockReturnValue({ success: false, forbidden: true });

      const result = await handlers['whitelist:remove']({}, { hash: testHash });

      expect(result.success).toBe(false);
      expect(result.forbidden).toBe(true);
    });

    it('should handle non-existent entries', async () => {
      const testHash = 'g'.repeat(64);

      mockWhitelistDb.deleteEntry.mockReturnValue({ success: false });

      const result = await handlers['whitelist:remove']({}, { hash: testHash });

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
    });
  });

  // ─── whitelist:submit tests ─────────────────────────────────────────────────

  describe('whitelist:submit', () => {
    it('should return invalid_hash for invalid hashes (Requirement 5.4)', async () => {
      const invalidHashes = [
        'short',                          // Too short
        'z'.repeat(64),                   // Invalid hex chars
        'a'.repeat(63),                   // 63 chars
        'a'.repeat(65),                   // 65 chars
        '',                               // Empty
        'A'.repeat(64),                   // Uppercase hex — must be lowercase only
        'aBcDeF'.padEnd(64, '0'),         // Mixed case — rejected
      ];

      for (const hash of invalidHashes) {
        const result = await handlers['whitelist:submit']({}, {
          hash,
          name: 'Tool',
          vendor: 'Vendor',
        });

        expect(result.success).toBe(false);
        expect(result.error).toBe('invalid_hash');
      }
    });

    it('should accept valid 64-char lowercase hex hash and return { success: true }', async () => {
      const validHash = 'a'.repeat(64); // all lowercase hex

      // Mock successful backend submission
      const https = require('https');
      const mockRequest = {
        write: jest.fn(),
        end: jest.fn(),
        on: jest.fn(),
      };
      jest.spyOn(https, 'request').mockImplementation((options, callback) => {
        // Simulate successful response
        setImmediate(() => {
          const mockResponse = {
            statusCode: 200,
            on: jest.fn((event, handler) => {
              if (event === 'data') {
                // No data needed
              } else if (event === 'end') {
                setImmediate(handler);
              }
            }),
          };
          callback(mockResponse);
        });
        return mockRequest;
      });

      const result = await handlers['whitelist:submit']({}, {
        hash: validHash,
        name: 'Test Tool',
        vendor: 'Test Vendor',
      });

      expect(result).toEqual({ success: true });

      https.request.mockRestore();
    });

    it('should reject submission with empty name (Requirement 5.4)', async () => {
      const validHash = 'b'.repeat(64);

      const result = await handlers['whitelist:submit']({}, {
        hash: validHash,
        name: '',
        vendor: 'Vendor',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('name_required');
    });

    it('should return descriptive error on non-2xx backend response (Requirement 5.3)', async () => {
      const validHash = 'c'.repeat(64);

      const https = require('https');
      const mockRequest = {
        write: jest.fn(),
        end: jest.fn(),
        on: jest.fn(),
      };
      jest.spyOn(https, 'request').mockImplementation((options, callback) => {
        setImmediate(() => {
          const mockResponse = {
            statusCode: 500,
            on: jest.fn((event, handler) => {
              if (event === 'data') handler('Internal Server Error');
              else if (event === 'end') setImmediate(handler);
            }),
          };
          callback(mockResponse);
        });
        return mockRequest;
      });

      const result = await handlers['whitelist:submit']({}, {
        hash: validHash,
        name: 'Tool',
        vendor: 'Vendor',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('500');

      https.request.mockRestore();
    });

    it('should return descriptive error on network failure without throwing (Requirement 5.3)', async () => {
      const validHash = 'd'.repeat(64);

      const https = require('https');
      const mockRequest = {
        write: jest.fn(),
        end: jest.fn(),
        on: jest.fn((event, handler) => {
          if (event === 'error') setImmediate(() => handler(new Error('ECONNREFUSED')));
        }),
      };
      jest.spyOn(https, 'request').mockImplementation(() => mockRequest);

      const result = await handlers['whitelist:submit']({}, {
        hash: validHash,
        name: 'Tool',
        vendor: 'Vendor',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Network error');

      https.request.mockRestore();
    });

    it('should send Authorization header when API_KEY is set (Requirement 5.1)', async () => {
      const validHash = 'e'.repeat(64);
      process.env.API_KEY = 'test-api-key-12345';

      const https = require('https');
      let capturedOptions = null;
      const mockRequest = {
        write: jest.fn(),
        end: jest.fn(),
        on: jest.fn(),
      };
      jest.spyOn(https, 'request').mockImplementation((options, callback) => {
        capturedOptions = options;
        setImmediate(() => {
          const mockResponse = {
            statusCode: 201,
            on: jest.fn((event, handler) => {
              if (event === 'end') setImmediate(handler);
            }),
          };
          callback(mockResponse);
        });
        return mockRequest;
      });

      const result = await handlers['whitelist:submit']({}, {
        hash: validHash,
        name: 'Tool',
        vendor: 'Vendor',
      });

      expect(result).toEqual({ success: true });
      expect(capturedOptions.headers['Authorization']).toBe('Bearer test-api-key-12345');

      delete process.env.API_KEY;
      https.request.mockRestore();
    });
  });

  // ─── whitelist:sync tests ───────────────────────────────────────────────────

  describe('whitelist:sync', () => {
    it('should delegate to sync.syncFromCloud() (Requirement 4.4)', async () => {
      const mockResult = {
        added: 5,
        updated: 3,
        timestamp: '2024-01-15T10:00:00Z',
      };

      mockSync.syncFromCloud.mockResolvedValue(mockResult);

      const result = await handlers['whitelist:sync']({}, {});

      expect(mockSync.syncFromCloud).toHaveBeenCalled();
      expect(result.success).toBe(true);
      expect(result.added).toBe(5);
      expect(result.updated).toBe(3);
    });

    it('should handle sync errors gracefully', async () => {
      mockSync.syncFromCloud.mockRejectedValue(new Error('Network error'));

      const result = await handlers['whitelist:sync']({}, {});

      expect(result.success).toBe(false);
      expect(result.error).toContain('Sync failed');
    });
  });
});
