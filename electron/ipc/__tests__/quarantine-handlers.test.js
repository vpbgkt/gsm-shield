'use strict';

/**
 * electron/ipc/__tests__/quarantine-handlers.test.js
 *
 * Unit tests for quarantine IPC handlers:
 *   - quarantine:list
 *   - quarantine:restore
 *   - quarantine:restore-to
 *   - quarantine:delete
 *
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.6
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { register } = require('../quarantine-handlers');

// ─── Test setup ────────────────────────────────────────────────────────────────

describe('Quarantine IPC Handlers', () => {
  let ipcMain;
  let db;
  let quarantineModule;
  let tempDir;
  let handlers;

  beforeEach(() => {
    // Create temporary directory for test files
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'quarantine-test-'));

    // Mock IPC main
    handlers = new Map();
    ipcMain = {
      handle: jest.fn((channel, handler) => {
        handlers.set(channel, handler);
      }),
    };

    // Mock database
    db = {
      prepare: jest.fn(),
    };

    // Mock quarantine module
    quarantineModule = {
      QUARANTINE_DIR: path.join(tempDir, 'quarantine'),
      quarantineFile: jest.fn(),
      restoreFile: jest.fn(),
      deleteFile: jest.fn(),
      OriginalPathMissingError: class OriginalPathMissingError extends Error {
        constructor(message) {
          super(message);
          this.name = 'OriginalPathMissingError';
        }
      },
    };

    // Register handlers
    register(ipcMain, {
      getDb: () => db,
      getQuarantine: () => quarantineModule,
    });
  });

  afterEach(() => {
    // Clean up temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // ─── Helper to invoke handlers ─────────────────────────────────────────────
  const invoke = async (channel, args = {}) => {
    const handler = handlers.get(channel);
    if (!handler) throw new Error(`Handler not found: ${channel}`);
    return handler({}, args);
  };

  // ─── quarantine:list tests ─────────────────────────────────────────────────

  describe('quarantine:list', () => {
    it('should return all quarantine entries ordered by detected_at DESC', async () => {
      const mockEntries = [
        {
          id: 1,
          original_path: 'C:\\test\\file1.exe',
          quarantine_path: 'C:\\quarantine\\uuid1_file1.exe',
          threat_name: 'Trojan.Generic',
          file_hash: 'abc123',
          detected_at: '2024-01-02',
          file_size: 1024,
        },
        {
          id: 2,
          original_path: 'C:\\test\\file2.exe',
          quarantine_path: 'C:\\quarantine\\uuid2_file2.exe',
          threat_name: 'Virus.Win32',
          file_hash: 'def456',
          detected_at: '2024-01-01',
          file_size: 2048,
        },
      ];

      const stmt = {
        all: jest.fn().mockReturnValue(mockEntries),
      };
      db.prepare.mockReturnValue(stmt);

      const result = await invoke('quarantine:list');

      expect(result).toEqual(mockEntries);
      expect(db.prepare).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM quarantine')
      );
      expect(db.prepare).toHaveBeenCalledWith(
        expect.stringContaining('ORDER BY detected_at DESC')
      );
    });

    it('should return empty array on database error', async () => {
      db.prepare.mockImplementation(() => {
        throw new Error('Database error');
      });

      const result = await invoke('quarantine:list');

      expect(result).toEqual([]);
    });
  });

  // ─── quarantine:restore tests ──────────────────────────────────────────────

  describe('quarantine:restore', () => {
    it('should successfully restore a file to its original location', async () => {
      quarantineModule.restoreFile.mockResolvedValue(undefined);

      const result = await invoke('quarantine:restore', { id: 1 });

      expect(result).toEqual({
        success: true,
        message: 'File restored to original location.',
      });
      expect(quarantineModule.restoreFile).toHaveBeenCalledWith(1);
    });

    it('should return needsPath=true when original directory is missing', async () => {
      const error = new quarantineModule.OriginalPathMissingError(
        'Original directory no longer exists: C:\\test'
      );
      quarantineModule.restoreFile.mockRejectedValue(error);

      const result = await invoke('quarantine:restore', { id: 1 });

      expect(result).toEqual({
        success: false,
        needsPath: true,
        message: 'Original directory no longer exists: C:\\test',
      });
    });

    it('should return error on other failures', async () => {
      quarantineModule.restoreFile.mockRejectedValue(
        new Error('File not found')
      );

      const result = await invoke('quarantine:restore', { id: 1 });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to restore file');
    });
  });

  // ─── quarantine:restore-to tests ───────────────────────────────────────────

  describe('quarantine:restore-to', () => {
    it('should restore file to user-chosen destination', async () => {
      const quarantinePath = path.join(tempDir, 'quarantine', 'uuid_file.exe');
      const destPath = path.join(tempDir, 'restored', 'file.exe');

      // Create quarantine directory and file
      fs.mkdirSync(path.dirname(quarantinePath), { recursive: true });
      fs.writeFileSync(quarantinePath, 'infected content');

      // Create destination directory
      fs.mkdirSync(path.dirname(destPath), { recursive: true });

      // Mock database
      const stmt = {
        get: jest.fn().mockReturnValue({
          quarantine_path: quarantinePath,
          original_path: 'C:\\original\\file.exe',
        }),
      };
      const deleteStmt = {
        run: jest.fn(),
      };
      db.prepare.mockImplementation((sql) => {
        if (sql.includes('SELECT')) return stmt;
        if (sql.includes('DELETE')) return deleteStmt;
        return { run: jest.fn(), get: jest.fn() };
      });

      const result = await invoke('quarantine:restore-to', {
        id: 1,
        destPath,
      });

      expect(result.success).toBe(true);
      expect(result.message).toContain(destPath);
      expect(fs.existsSync(destPath)).toBe(true);
      expect(fs.existsSync(quarantinePath)).toBe(false);
      expect(deleteStmt.run).toHaveBeenCalledWith(1);
    });

    it('should return error when quarantine entry not found', async () => {
      const stmt = {
        get: jest.fn().mockReturnValue(null),
      };
      db.prepare.mockReturnValue(stmt);

      const result = await invoke('quarantine:restore-to', {
        id: 1,
        destPath: 'C:\\test\\file.exe',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should return error when quarantined file does not exist', async () => {
      const stmt = {
        get: jest.fn().mockReturnValue({
          quarantine_path: 'C:\\nonexistent\\file.exe',
          original_path: 'C:\\original\\file.exe',
        }),
      };
      db.prepare.mockReturnValue(stmt);

      const result = await invoke('quarantine:restore-to', {
        id: 1,
        destPath: 'C:\\test\\file.exe',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('no longer exists');
    });

    it('should return error when destination directory does not exist', async () => {
      const quarantinePath = path.join(tempDir, 'quarantine', 'uuid_file.exe');

      // Create quarantine file
      fs.mkdirSync(path.dirname(quarantinePath), { recursive: true });
      fs.writeFileSync(quarantinePath, 'infected content');

      const stmt = {
        get: jest.fn().mockReturnValue({
          quarantine_path: quarantinePath,
          original_path: 'C:\\original\\file.exe',
        }),
      };
      db.prepare.mockReturnValue(stmt);

      const result = await invoke('quarantine:restore-to', {
        id: 1,
        destPath: path.join(tempDir, 'nonexistent', 'file.exe'),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('does not exist');
    });
  });

  // ─── quarantine:delete tests ───────────────────────────────────────────────

  describe('quarantine:delete', () => {
    it('should permanently delete a quarantined file', async () => {
      quarantineModule.deleteFile.mockResolvedValue(undefined);

      const result = await invoke('quarantine:delete', { id: 1 });

      expect(result).toEqual({
        success: true,
        message: 'File permanently deleted.',
      });
      expect(quarantineModule.deleteFile).toHaveBeenCalledWith(1);
    });

    it('should return error on deletion failure', async () => {
      quarantineModule.deleteFile.mockRejectedValue(
        new Error('Entry not found')
      );

      const result = await invoke('quarantine:delete', { id: 1 });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to delete file');
    });
  });
});
