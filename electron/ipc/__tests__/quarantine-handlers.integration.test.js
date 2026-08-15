'use strict';

/**
 * electron/ipc/__tests__/quarantine-handlers.integration.test.js
 *
 * Integration tests for quarantine IPC handlers with real database and file system.
 * Tests the complete quarantine flow: list, restore, restore-to, delete.
 *
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.6
 */

'use strict';

/**
 * electron/ipc/__tests__/quarantine-handlers.integration.test.js
 *
 * Integration tests for quarantine IPC handlers with real database.
 * Tests the complete quarantine flow: list, restore, restore-to, delete.
 *
 * Note: These tests mock the quarantine module since it requires database
 * initialization that's tied to Electron app lifecycle. The unit tests in
 * quarantine-handlers.test.js verify the handler logic.
 *
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.6
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const Database = require('better-sqlite3');
const { register } = require('../quarantine-handlers');

describe('Quarantine IPC Handlers - Integration', () => {
  let ipcMain;
  let db;
  let tempDir;
  let dbPath;
  let handlers;
  let quarantineDir;
  let mockQuarantine;

  beforeEach(() => {
    // Create temporary directory
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'quarantine-integration-'));
    dbPath = path.join(tempDir, 'test.db');
    quarantineDir = path.join(tempDir, 'quarantine');

    // Create real database with quarantine table
    db = new Database(dbPath);
    db.exec(`
      CREATE TABLE IF NOT EXISTS quarantine (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        original_path   TEXT NOT NULL,
        quarantine_path TEXT NOT NULL,
        threat_name     TEXT NOT NULL,
        file_hash       TEXT NOT NULL,
        detected_at     TEXT NOT NULL DEFAULT (datetime('now')),
        file_size       INTEGER NOT NULL DEFAULT 0
      )
    `);

    // Create quarantine directory
    fs.mkdirSync(quarantineDir, { recursive: true });

    // Mock quarantine module that works with real files
    mockQuarantine = {
      QUARANTINE_DIR: quarantineDir,
      
      quarantineFile: jest.fn(async (filePath, threatName) => {
        // Simplified version that adds to DB
        const quarantinePath = path.join(quarantineDir, `test_${path.basename(filePath)}`);
        fs.renameSync(filePath, quarantinePath);
        
        db.prepare(`
          INSERT INTO quarantine (original_path, quarantine_path, threat_name, file_hash, file_size)
          VALUES (?, ?, ?, ?, ?)
        `).run(filePath, quarantinePath, threatName, 'abc123hash', 1024);
      }),

      restoreFile: jest.fn(async (id) => {
        const record = db.prepare('SELECT * FROM quarantine WHERE id = ?').get(id);
        if (!record) throw new Error('Entry not found');
        
        const originalDir = path.dirname(record.original_path);
        if (!fs.existsSync(originalDir)) {
          const error = new Error(`Original directory no longer exists: ${originalDir}`);
          error.name = 'OriginalPathMissingError';
          throw error;
        }
        
        fs.renameSync(record.quarantine_path, record.original_path);
        db.prepare('DELETE FROM quarantine WHERE id = ?').run(id);
      }),

      deleteFile: jest.fn(async (id) => {
        const record = db.prepare('SELECT * FROM quarantine WHERE id = ?').get(id);
        if (!record) throw new Error('Entry not found');
        
        if (fs.existsSync(record.quarantine_path)) {
          fs.unlinkSync(record.quarantine_path);
        }
        db.prepare('DELETE FROM quarantine WHERE id = ?').run(id);
      }),

      OriginalPathMissingError: class OriginalPathMissingError extends Error {
        constructor(message) {
          super(message);
          this.name = 'OriginalPathMissingError';
        }
      },
    };

    // Mock IPC main
    handlers = new Map();
    ipcMain = {
      handle: jest.fn((channel, handler) => {
        handlers.set(channel, handler);
      }),
    };

    // Register handlers with real DB and mock quarantine
    register(ipcMain, {
      getDb: () => db,
      getQuarantine: () => mockQuarantine,
    });
  });

  afterEach(() => {
    if (db) {
      db.close();
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // Helper to invoke handlers
  const invoke = async (channel, args = {}) => {
    const handler = handlers.get(channel);
    if (!handler) throw new Error(`Handler not found: ${channel}`);
    return handler({}, args);
  };

  describe('Complete quarantine workflow', () => {
    it('should list, restore, and delete quarantined files', async () => {
      // 1. Create a test file and quarantine it
      const originalPath = path.join(tempDir, 'original', 'infected.exe');
      fs.mkdirSync(path.dirname(originalPath), { recursive: true });
      fs.writeFileSync(originalPath, 'malicious content');

      await mockQuarantine.quarantineFile(originalPath, 'Trojan.Generic');

      // 2. List quarantine entries - should have 1 entry
      let result = await invoke('quarantine:list');
      expect(result).toHaveLength(1);
      expect(result[0].threat_name).toBe('Trojan.Generic');
      expect(result[0].original_path).toBe(originalPath);
      expect(fs.existsSync(originalPath)).toBe(false); // Original removed

      const quarantineId = result[0].id;
      const quarantinePath = result[0].quarantine_path;
      expect(fs.existsSync(quarantinePath)).toBe(true); // In quarantine

      // 3. Restore the file
      const restoreResult = await invoke('quarantine:restore', { id: quarantineId });
      expect(restoreResult.success).toBe(true);
      expect(fs.existsSync(originalPath)).toBe(true); // Restored
      expect(fs.existsSync(quarantinePath)).toBe(false); // No longer in quarantine

      // 4. Verify quarantine list is empty
      result = await invoke('quarantine:list');
      expect(result).toHaveLength(0);
    });

    it('should handle restore-to when original directory is deleted', async () => {
      // 1. Create and quarantine a file
      const originalPath = path.join(tempDir, 'original', 'infected.exe');
      fs.mkdirSync(path.dirname(originalPath), { recursive: true });
      fs.writeFileSync(originalPath, 'malicious content');

      await mockQuarantine.quarantineFile(originalPath, 'Virus.Win32');

      // 2. Delete the original directory
      fs.rmSync(path.dirname(originalPath), { recursive: true, force: true });

      // 3. List and get quarantine ID
      let result = await invoke('quarantine:list');
      expect(result).toHaveLength(1);
      const quarantineId = result[0].id;

      // 4. Try to restore - should return needsPath=true
      const restoreResult = await invoke('quarantine:restore', { id: quarantineId });
      expect(restoreResult.success).toBe(false);
      expect(restoreResult.needsPath).toBe(true);

      // 5. Use restore-to with a new destination
      const newDestPath = path.join(tempDir, 'restored', 'recovered.exe');
      fs.mkdirSync(path.dirname(newDestPath), { recursive: true });

      const restoreToResult = await invoke('quarantine:restore-to', {
        id: quarantineId,
        destPath: newDestPath,
      });

      expect(restoreToResult.success).toBe(true);
      expect(fs.existsSync(newDestPath)).toBe(true);
      expect(fs.readFileSync(newDestPath, 'utf8')).toBe('malicious content');

      // 6. Verify quarantine list is empty
      result = await invoke('quarantine:list');
      expect(result).toHaveLength(0);
    });

    it('should permanently delete quarantined files', async () => {
      // 1. Create and quarantine a file
      const originalPath = path.join(tempDir, 'original', 'infected.exe');
      fs.mkdirSync(path.dirname(originalPath), { recursive: true });
      fs.writeFileSync(originalPath, 'malicious content');

      await mockQuarantine.quarantineFile(originalPath, 'Malware.Generic');

      // 2. List and get quarantine info
      let result = await invoke('quarantine:list');
      expect(result).toHaveLength(1);
      const quarantineId = result[0].id;
      const quarantinePath = result[0].quarantine_path;

      expect(fs.existsSync(quarantinePath)).toBe(true);

      // 3. Delete permanently
      const deleteResult = await invoke('quarantine:delete', { id: quarantineId });
      expect(deleteResult.success).toBe(true);

      // 4. Verify file is gone from both disk and database
      expect(fs.existsSync(quarantinePath)).toBe(false);
      result = await invoke('quarantine:list');
      expect(result).toHaveLength(0);
    });

    it('should handle multiple quarantine entries correctly', async () => {
      // Create and quarantine multiple files
      const files = [
        { name: 'file1.exe', threat: 'Trojan.A' },
        { name: 'file2.dll', threat: 'Virus.B' },
        { name: 'file3.bat', threat: 'Malware.C' },
      ];

      for (const file of files) {
        const filePath = path.join(tempDir, 'original', file.name);
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, `content of ${file.name}`);
        await mockQuarantine.quarantineFile(filePath, file.threat);
      }

      // List all entries
      const result = await invoke('quarantine:list');
      expect(result).toHaveLength(3);

      // Verify they're ordered by detected_at DESC (most recent first)
      const timestamps = result.map(r => new Date(r.detected_at).getTime());
      for (let i = 0; i < timestamps.length - 1; i++) {
        expect(timestamps[i]).toBeGreaterThanOrEqual(timestamps[i + 1]);
      }

      // Delete one entry
      const deleteResult = await invoke('quarantine:delete', { id: result[1].id });
      expect(deleteResult.success).toBe(true);

      // Should now have 2 entries
      const updatedResult = await invoke('quarantine:list');
      expect(updatedResult).toHaveLength(2);
    });
  });
});
