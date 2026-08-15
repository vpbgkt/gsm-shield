'use strict';

/**
 * electron/ipc/__tests__/whitelist-handlers.integration.test.js
 *
 * Integration tests verifying whitelist IPC handlers are properly registered
 * and can be invoked through the IPC system.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const Database = require('better-sqlite3');
const { register } = require('../whitelist-handlers');
const hasher = require('../../../whitelist/hasher');

describe('Whitelist IPC Handlers Integration', () => {
  let db;
  let dbPath;
  let ipcMain;
  let handlers;
  let testFilePath;
  let whitelistDb;

  beforeEach(() => {
    // Create a real SQLite database
    dbPath = path.join(os.tmpdir(), `test-whitelist-integration-${Date.now()}.db`);
    db = new Database(dbPath);

    // Create whitelist table
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

    // Seed some test data
    db.prepare(`
      INSERT INTO whitelist (hash, name, vendor, verified, source)
      VALUES (?, ?, ?, ?, ?)
    `).run('a'.repeat(64), 'Odin3', 'Samsung', 1, 'bundled');

    db.prepare(`
      INSERT INTO whitelist (hash, name, vendor, verified, source)
      VALUES (?, ?, ?, ?, ?)
    `).run('b'.repeat(64), 'SP Flash Tool', 'MediaTek', 1, 'bundled');

    // Create a test file to hash
    testFilePath = path.join(os.tmpdir(), `test-file-${Date.now()}.txt`);
    fs.writeFileSync(testFilePath, 'Test file content for hashing');

    // Mock IPC handler registry
    handlers = {};
    ipcMain = {
      handle: jest.fn((channel, handler) => {
        handlers[channel] = handler;
      }),
    };

    // Create whitelistDb wrapper that uses our test database directly
    whitelistDb = {
      listEntries: (query) => {
        if (query !== undefined && query !== null && query !== '') {
          const stmt = db.prepare(
            `SELECT hash, name, vendor, verified, source, created_at
             FROM whitelist
             WHERE name   LIKE '%' || ? || '%' ESCAPE '\\'
                OR vendor LIKE '%' || ? || '%' ESCAPE '\\'`
          );
          return stmt.all(query, query);
        }
        return db.prepare(
          'SELECT hash, name, vendor, verified, source, created_at FROM whitelist'
        ).all();
      },
      entryExists: (hash) => {
        const row = db.prepare('SELECT 1 FROM whitelist WHERE hash = ?').get(hash);
        return row !== undefined;
      },
      insertEntry: ({ hash, name, vendor = '', source, verified = 0 }) => {
        db.prepare(
          `INSERT OR IGNORE INTO whitelist (hash, name, vendor, verified, source)
           VALUES (?, ?, ?, ?, ?)`
        ).run(hash, name, vendor, verified ? 1 : 0, source);
      },
      deleteEntry: (hash) => {
        const row = db.prepare('SELECT source FROM whitelist WHERE hash = ?').get(hash);
        if (!row) return { success: false };
        if (row.source !== 'user') return { success: false, forbidden: true };
        db.prepare('DELETE FROM whitelist WHERE hash = ?').run(hash);
        return { success: true };
      },
      countUserEntries: () => {
        const row = db
          .prepare("SELECT COUNT(*) AS cnt FROM whitelist WHERE source = 'user'")
          .get();
        return row.cnt;
      },
    };

    // Register handlers
    register(ipcMain, {
      getDb: () => db,
      getHasher: () => hasher,
      getWhitelistDb: () => whitelistDb,
      getSync: () => ({
        syncFromCloud: async () => ({
          added: 0,
          updated: 0,
          timestamp: new Date().toISOString(),
        }),
      }),
      getLicense: () => ({ status: 'active' }),
    });
  });

  afterEach(() => {
    if (db) {
      db.close();
    }
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
    if (fs.existsSync(testFilePath)) {
      fs.unlinkSync(testFilePath);
    }
  });

  test('should register all required IPC channels', () => {
    expect(ipcMain.handle).toHaveBeenCalledWith('whitelist:list', expect.any(Function));
    expect(ipcMain.handle).toHaveBeenCalledWith('whitelist:add', expect.any(Function));
    expect(ipcMain.handle).toHaveBeenCalledWith('whitelist:remove', expect.any(Function));
    expect(ipcMain.handle).toHaveBeenCalledWith('whitelist:submit', expect.any(Function));
    expect(ipcMain.handle).toHaveBeenCalledWith('whitelist:sync', expect.any(Function));
  });

  test('whitelist:list should return seeded entries', async () => {
    const result = await handlers['whitelist:list']({}, {});

    expect(result).toHaveLength(2);
    expect(result[0].name).toBe('Odin3');
    expect(result[1].name).toBe('SP Flash Tool');
  });

  test('whitelist:list should filter by query', async () => {
    const result = await handlers['whitelist:list']({}, { query: 'Odin' });

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Odin3');
  });

  test('whitelist:add should hash real file and insert entry', async () => {
    const result = await handlers['whitelist:add']({}, { filePath: testFilePath });

    expect(result.success).toBe(true);
    expect(result.hash).toMatch(/^[0-9a-f]{64}$/);

    // Verify entry was added to database
    const entries = db.prepare('SELECT * FROM whitelist WHERE hash = ?').all(result.hash);
    expect(entries).toHaveLength(1);
    expect(entries[0].source).toBe('user');
    expect(entries[0].verified).toBe(0);
  });

  test('whitelist:add should detect duplicate when adding same file twice', async () => {
    const firstResult = await handlers['whitelist:add']({}, { filePath: testFilePath });
    expect(firstResult.success).toBe(true);

    const secondResult = await handlers['whitelist:add']({}, { filePath: testFilePath });
    expect(secondResult.success).toBe(false);
    expect(secondResult.duplicate).toBe(true);
  });

  test('whitelist:remove should delete user entry', async () => {
    // Add a user entry first
    const addResult = await handlers['whitelist:add']({}, { filePath: testFilePath });
    expect(addResult.success).toBe(true);

    const hash = addResult.hash;

    // Remove it
    const removeResult = await handlers['whitelist:remove']({}, { hash });
    expect(removeResult.success).toBe(true);

    // Verify it's gone
    const entries = db.prepare('SELECT * FROM whitelist WHERE hash = ?').all(hash);
    expect(entries).toHaveLength(0);
  });

  test('whitelist:remove should not delete bundled entry', async () => {
    const bundledHash = 'a'.repeat(64); // Odin3 hash

    const result = await handlers['whitelist:remove']({}, { hash: bundledHash });

    expect(result.success).toBe(false);
    expect(result.forbidden).toBe(true);

    // Verify entry still exists
    const entries = db.prepare('SELECT * FROM whitelist WHERE hash = ?').all(bundledHash);
    expect(entries).toHaveLength(1);
  });

  test('whitelist:sync should call syncFromCloud', async () => {
    const result = await handlers['whitelist:sync']({}, {});

    expect(result.success).toBe(true);
    expect(result).toHaveProperty('added');
    expect(result).toHaveProperty('updated');
    expect(result).toHaveProperty('timestamp');
  });
});
