'use strict';

/**
 * Neutralized quarantine storage — runs without the better-sqlite3 native
 * module (the database layer is replaced by a tiny in-memory fake), so the
 * file-handling logic can be verified on any Node version.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

// Never touch the real %APPDATA%\GSMShieldAV\quarantine of the machine running the tests.
process.env.APPDATA = fs.mkdtempSync(path.join(os.tmpdir(), 'qneutral-appdata-'));

const mockRows = new Map();
let mockNextId = 1;
jest.mock('../database/init', () => ({
  getDb: () => ({
    prepare: (sql) => ({
      run: (...a) => {
        if (/^\s*INSERT/i.test(sql)) {
          const id = mockNextId++;
          mockRows.set(id, { id, original_path: a[0], quarantine_path: a[1], threat_name: a[2], file_hash: a[3], file_size: a[4] });
          return { lastInsertRowid: id };
        }
        if (/^\s*DELETE/i.test(sql)) { mockRows.delete(a[0]); return {}; }
        throw new Error(`unexpected SQL ${sql}`);
      },
      get: (id) => mockRows.get(id),
    }),
  }),
}));

const { QUARANTINE_DIR, QUARANTINE_EXT, quarantineFile, restoreFile, deleteFile, isNeutralized } = require('./quarantine');

describe('quarantine (neutralized storage)', () => {
  let dir;
  beforeEach(() => {
    mockRows.clear();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qneutral-'));
    fs.rmSync(QUARANTINE_DIR, { recursive: true, force: true });
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(QUARANTINE_DIR, { recursive: true, force: true });
  });

  test('stores a non-executable, non-PE copy and removes the original', async () => {
    const f = path.join(dir, 'tool.exe');
    const content = Buffer.concat([Buffer.from('MZ\x90\x00', 'latin1'), Buffer.alloc(3000, 7)]);
    fs.writeFileSync(f, content);
    const r = await quarantineFile(f, 'Virus:Win64/Expiro (structural)');
    expect(fs.existsSync(f)).toBe(false);
    expect(r.quarantinePath.endsWith(`tool.exe${QUARANTINE_EXT}`)).toBe(true);
    const stored = fs.readFileSync(r.quarantinePath);
    expect(isNeutralized(r.quarantinePath)).toBe(true);
    expect(stored.subarray(8, 10).toString('latin1')).not.toBe('MZ');
    expect(stored.subarray(0, 2).toString('latin1')).not.toBe('MZ');
    expect(r.fileSize).toBe(content.length);
    expect(r.fileHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('round trip restores the exact bytes (multi-chunk file)', async () => {
    const f = path.join(dir, 'big.exe');
    const content = Buffer.alloc(3 * 1024 * 1024 + 123);
    for (let i = 0; i < content.length; i++) content[i] = (i * 31) & 0xff;
    fs.writeFileSync(f, content);
    await quarantineFile(f, 'x');
    const id = [...mockRows.keys()][0];
    await restoreFile(id);
    expect(fs.readFileSync(f).equals(content)).toBe(true);
    expect(mockRows.size).toBe(0);
    expect(fs.readdirSync(QUARANTINE_DIR)).toHaveLength(0);
  });

  test('legacy raw entries still restore', async () => {
    fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
    const legacy = path.join(QUARANTINE_DIR, 'uuid_old.exe');
    fs.writeFileSync(legacy, 'legacy');
    const target = path.join(dir, 'old.exe');
    mockRows.set(99, { id: 99, original_path: target, quarantine_path: legacy });
    await restoreFile(99);
    expect(fs.readFileSync(target, 'utf8')).toBe('legacy');
  });

  test('if the original cannot be removed, nothing is left half-quarantined', async () => {
    const f = path.join(dir, 'locked.exe');
    fs.writeFileSync(f, 'abc');
    const spy = jest.spyOn(fs, 'unlinkSync').mockImplementationOnce(() => { const e = new Error('EBUSY'); e.code = 'EBUSY'; throw e; });
    await expect(quarantineFile(f, 'x')).rejects.toThrow('EBUSY');
    spy.mockRestore();
    expect(fs.existsSync(f)).toBe(true);
    expect(fs.existsSync(QUARANTINE_DIR) ? fs.readdirSync(QUARANTINE_DIR) : []).toHaveLength(0);
    expect(mockRows.size).toBe(0);
  });

  test('deleteFile removes the neutralized copy and the record', async () => {
    const f = path.join(dir, 'd.exe');
    fs.writeFileSync(f, 'zz');
    const r = await quarantineFile(f, 'x');
    const id = [...mockRows.keys()][0];
    await deleteFile(id);
    expect(fs.existsSync(r.quarantinePath)).toBe(false);
    expect(mockRows.size).toBe(0);
  });
});
