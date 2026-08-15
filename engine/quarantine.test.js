'use strict';

/**
 * engine/quarantine.test.js
 *
 * Unit tests for quarantine.js: quarantineFile, restoreFile, deleteFile
 * Property tests: Property 15 — quarantine round trip
 *
 * **Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.6**
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const fc = require('fast-check');
const { initDatabase, getDb, closeDatabase } = require('../database/init');
const {
  QUARANTINE_DIR,
  quarantineFile,
  restoreFile,
  deleteFile,
  OriginalPathMissingError,
} = require('./quarantine');

describe('engine/quarantine', () => {
  let testDir;
  let testFile;

  beforeEach(() => {
    // Clean up quarantine directory BEFORE test
    if (fs.existsSync(QUARANTINE_DIR)) {
      fs.rmSync(QUARANTINE_DIR, { recursive: true, force: true });
    }

    // Initialize database before each test
    initDatabase();

    // Clean up quarantine table
    const db = getDb();
    db.prepare('DELETE FROM quarantine').run();

    // Create a temporary test directory with a sample file
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'quarantine-test-'));
    testFile = path.join(testDir, 'infected-file.exe');
    fs.writeFileSync(testFile, 'malicious-content-example');
  });

  afterEach(() => {
    // Close database and reset singleton
    closeDatabase();

    // Clean up: remove test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }

    // Clean up quarantine directory
    if (fs.existsSync(QUARANTINE_DIR)) {
      fs.rmSync(QUARANTINE_DIR, { recursive: true, force: true });
    }
  });

  describe('QUARANTINE_DIR', () => {
    it('should be defined and contain "GSMShieldAV/quarantine"', () => {
      expect(QUARANTINE_DIR).toBeDefined();
      expect(QUARANTINE_DIR).toContain('GSMShieldAV');
      expect(QUARANTINE_DIR).toContain('quarantine');
    });
  });

  describe('quarantineFile', () => {
    it('should move file to quarantine directory with UUID-prefixed name (Req 9.1)', async () => {
      // Arrange
      const threatName = 'Win.Test.EICAR-1';
      expect(fs.existsSync(testFile)).toBe(true);

      // Act
      await quarantineFile(testFile, threatName);

      // Assert: original file should be gone
      expect(fs.existsSync(testFile)).toBe(false);

      // Assert: file should exist in quarantine directory
      const files = fs.readdirSync(QUARANTINE_DIR);
      expect(files.length).toBe(1);
      expect(files[0]).toMatch(/^[0-9a-f-]{36}_infected-file\.exe$/);
    });

    it('should record original_path, threat_name, and file_hash in quarantine table (Req 9.1)', async () => {
      // Arrange
      const threatName = 'Win.Test.Malware-2';

      // Act
      await quarantineFile(testFile, threatName);

      // Assert: database record should exist
      const db = getDb();
      const record = db.prepare('SELECT * FROM quarantine WHERE threat_name = ?').get(threatName);

      expect(record).toBeDefined();
      expect(record.original_path).toBe(testFile);
      expect(record.threat_name).toBe(threatName);
      expect(record.file_hash).toMatch(/^[0-9a-f]{64}$/); // SHA-256 hex
      expect(record.quarantine_path).toContain(QUARANTINE_DIR);
      expect(record.file_size).toBe('malicious-content-example'.length);
    });

    it('should create quarantine directory if it does not exist', async () => {
      // Arrange: ensure directory does not exist
      if (fs.existsSync(QUARANTINE_DIR)) {
        fs.rmSync(QUARANTINE_DIR, { recursive: true, force: true });
      }
      expect(fs.existsSync(QUARANTINE_DIR)).toBe(false);

      // Act
      await quarantineFile(testFile, 'TestThreat');

      // Assert: directory should now exist
      expect(fs.existsSync(QUARANTINE_DIR)).toBe(true);
    });
  });

  describe('restoreFile', () => {
    it('should restore file to original path and delete quarantine record (Req 9.3)', async () => {
      // Arrange: quarantine a file
      const threatName = 'Win.Test.Restore-1';
      await quarantineFile(testFile, threatName);

      const db = getDb();
      const record = db.prepare('SELECT id FROM quarantine WHERE threat_name = ?').get(threatName);
      expect(record).toBeDefined();

      const quarantineId = record.id;
      expect(fs.existsSync(testFile)).toBe(false); // should be gone from original location

      // Act
      await restoreFile(quarantineId);

      // Assert: file should be back at original location
      expect(fs.existsSync(testFile)).toBe(true);
      expect(fs.readFileSync(testFile, 'utf8')).toBe('malicious-content-example');

      // Assert: quarantine record should be deleted
      const afterRecord = db.prepare('SELECT * FROM quarantine WHERE id = ?').get(quarantineId);
      expect(afterRecord).toBeUndefined();
    });

    it('should throw OriginalPathMissingError when original directory no longer exists (Req 9.6)', async () => {
      // Arrange: quarantine a file
      await quarantineFile(testFile, 'TestThreat');

      const db = getDb();
      const record = db.prepare('SELECT id FROM quarantine').get();
      const quarantineId = record.id;

      // Remove original directory
      fs.rmSync(testDir, { recursive: true, force: true });
      expect(fs.existsSync(testDir)).toBe(false);

      // Act & Assert
      await expect(restoreFile(quarantineId)).rejects.toThrow(OriginalPathMissingError);
      await expect(restoreFile(quarantineId)).rejects.toThrow(/Original directory no longer exists/);
    });

    it('should throw error when quarantine entry ID does not exist', async () => {
      // Act & Assert
      await expect(restoreFile(99999)).rejects.toThrow(/Quarantine entry not found/);
    });
  });

  describe('deleteFile', () => {
    it('should permanently delete file from quarantine and remove database record (Req 9.4)', async () => {
      // Arrange: quarantine a file
      await quarantineFile(testFile, 'TestThreat');

      const db = getDb();
      const record = db.prepare('SELECT id, quarantine_path FROM quarantine').get();
      const quarantineId = record.id;
      const quarantinePath = record.quarantine_path;

      expect(fs.existsSync(quarantinePath)).toBe(true);

      // Act
      await deleteFile(quarantineId);

      // Assert: file should be deleted from disk
      expect(fs.existsSync(quarantinePath)).toBe(false);

      // Assert: database record should be deleted
      const afterRecord = db.prepare('SELECT * FROM quarantine WHERE id = ?').get(quarantineId);
      expect(afterRecord).toBeUndefined();
    });

    it('should not throw if quarantine file already deleted from disk', async () => {
      // Arrange: quarantine a file
      await quarantineFile(testFile, 'TestThreat');

      const db = getDb();
      const record = db.prepare('SELECT id, quarantine_path FROM quarantine').get();
      const quarantineId = record.id;
      const quarantinePath = record.quarantine_path;

      // Manually delete the file from disk
      fs.unlinkSync(quarantinePath);
      expect(fs.existsSync(quarantinePath)).toBe(false);

      // Act & Assert: should not throw
      await expect(deleteFile(quarantineId)).resolves.not.toThrow();

      // Assert: database record should still be deleted
      const afterRecord = db.prepare('SELECT * FROM quarantine WHERE id = ?').get(quarantineId);
      expect(afterRecord).toBeUndefined();
    });

    it('should throw error when quarantine entry ID does not exist', async () => {
      // Act & Assert
      await expect(deleteFile(99999)).rejects.toThrow(/Quarantine entry not found/);
    });
  });

  describe('Integration: multiple operations', () => {
    it('should handle quarantine, restore, and re-quarantine sequence', async () => {
      // 1. Quarantine
      await quarantineFile(testFile, 'Threat-A');
      expect(fs.existsSync(testFile)).toBe(false);

      const db = getDb();
      let record = db.prepare('SELECT id FROM quarantine').get();
      const quarantineId = record.id;

      // 2. Restore
      await restoreFile(quarantineId);
      expect(fs.existsSync(testFile)).toBe(true);

      // 3. Re-quarantine
      await quarantineFile(testFile, 'Threat-B');
      expect(fs.existsSync(testFile)).toBe(false);

      record = db.prepare('SELECT * FROM quarantine WHERE threat_name = ?').get('Threat-B');
      expect(record).toBeDefined();
    });

    it('should handle multiple files in quarantine', async () => {
      // Arrange: create multiple test files
      const file1 = path.join(testDir, 'malware1.exe');
      const file2 = path.join(testDir, 'malware2.dll');
      fs.writeFileSync(file1, 'content1');
      fs.writeFileSync(file2, 'content2');

      // Act: quarantine both
      await quarantineFile(file1, 'Threat1');
      await quarantineFile(file2, 'Threat2');

      // Assert: both should be in quarantine
      const db = getDb();
      const records = db.prepare('SELECT * FROM quarantine').all();
      expect(records.length).toBe(2);

      const files = fs.readdirSync(QUARANTINE_DIR);
      expect(files.length).toBe(2);

      // Act: delete first, restore second
      await deleteFile(records[0].id);
      await restoreFile(records[1].id);

      // Assert: only first should be gone
      const afterRecords = db.prepare('SELECT * FROM quarantine').all();
      expect(afterRecords.length).toBe(0);

      expect(fs.existsSync(file1)).toBe(false);
      expect(fs.existsSync(file2)).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Property-Based Tests
// ---------------------------------------------------------------------------

/**
 * Property 15: Quarantine round trip
 *
 * For any valid file name and threat name:
 *   1. Create a real file at a known path inside a temp directory.
 *   2. quarantineFile(filePath, threatName) — file moves out of original path.
 *      • original path no longer exists on disk
 *      • a file exists in QUARANTINE_DIR
 *      • the quarantine table has exactly one matching record
 *   3. restoreFile(id) — file moves back to original path.
 *      • file is present at original path again
 *      • quarantine table record is removed
 *
 * **Validates: Requirements 9.1, 9.3**
 */
describe('Property 15: Quarantine round trip', () => {
  // Arbitraries ---------------------------------------------------------------

  /** File names that are safe for every OS: no path separators, non-empty. */
  const fileNameArb = fc
    .string({ minLength: 1, maxLength: 20 })
    .filter((s) => {
      // No path separators or null bytes
      if (s.includes('/') || s.includes('\\') || s.includes('\0')) return false;
      // No Windows-reserved characters
      if (/[<>:"?*|]/.test(s)) return false;
      // No control characters (0x00–0x1f)
      if (/[\x00-\x1f]/.test(s)) return false;
      // Cannot be just dots or spaces (Windows reserved names)
      if (/^[. ]+$/.test(s)) return false;
      return true;
    });

  /** Threat names: any non-empty string. */
  const threatNameArb = fc.string({ minLength: 1 });

  /** Combined record arbitrary per task spec. */
  const roundTripArb = fc.record({
    fileName: fileNameArb,
    threatName: threatNameArb,
  });

  // Per-run state: each property invocation gets its own temp dir.
  // We collect dirs for cleanup even if the test throws.
  const tempDirs = [];

  beforeEach(() => {
    // Fresh in-memory-equivalent DB for each property run batch
    initDatabase();
    const db = getDb();
    db.prepare('DELETE FROM quarantine').run();

    // Remove any leftover quarantine directory from previous run
    if (fs.existsSync(QUARANTINE_DIR)) {
      fs.rmSync(QUARANTINE_DIR, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    closeDatabase();

    // Clean up all temp dirs that were created during the property runs
    for (const dir of tempDirs.splice(0)) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }

    // Clean up quarantine directory
    if (fs.existsSync(QUARANTINE_DIR)) {
      fs.rmSync(QUARANTINE_DIR, { recursive: true, force: true });
    }
  });

  it('quarantine then restore returns file to original path and removes DB record', async () => {
    await fc.assert(
      fc.asyncProperty(roundTripArb, async ({ fileName, threatName }) => {
        // ----- Setup: create a real file in a fresh temp directory -----
        const tempDir = fs.mkdtempSync(
          path.join(os.tmpdir(), 'pbt-quarantine-')
        );
        tempDirs.push(tempDir);

        const filePath = path.join(tempDir, fileName);
        const fileContent = `pbt-content-${fileName}-${threatName}`;
        fs.writeFileSync(filePath, fileContent);

        // Ensure the DB is clean before this individual run
        const db = getDb();
        db.prepare('DELETE FROM quarantine').run();

        // ----- Step 1: quarantineFile -----
        await quarantineFile(filePath, threatName);

        // Assert: file gone from original path
        expect(fs.existsSync(filePath)).toBe(false);

        // Assert: exactly one file in QUARANTINE_DIR
        const qFiles = fs.readdirSync(QUARANTINE_DIR);
        expect(qFiles.length).toBeGreaterThanOrEqual(1);

        // Assert: exactly one DB record for this threat
        const record = db
          .prepare('SELECT * FROM quarantine WHERE original_path = ?')
          .get(filePath);
        expect(record).toBeDefined();
        expect(record.original_path).toBe(filePath);
        expect(record.threat_name).toBe(threatName);

        const quarantineId = record.id;

        // ----- Step 2: restoreFile -----
        await restoreFile(quarantineId);

        // Assert: file is back at original path with same content
        expect(fs.existsSync(filePath)).toBe(true);
        expect(fs.readFileSync(filePath, 'utf8')).toBe(fileContent);

        // Assert: DB record removed
        const afterRecord = db
          .prepare('SELECT * FROM quarantine WHERE id = ?')
          .get(quarantineId);
        expect(afterRecord).toBeUndefined();
      }),
      {
        numRuns: 30,
        verbose: false,
      }
    );
  });
});
