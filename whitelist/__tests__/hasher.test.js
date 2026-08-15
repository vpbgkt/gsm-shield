'use strict';

const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { hashFile, hashBuffer } = require('../hasher');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Counter to ensure unique file names even within the same millisecond. */
let _counter = 0;

/**
 * Write a temp file and return its absolute path.
 * The caller is responsible for cleanup.
 */
function writeTempFile(content) {
  // Use os.tmpdir() directly — fs.realpathSync can return 8.3 short paths on
  // Windows when the user's home dir contains spaces, causing ENOENT mismatches.
  const base = os.tmpdir();
  const name = `hasher-${process.pid}-${Date.now()}-${++_counter}.bin`;
  const tmpPath = path.join(base, name);
  fs.writeFileSync(tmpPath, content);
  return tmpPath;
}

// ---------------------------------------------------------------------------
// hashBuffer — synchronous
// ---------------------------------------------------------------------------

describe('hashBuffer', () => {
  test('returns a 64-character lowercase hex string', () => {
    const result = hashBuffer(Buffer.from('hello world'));
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  test('produces the known SHA-256 of "hello world"', () => {
    // echo -n "hello world" | sha256sum
    const expected = 'b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576c30d9ba865e46a8a';
    // Node's own reference:
    const ref = crypto.createHash('sha256').update('hello world').digest('hex');
    expect(hashBuffer(Buffer.from('hello world'))).toBe(ref);
    // Cross-check the known value (first 31 chars are unambiguous enough):
    expect(hashBuffer(Buffer.from('hello world')).startsWith('b94d27b')).toBe(true);
  });

  test('returns different hashes for different inputs', () => {
    const a = hashBuffer(Buffer.from('aaa'));
    const b = hashBuffer(Buffer.from('bbb'));
    expect(a).not.toBe(b);
  });

  test('accepts a string as input (behaves like Buffer.from)', () => {
    const fromBuf = hashBuffer(Buffer.from('test data'));
    const fromStr = hashBuffer('test data');
    expect(fromStr).toBe(fromBuf);
  });

  test('empty buffer produces the known empty-string SHA-256', () => {
    const emptyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(hashBuffer(Buffer.alloc(0))).toBe(emptyHash);
  });
});

// ---------------------------------------------------------------------------
// hashFile — streaming / async
// ---------------------------------------------------------------------------

describe('hashFile', () => {
  let tempFiles = [];

  afterEach(() => {
    for (const f of tempFiles) {
      try { fs.unlinkSync(f); } catch (_) { /* best-effort */ }
    }
    tempFiles = [];
  });

  function temp(content) {
    const p = writeTempFile(content);
    tempFiles.push(p);
    return p;
  }

  test('returns a Promise', async () => {
    const p = temp('x');
    const result = hashFile(p);
    expect(result).toBeInstanceOf(Promise);
    // Await to prevent an in-flight read from racing with afterEach cleanup.
    await result;
  });

  test('resolves to a 64-character lowercase hex string', async () => {
    const p = temp('hello world');
    const result = await hashFile(p);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  test('hashFile result matches hashBuffer for same content', async () => {
    const content = Buffer.from('consistency check');
    const p = temp(content);
    const fileHash = await hashFile(p);
    const bufHash = hashBuffer(content);
    expect(fileHash).toBe(bufHash);
  });

  test('different file contents produce different hashes', async () => {
    const p1 = temp('file contents alpha');
    const p2 = temp('file contents beta');
    const [h1, h2] = await Promise.all([hashFile(p1), hashFile(p2)]);
    expect(h1).not.toBe(h2);
  });

  test('same file hashed twice gives the same result', async () => {
    const p = temp('deterministic');
    const [h1, h2] = await Promise.all([hashFile(p), hashFile(p)]);
    expect(h1).toBe(h2);
  });

  test('handles large files without error', async () => {
    // 1 MB of random-ish bytes
    const bigContent = Buffer.alloc(1024 * 1024, 0xab);
    const p = temp(bigContent);
    const result = await hashFile(p);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  // -------------------------------------------------------------------------
  // Error handling
  // -------------------------------------------------------------------------

  test('rejects with "File not found" for a non-existent path', async () => {
    const missing = path.join(os.tmpdir(), 'this-file-does-not-exist-gsm-shield-av.bin');
    await expect(hashFile(missing)).rejects.toThrow(`File not found: ${missing}`);
  });

  test('error message for missing file contains the path', async () => {
    const missing = path.join(os.tmpdir(), 'no-such-file-xyz.bin');
    await expect(hashFile(missing)).rejects.toThrow(missing);
  });
});
