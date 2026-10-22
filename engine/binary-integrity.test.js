'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { verifyExecutable, assertExecutable, verifyManifestDirectory, MANIFEST_NAME, BinaryIntegrityError } = require('./binary-integrity');
const { cleanMsvc64, expiroInfected64 } = require('./__tests__/helpers/pe-builder');

const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

describe('binary-integrity', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bin-integrity-')); delete process.env.GSM_ALLOW_UNVERIFIED_BINARIES; });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); delete process.env.GSM_ALLOW_UNVERIFIED_BINARIES; });

  const writeManifest = (files) => fs.writeFileSync(path.join(dir, MANIFEST_NAME), JSON.stringify({ files }));

  test('missing file is allowed (spawn reports ENOENT as before)', () => {
    expect(verifyExecutable(path.join(dir, 'nope.exe'))).toMatchObject({ ok: true, status: 'missing' });
  });

  test('file matching the manifest is verified', () => {
    const buf = cleanMsvc64();
    fs.writeFileSync(path.join(dir, 'clamscan.exe'), buf);
    writeManifest({ 'clamscan.exe': sha(buf) });
    expect(verifyExecutable(path.join(dir, 'clamscan.exe'))).toMatchObject({ ok: true, status: 'verified' });
  });

  test('hash mismatch is refused', () => {
    const buf = cleanMsvc64();
    fs.writeFileSync(path.join(dir, 'clamd.exe'), buf);
    writeManifest({ 'clamd.exe': '0'.repeat(64) });
    const r = verifyExecutable(path.join(dir, 'clamd.exe'));
    expect(r).toMatchObject({ ok: false, status: 'mismatch' });
    expect(() => assertExecutable(path.join(dir, 'clamd.exe'))).toThrow(BinaryIntegrityError);
  });

  test('override env allows a mismatch but never an infected file', () => {
    process.env.GSM_ALLOW_UNVERIFIED_BINARIES = '1';
    const clean = cleanMsvc64();
    fs.writeFileSync(path.join(dir, 'a.exe'), clean);
    const infected = expiroInfected64();
    fs.writeFileSync(path.join(dir, 'b.exe'), infected);
    writeManifest({ 'a.exe': '0'.repeat(64), 'b.exe': '0'.repeat(64) });
    expect(verifyExecutable(path.join(dir, 'a.exe'))).toMatchObject({ ok: true, status: 'override' });
    expect(verifyExecutable(path.join(dir, 'b.exe'))).toMatchObject({ ok: false, status: 'infected' });
  });

  test('structurally infected file is refused even when listed with its own hash', () => {
    const infected = expiroInfected64();
    fs.writeFileSync(path.join(dir, 'freshclam.exe'), infected);
    writeManifest({ 'freshclam.exe': sha(infected) });
    expect(verifyExecutable(path.join(dir, 'freshclam.exe'))).toMatchObject({ ok: false, status: 'infected' });
  });

  test('unlisted file without manifest is allowed but marked unverified', () => {
    fs.writeFileSync(path.join(dir, 'x.exe'), cleanMsvc64());
    expect(verifyExecutable(path.join(dir, 'x.exe'))).toMatchObject({ ok: true, status: 'unverified' });
  });

  test('cache is invalidated when the file changes', () => {
    const buf = cleanMsvc64();
    const p = path.join(dir, 'clamdscan.exe');
    fs.writeFileSync(p, buf);
    writeManifest({ 'clamdscan.exe': sha(buf) });
    expect(verifyExecutable(p).status).toBe('verified');
    const changed = Buffer.from(buf); changed[changed.length - 1] ^= 0xff;
    fs.writeFileSync(p, changed);
    const future = new Date(Date.now() + 5000);
    fs.utimesSync(p, future, future);
    expect(verifyExecutable(p).status).toBe('mismatch');
  });
});

describe('repository assets/clamav', () => {
  test('every bundled ClamAV executable matches the known-good manifest and is not infected', () => {
    const dir = path.join(__dirname, '..', 'assets', 'clamav');
    const { ok, results } = verifyManifestDirectory(dir);
    if (!ok) console.error(results.filter((r) => !r.ok));
    expect(results.map((r) => r.file).sort()).toEqual(['clamconf.exe', 'clamd.exe', 'clamdscan.exe', 'clamscan.exe', 'freshclam.exe']);
    expect(ok).toBe(true);
  });
});
