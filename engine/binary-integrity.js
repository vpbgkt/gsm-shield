/**
 * engine/binary-integrity.js
 *
 * Refuse to launch bundled third-party executables (ClamAV) unless they match a
 * known-good SHA-256 manifest and are structurally free of Expiro.
 *
 * WHY: on 2026-10-19 the five ClamAV executables in assets/clamav were committed
 * to this repository already infected by Expiro (all DLLs were byte-identical
 * to the official ClamAV 1.5.4 release; only the .exe files had grown by
 * ~1.23 MB). GSM Shield runs with administrator rights and starts clamd.exe at
 * launch, so the antivirus itself became a reinfection vector, and every
 * installer built from the repo shipped the virus. This guard closes that path.
 *
 * Manifest: <dir>/clamav-binaries.sha256.json
 *   { "source": "...", "files": { "clamscan.exe": "<sha256>", ... } }
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { analyzeExpiroStructure } = require('./expiro-structural');

const MANIFEST_NAME = 'clamav-binaries.sha256.json';
const _hashCache = new Map(); // path -> { size, mtimeMs, sha256 }

class BinaryIntegrityError extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'BinaryIntegrityError';
    this.details = details;
  }
}

function loadManifest(dir) {
  const p = path.join(dir, MANIFEST_NAME);
  try {
    const m = JSON.parse(fs.readFileSync(p, 'utf8').replace(/^﻿/, ''));
    if (m && typeof m.files === 'object') return m;
  } catch (_) { /* missing or invalid */ }
  return null;
}

function sha256File(filePath) {
  const st = fs.statSync(filePath);
  const cached = _hashCache.get(filePath);
  if (cached && cached.size === st.size && cached.mtimeMs === st.mtimeMs) return cached.sha256;
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(1024 * 1024);
    let pos = 0;
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, pos);
      if (n <= 0) break;
      h.update(buf.subarray(0, n));
      pos += n;
    }
  } finally {
    fs.closeSync(fd);
  }
  const sha256 = h.digest('hex');
  _hashCache.set(filePath, { size: st.size, mtimeMs: st.mtimeMs, sha256 });
  return sha256;
}

/**
 * Verify an executable before spawning it.
 *
 * - Missing file: ok (the caller's spawn will fail with ENOENT as before).
 * - Structurally Expiro-infected: NEVER ok.
 * - Listed in the manifest: ok only if the SHA-256 matches.
 * - Not listed / no manifest: ok unless infected (logged as unverified).
 * - GSM_ALLOW_UNVERIFIED_BINARIES=1 permits a hash mismatch (for deliberate
 *   engine upgrades during development) but still blocks infected files.
 *
 * @param {string} exePath
 * @returns {{ok: boolean, status: string, reason: string, expected?: string, actual?: string}}
 */
function verifyExecutable(exePath) {
  if (!exePath || !fs.existsSync(exePath)) {
    return { ok: true, status: 'missing', reason: 'file not present; spawn will report the error' };
  }
  const structural = analyzeExpiroStructure(exePath);
  if (structural.verdict === 'infected') {
    return { ok: false, status: 'infected', reason: `structurally infected (${structural.threatName}); refusing to execute`, structural: structural.indicators };
  }
  const manifest = loadManifest(path.dirname(exePath));
  const expected = manifest && manifest.files[path.basename(exePath).toLowerCase()];
  if (!expected) {
    return { ok: true, status: 'unverified', reason: manifest ? 'not listed in manifest' : 'no manifest present' };
  }
  const actual = sha256File(exePath);
  if (actual === String(expected).toLowerCase()) {
    return { ok: true, status: 'verified', reason: 'SHA-256 matches manifest', expected, actual };
  }
  if (process.env.GSM_ALLOW_UNVERIFIED_BINARIES === '1') {
    return { ok: true, status: 'override', reason: 'SHA-256 mismatch allowed by GSM_ALLOW_UNVERIFIED_BINARIES=1', expected, actual };
  }
  return { ok: false, status: 'mismatch', reason: 'SHA-256 does not match the known-good manifest; refusing to execute', expected, actual };
}

/** Throwing variant for callers that prefer exceptions. */
function assertExecutable(exePath) {
  const r = verifyExecutable(exePath);
  if (!r.ok) throw new BinaryIntegrityError(`${path.basename(exePath)}: ${r.reason}`, r);
  return r;
}

/**
 * Verify every file listed in the manifest of `dir` (used by the build and tests).
 * @returns {{ok: boolean, results: object[]}}
 */
function verifyManifestDirectory(dir) {
  const manifest = loadManifest(dir);
  if (!manifest) return { ok: false, results: [{ file: MANIFEST_NAME, ok: false, reason: 'manifest missing' }] };
  const results = Object.keys(manifest.files).map((name) => {
    const p = path.join(dir, name);
    if (!fs.existsSync(p)) return { file: name, ok: false, reason: 'missing' };
    const r = verifyExecutable(p);
    return { file: name, ok: r.ok && r.status === 'verified', reason: r.reason, actual: r.actual };
  });
  return { ok: results.every((r) => r.ok), results };
}

module.exports = {
  MANIFEST_NAME,
  BinaryIntegrityError,
  verifyExecutable,
  assertExecutable,
  verifyManifestDirectory,
  loadManifest,
  _internals: { sha256File, _hashCache },
};
