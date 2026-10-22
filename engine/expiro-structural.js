/**
 * engine/expiro-structural.js
 *
 * Structural (layout-based) detection of Expiro-infected PE files.
 *
 * WHY THIS EXISTS
 * ---------------
 * The earlier heuristics in expiro-detector.js were written before any real
 * infected sample had been examined. They looked for a ".expiro" section, a
 * 40-150 KB overlay, or an entry point outside .text. None of those occur in the
 * real Expiro infections found on this machine on 2026-10-22, so the old engine
 * scored real infections at 0 (see research/EXPIRO_INCIDENT_2026-10-22.md).
 *
 * The indicators below were derived from real infected files and verified
 * against exact clean/infected pairs (official ClamAV 1.5.4 executables versus
 * the infected copies committed to this repository; ssh-agent.exe 10.0.26100.1
 * versus 10.0.26100.9444). They match the public descriptions of modern Expiro
 * as an "appender" that places its body at the end of the LAST section and
 * patches a CALL in the code section to reach it (Quick Heal / Seqrite 2023,
 * ESET 2013 for the zeroed security directory).
 *
 * Observed on every infected file (72 on C:, 0 false hits on 35,877 PE files):
 *   S1  last section is EXECUTABLE although its name is a data section
 *       (.reloc / .rsrc / .debug ...), usually also WRITABLE
 *   S2  a .reloc section exists but the base-relocation data directory is zero
 *       (the relocation table is overwritten by the virus body)
 *   S3  IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR) cleared so the image loads
 *       at its preferred base without relocations
 *   S4  a CALL/JMP rel32 at the entry-point stub jumps into the last section
 *       (entry-point obscuring: the EP RVA itself is NOT changed)
 *   S5  last section RWX and >= 512 KB
 * Also observed: security (Authenticode) directory zeroed, so signed files
 * become "NotSigned".
 *
 * This module only READS files: the header, 32 bytes at the entry point and a
 * bounded window of the entry-point section. It never executes anything.
 */

'use strict';

const fs = require('fs');

const IMAGE_SCN_CNT_CODE = 0x00000020;
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const DLLCHAR_DYNAMIC_BASE = 0x0040;

/** Section names that legitimately hold data, never code. */
const DATA_SECTION_NAMES = new Set([
  '.reloc', '.rsrc', '.debug', '.data', '.rdata', '.pdata', '.xdata', '.idata',
  '.edata', '.tls', '.bss', '.didat', '_RDATA', '.fptable', '.gfids', '.00cfg',
  '.CRT', '.buildid',
  // Go toolchain symbol table (esbuild.exe / app-builder.exe were infected via .symtab)
  '.symtab',
]);

/** Data-only section names that follow a pattern (MinGW "/4" long-name debug sections, Go .zdebug_*). */
function isDataSectionName(name) {
  return DATA_SECTION_NAMES.has(name) || /^\/\d+$/.test(name) || /^\.z?debug/.test(name);
}

const WEIGHTS = {
  lastExecDataSection: 50,
  lastRwxOtherName: 15,
  relocDirZeroed: 25,
  dynamicBaseCleared: 10,
  epBranchIntoLast: 40,
  lastRwxLarge: 10,
  codeBranchesIntoLast: 15,
};

const THRESHOLDS = { infected: 75, suspicious: 40 };

const DEFAULTS = {
  maxHeaderBytes: 64 * 1024,
  maxBranchScanBytes: 4 * 1024 * 1024,
  scanBranches: true,
};

/**
 * Observed body-layout families (informational only; never used for the
 * verdict). Sizes are the raw size of the infected last section.
 */
const LAYOUT_FAMILIES = [
  { id: 'A', min: 0x158000, max: 0x15E000, note: '~1.35 MB body, entry ~4 KB before section end; seen with Win32/Expiro.HNW, Win32/Expiro.EK, Win64/Expiro.EM' },
  { id: 'C', min: 0x138000, max: 0x13D000, note: '~1.23 MB body; seen in the infected ClamAV executables committed to this repo' },
  { id: 'B', min: 0x08C000, max: 0x090000, note: '~570 KB high-entropy body; seen with Win64/Expiro.DD' },
];

function readAt(fd, position, length) {
  const buf = Buffer.alloc(length);
  const n = fs.readSync(fd, buf, 0, length, position);
  return n === length ? buf : buf.subarray(0, n);
}

/**
 * Parse PE headers from an open file descriptor.
 * @returns {object|null} parsed header or null when not a PE image
 */
function parsePEHeaders(fd, fileSize, maxHeaderBytes) {
  const first = readAt(fd, 0, Math.min(fileSize, 4096));
  if (first.length < 0x40 || first[0] !== 0x4d || first[1] !== 0x5a) return null;
  const peOff = first.readUInt32LE(0x3c);
  if (peOff < 0x40 || peOff + 24 > fileSize || peOff > maxHeaderBytes) return null;

  let hdr = first;
  const need = Math.min(fileSize, maxHeaderBytes);
  if (peOff + 0x400 > hdr.length && hdr.length < need) hdr = readAt(fd, 0, need);
  if (hdr.readUInt32LE(peOff) !== 0x00004550) return null; // 'PE\0\0'

  const coff = peOff + 4;
  const machine = hdr.readUInt16LE(coff);
  const numberOfSections = hdr.readUInt16LE(coff + 2);
  const timeDateStamp = hdr.readUInt32LE(coff + 4);
  const sizeOfOptionalHeader = hdr.readUInt16LE(coff + 16);
  const characteristics = hdr.readUInt16LE(coff + 18);
  const opt = coff + 20;
  if (opt + 96 > hdr.length) return null;
  const magic = hdr.readUInt16LE(opt);
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const is64 = magic === 0x20b;

  const entryPointRVA = hdr.readUInt32LE(opt + 16);
  const checksum = hdr.readUInt32LE(opt + 64);
  const dllCharacteristics = hdr.readUInt16LE(opt + 70);
  const ddBase = opt + (is64 ? 112 : 96);
  const numDirs = hdr.readUInt32LE(opt + (is64 ? 108 : 92));
  const dir = (i) => {
    const o = ddBase + i * 8;
    if (i >= numDirs || o + 8 > hdr.length) return { rva: 0, size: 0 };
    return { rva: hdr.readUInt32LE(o), size: hdr.readUInt32LE(o + 4) };
  };

  const secTable = opt + sizeOfOptionalHeader;
  if (numberOfSections === 0 || numberOfSections > 96) return null;
  if (secTable + numberOfSections * 40 > hdr.length) {
    if (secTable + numberOfSections * 40 > need) return null;
    hdr = readAt(fd, 0, need);
    if (secTable + numberOfSections * 40 > hdr.length) return null;
  }

  const sections = [];
  for (let i = 0; i < numberOfSections; i++) {
    const s = secTable + i * 40;
    const ch = hdr.readUInt32LE(s + 36);
    sections.push({
      index: i,
      name: hdr.subarray(s, s + 8).toString('latin1').replace(/\0+$/, ''),
      virtualSize: hdr.readUInt32LE(s + 8),
      virtualAddress: hdr.readUInt32LE(s + 12),
      rawSize: hdr.readUInt32LE(s + 16),
      rawOffset: hdr.readUInt32LE(s + 20),
      characteristics: ch,
      isExecutable: (ch & IMAGE_SCN_MEM_EXECUTE) !== 0 || (ch & IMAGE_SCN_CNT_CODE) !== 0,
      isWritable: (ch & IMAGE_SCN_MEM_WRITE) !== 0,
    });
  }

  return {
    machine, is64, numberOfSections, timeDateStamp, characteristics,
    isDll: (characteristics & 0x2000) !== 0,
    entryPointRVA, checksum, dllCharacteristics,
    securityDir: dir(4), baseRelocDir: dir(5), clrDir: dir(14),
    sections,
  };
}

function sectionForRva(sections, rva) {
  for (const s of sections) {
    const span = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + span) return s;
  }
  return null;
}

function inSection(s, rva) {
  return rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize);
}

/** Look for E8/E9 rel32 in the first bytes at the entry point that target `last`. */
function findEpBranchIntoLast(fd, fileSize, pe, last) {
  const epSec = sectionForRva(pe.sections, pe.entryPointRVA);
  if (!epSec || epSec.index === last.index) return null;
  const fileOff = epSec.rawOffset + (pe.entryPointRVA - epSec.virtualAddress);
  if (fileOff < 0 || fileOff + 16 > fileSize) return null;
  const b = readAt(fd, fileOff, Math.min(32, fileSize - fileOff));
  for (let i = 0; i + 5 <= b.length; i++) {
    if (b[i] !== 0xe8 && b[i] !== 0xe9) continue;
    const target = pe.entryPointRVA + i + 5 + b.readInt32LE(i + 1);
    if (inSection(last, target)) {
      return {
        offsetFromEntry: i,
        opcode: b[i] === 0xe8 ? 'CALL' : 'JMP',
        targetRva: target >>> 0,
        targetOffsetInLast: target - last.virtualAddress,
        bytesFromLastEnd: last.rawSize - (target - last.virtualAddress),
      };
    }
  }
  return null;
}

/** Count rel32 branches inside the entry-point section that land in `last`. */
function countBranchesIntoLast(fd, fileSize, pe, last, maxBytes) {
  const epSec = sectionForRva(pe.sections, pe.entryPointRVA);
  if (!epSec || epSec.index === last.index || epSec.rawSize === 0) return 0;
  const len = Math.min(epSec.rawSize, maxBytes, Math.max(0, fileSize - epSec.rawOffset));
  if (len < 5) return 0;
  const b = readAt(fd, epSec.rawOffset, len);
  const lo = last.virtualAddress;
  const hi = last.virtualAddress + Math.max(last.virtualSize, last.rawSize);
  let n = 0;
  for (let i = 0; i + 5 <= b.length; i++) {
    const op = b[i];
    if (op !== 0xe8 && op !== 0xe9) continue;
    const target = epSec.virtualAddress + i + 5 + b.readInt32LE(i + 1);
    if (target >= lo && target < hi) n++;
  }
  return n;
}

function layoutFamily(lastRawSize) {
  const f = LAYOUT_FAMILIES.find((x) => lastRawSize >= x.min && lastRawSize <= x.max);
  return f ? `${f.id}: ${f.note}` : null;
}

/**
 * Analyse a file for the Expiro infection layout.
 *
 * @param {string} filePath
 * @param {object} [options]
 * @param {boolean} [options.scanBranches=true] scan the EP section for branches into the last section
 * @param {number} [options.maxBranchScanBytes=4MB]
 * @returns {{
 *   isPE: boolean, verdict: 'not-pe'|'clean'|'suspicious'|'infected'|'error',
 *   score: number, indicators: {id: string, weight: number, detail: string}[],
 *   threatName: string|null, layout: object|null, error?: string
 * }}
 */
function analyzeExpiroStructure(filePath, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const result = { filePath, isPE: false, verdict: 'not-pe', score: 0, indicators: [], threatName: null, layout: null };
  let fd = null;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size < 0x200) return result;
    fd = fs.openSync(filePath, 'r');
    const pe = parsePEHeaders(fd, st.size, opts.maxHeaderBytes);
    if (!pe) return result;
    result.isPE = true;

    const last = pe.sections[pe.sections.length - 1];
    const lastExec = last.isExecutable;
    const lastWrite = last.isWritable;
    const lastIsDataName = isDataSectionName(last.name);
    const hasRelocSection = pe.sections.some((s) => s.name === '.reloc');
    const relocDirZero = pe.baseRelocDir.rva === 0;
    const dynamicBaseCleared = (pe.dllCharacteristics & DLLCHAR_DYNAMIC_BASE) === 0;
    const add = (id, detail) => { result.indicators.push({ id, weight: WEIGHTS[id], detail }); result.score += WEIGHTS[id]; };

    if (lastExec && lastIsDataName) {
      add('lastExecDataSection', `last section '${last.name}' is executable${lastWrite ? ' and writable' : ''} (data sections never hold code)`);
    } else if (lastExec && lastWrite) {
      add('lastRwxOtherName', `last section '${last.name}' is executable and writable`);
    }
    if (hasRelocSection && relocDirZero) {
      add('relocDirZeroed', '.reloc section present but the base-relocation directory is zero (relocation table overwritten)');
    }
    if (hasRelocSection && dynamicBaseCleared && (lastExec || relocDirZero)) {
      add('dynamicBaseCleared', 'ASLR (DYNAMIC_BASE) cleared while a .reloc section exists');
    }

    let epBranch = null;
    let branches = 0;
    if (lastExec) {
      epBranch = findEpBranchIntoLast(fd, st.size, pe, last);
      if (epBranch) {
        add('epBranchIntoLast', `${epBranch.opcode} at entry+${epBranch.offsetFromEntry} jumps into '${last.name}' (+0x${epBranch.targetOffsetInLast.toString(16)}, 0x${epBranch.bytesFromLastEnd.toString(16)} bytes before its end)`);
      }
      if (lastWrite && last.rawSize >= 0x80000) {
        add('lastRwxLarge', `last section RWX and ${(last.rawSize / 1024).toFixed(0)} KB`);
      }
      if (opts.scanBranches) {
        branches = countBranchesIntoLast(fd, st.size, pe, last, opts.maxBranchScanBytes);
        if (!epBranch && branches >= 1 && branches <= 8) {
          add('codeBranchesIntoLast', `${branches} rel32 branch(es) in the entry-point section target '${last.name}'`);
        }
      }
    }

    const hasAnchor = result.indicators.some((i) => i.id === 'lastExecDataSection' || i.id === 'epBranchIntoLast');
    result.score = Math.min(100, result.score);
    if (hasAnchor && result.score >= THRESHOLDS.infected) result.verdict = 'infected';
    else if (result.score >= THRESHOLDS.suspicious) result.verdict = 'suspicious';
    else result.verdict = 'clean';

    if (result.verdict === 'infected') {
      result.threatName = pe.is64 ? 'Virus:Win64/Expiro (structural)' : 'Virus:Win32/Expiro (structural)';
    }

    result.layout = {
      is64: pe.is64,
      isDll: pe.isDll,
      timeDateStamp: pe.timeDateStamp,
      numberOfSections: pe.numberOfSections,
      entryPointRVA: pe.entryPointRVA,
      dllCharacteristics: pe.dllCharacteristics,
      securityDirZero: pe.securityDir.rva === 0,
      relocDirZero,
      dynamicBaseCleared,
      lastSection: { name: last.name, rawSize: last.rawSize, virtualSize: last.virtualSize, characteristics: last.characteristics, executable: lastExec, writable: lastWrite },
      epBranchIntoLast: epBranch,
      branchesIntoLast: branches,
      family: result.verdict === 'infected' ? layoutFamily(last.rawSize) : null,
    };
    return result;
  } catch (err) {
    result.verdict = 'error';
    result.error = err.message;
    return result;
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch (_) { /* ignore */ } }
  }
}

/**
 * Identity of a PE build that survives Expiro infection: Expiro rewrites the
 * last section, data directories and DllCharacteristics, but keeps the COFF
 * machine/timestamp and the layout of the original sections before the last.
 * Used to decide whether a candidate clean file is the SAME build as an
 * infected one before restoring it.
 */
function buildIdentity(filePath) {
  let fd = null;
  try {
    const st = fs.statSync(filePath);
    fd = fs.openSync(filePath, 'r');
    const pe = parsePEHeaders(fd, st.size, DEFAULTS.maxHeaderBytes);
    if (!pe) return null;
    const head = pe.sections.slice(0, -1).map((s) => `${s.name}@${s.virtualAddress}:${s.rawSize}`);
    return { machine: pe.machine, timeDateStamp: pe.timeDateStamp, entryPointRVA: pe.entryPointRVA, sections: head.join('|') };
  } catch (_) {
    return null;
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch (_) { /* ignore */ } }
  }
}

function isSameBuild(a, b) {
  return !!(a && b && a.machine === b.machine && a.timeDateStamp === b.timeDateStamp &&
    a.entryPointRVA === b.entryPointRVA && a.sections === b.sections);
}

module.exports = {
  analyzeExpiroStructure,
  buildIdentity,
  isSameBuild,
  isDataSectionName,
  DATA_SECTION_NAMES,
  WEIGHTS,
  THRESHOLDS,
  LAYOUT_FAMILIES,
  _internals: { parsePEHeaders, findEpBranchIntoLast, countBranchesIntoLast },
};
