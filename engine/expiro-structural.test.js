'use strict';

/**
 * Tests for engine/expiro-structural.js using synthetic images that reproduce
 * the layouts measured on real infected / clean files (2026-10-22 incident).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { analyzeExpiroStructure, buildIdentity, isSameBuild } = require('./expiro-structural');
const { SEC, buildPE, msvcStub64, cleanMsvc64, expiroInfected64, expiroInfected32 } = require('./__tests__/helpers/pe-builder');

let dir;
const write = (name, buf) => { const p = path.join(dir, name); fs.writeFileSync(p, buf); return p; };

beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'expiro-struct-')); });
afterAll(() => { fs.rmSync(dir, { recursive: true, force: true }); });

describe('analyzeExpiroStructure — real-world infected layouts', () => {
  test('x64 MSVC binary infected via enlarged RWX .reloc + EP CALL is "infected"', () => {
    const r = analyzeExpiroStructure(write('infected64.exe', expiroInfected64()));
    expect(r.isPE).toBe(true);
    expect(r.verdict).toBe('infected');
    expect(r.threatName).toBe('Virus:Win64/Expiro (structural)');
    const ids = r.indicators.map((i) => i.id);
    expect(ids).toEqual(expect.arrayContaining(['lastExecDataSection', 'relocDirZeroed', 'dynamicBaseCleared', 'epBranchIntoLast']));
    expect(r.layout.epBranchIntoLast.opcode).toBe('CALL');
    expect(r.layout.epBranchIntoLast.bytesFromLastEnd).toBe(0x1000);
  });

  test('x86 binary with the same layout is "infected" (Win32)', () => {
    const r = analyzeExpiroStructure(write('infected32.exe', expiroInfected32()));
    expect(r.verdict).toBe('infected');
    expect(r.threatName).toBe('Virus:Win32/Expiro (structural)');
  });

  test('layout-family hint for a ~1.35 MB body (family A)', () => {
    const r = analyzeExpiroStructure(write('familyA.exe', expiroInfected64({ bodySize: 0x159e00 })));
    expect(r.verdict).toBe('infected');
    expect(r.layout.family).toMatch(/^A:/);
  });

  test('infected file whose EP stub has no direct branch is still caught by S1+S2', () => {
    // MinGW-style entry (no E8 at the stub) — like the infected Git binaries
    const buf = expiroInfected64({ epBytes: () => Buffer.from([0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x05, 0, 0, 0, 0]) });
    const r = analyzeExpiroStructure(write('mingw-infected.exe', buf));
    expect(r.verdict).toBe('infected');
    expect(r.indicators.map((i) => i.id)).not.toContain('epBranchIntoLast');
  });

  test('infected Go binary (body appended to .symtab, as seen in esbuild.exe) is "infected"', () => {
    // Official esbuild 0.21.5: .symtab raw 0x200, read-only, DllCharacteristics 0x8160, relocs present.
    // Infected copy: .symtab raw 0x8E000, RWX, DllCharacteristics 0x8120, reloc dir zero.
    const buf = buildPE({
      sections: [
        { name: '.text', characteristics: SEC.CODE, rawSize: 0x4000 },
        { name: '.rdata', characteristics: SEC.RDATA, rawSize: 0x1000 },
        { name: '.data', characteristics: SEC.DATA, rawSize: 0x200 },
        { name: '.idata', characteristics: SEC.DATA, rawSize: 0x200 },
        { name: '.reloc', characteristics: SEC.RELOC, rawSize: 0x200 },
        { name: '.symtab', characteristics: SEC.RWX_DATA, rawSize: 0x8e000 },
      ],
      relocDir: 'zero',
      dllCharacteristics: 0x8120,
      epBytes: () => Buffer.from([0xe9, 0x00, 0x00, 0x00, 0x00]), // Go rt0 jmp (no branch into last)
    });
    const r = analyzeExpiroStructure(write('go-infected.exe', buf));
    expect(r.verdict).toBe('infected');
    expect(r.layout.family).toMatch(/^B:/);
  });

  test('clean Go binary (.symtab read-only, relocs intact) is clean', () => {
    const buf = buildPE({
      sections: [
        { name: '.text', characteristics: SEC.CODE, rawSize: 0x4000 },
        { name: '.rdata', characteristics: SEC.RDATA, rawSize: 0x1000 },
        { name: '.reloc', characteristics: SEC.RELOC, rawSize: 0x200 },
        { name: '.symtab', characteristics: 0x42000040, rawSize: 0x200 },
      ],
      dllCharacteristics: 0x8160,
    });
    expect(analyzeExpiroStructure(write('go-clean.exe', buf)).verdict).toBe('clean');
  });

  test('infected Bun-compiled executable (non-data last section .bun) is caught via the EP anchor', () => {
    const buf = buildPE({
      sections: [
        { name: '.text', characteristics: SEC.CODE, rawSize: 0x2000 },
        { name: '.rdata', characteristics: SEC.RDATA, rawSize: 0x400 },
        { name: '.reloc', characteristics: SEC.RELOC, rawSize: 0x200 },
        { name: '.bun', characteristics: SEC.RWX_DATA, rawSize: 0x30000 + 0x8da00 },
      ],
      relocDir: 'zero',
      dllCharacteristics: 0x8120,
      epBytes: ({ sections, entryRva }) => { const l = sections[3]; return msvcStub64(entryRva, l.virtualAddress + l.rawSize - 0x1000); },
    });
    const r = analyzeExpiroStructure(write('bun-infected.exe', buf));
    expect(r.verdict).toBe('infected');
    expect(r.indicators.map((i) => i.id)).toEqual(expect.arrayContaining(['lastRwxOtherName', 'epBranchIntoLast', 'relocDirZeroed']));
  });
});

describe('analyzeExpiroStructure — clean and false-positive guards', () => {
  test('clean x64 MSVC binary is "clean" with score 0', () => {
    const r = analyzeExpiroStructure(write('clean64.exe', cleanMsvc64()));
    expect(r.verdict).toBe('clean');
    expect(r.score).toBe(0);
  });

  test('clean Bun-compiled executable (.bun read-only) is clean', () => {
    const buf = buildPE({
      sections: [
        { name: '.text', characteristics: SEC.CODE, rawSize: 0x2000 },
        { name: '.reloc', characteristics: SEC.RELOC, rawSize: 0x200 },
        { name: '.bun', characteristics: SEC.RDATA, rawSize: 0x30000 },
      ],
      epBytes: ({ sections, entryRva }) => msvcStub64(entryRva, sections[0].virtualAddress + 0x800),
    });
    expect(analyzeExpiroStructure(write('bun-clean.exe', buf)).verdict).toBe('clean');
  });

  test('UPX-style layout (exec UPX1, read-only .rsrc last, no .reloc) is clean', () => {
    const buf = buildPE({
      sections: [
        { name: 'UPX0', characteristics: SEC.RWX_CODE, rawSize: 0, virtualSize: 0x10000 },
        { name: 'UPX1', characteristics: SEC.RWX_CODE, rawSize: 0x4000, fill: 0x9d },
        { name: '.rsrc', characteristics: SEC.DATA, rawSize: 0x400 },
      ],
      entrySection: 1,
      dllCharacteristics: 0x8100,
    });
    expect(analyzeExpiroStructure(write('upx.exe', buf)).verdict).toBe('clean');
  });

  test('VMProtect-style layout (.vmp1 exec with EP, .reloc read-only last, relocs intact) is clean', () => {
    const buf = buildPE({
      sections: [
        { name: '.text', characteristics: SEC.CODE, rawSize: 0x1000 },
        { name: '.vmp0', characteristics: SEC.CODE, rawSize: 0x2000 },
        { name: '.vmp1', characteristics: SEC.CODE, rawSize: 0x4000 },
        { name: '.reloc', characteristics: SEC.RELOC, rawSize: 0x200 },
      ],
      entrySection: 2,
    });
    expect(analyzeExpiroStructure(write('vmp.exe', buf)).verdict).toBe('clean');
  });

  test('Themida-style layout (unnamed RWX last section containing the EP, relocs intact) is not "infected"', () => {
    const buf = buildPE({
      sections: [
        { name: '', characteristics: SEC.RWX_CODE, rawSize: 0x1000 },
        { name: '.rsrc', characteristics: SEC.RDATA, rawSize: 0x200 },
        { name: '.idata', characteristics: SEC.DATA, rawSize: 0x200 },
        { name: '.themida', characteristics: SEC.RWX_CODE, rawSize: 0x90000, fill: 0x5a },
      ],
      entrySection: 3,
      dllCharacteristics: 0x8140,
    });
    const r = analyzeExpiroStructure(write('themida.exe', buf));
    expect(r.verdict).not.toBe('infected');
  });

  test('executable data-named last section alone (relocs intact, no EP branch) is only "suspicious"', () => {
    const buf = buildPE({
      sections: [
        { name: '.text', characteristics: SEC.CODE, rawSize: 0x2000 },
        { name: '.reloc', characteristics: SEC.RELOC, rawSize: 0x200 },
        { name: '.rsrc', characteristics: SEC.RWX_DATA, rawSize: 0x400 },
      ],
      epBytes: ({ sections, entryRva }) => msvcStub64(entryRva, sections[0].virtualAddress + 0x800),
    });
    expect(analyzeExpiroStructure(write('odd.exe', buf)).verdict).toBe('suspicious');
  });

  test('non-PE and tiny files are "not-pe"', () => {
    expect(analyzeExpiroStructure(__filename).verdict).toBe('not-pe');
    expect(analyzeExpiroStructure(write('tiny.exe', Buffer.from('MZ'))).verdict).toBe('not-pe');
    expect(analyzeExpiroStructure(path.join(dir, 'missing.exe')).verdict).toBe('error');
  });

  test('corrupt section table does not throw', () => {
    const buf = cleanMsvc64();
    buf.writeUInt16LE(0xffff, 0x80 + 4 + 2); // absurd NumberOfSections
    expect(() => analyzeExpiroStructure(write('corrupt.exe', buf))).not.toThrow();
  });
});

describe('buildIdentity / isSameBuild', () => {
  test('infected and clean copies of the same build share an identity', () => {
    const clean = write('same-clean.exe', cleanMsvc64({ timeDateStamp: 0x66aabbcc }));
    const infected = write('same-infected.exe', expiroInfected64({ timeDateStamp: 0x66aabbcc }));
    expect(isSameBuild(buildIdentity(clean), buildIdentity(infected))).toBe(true);
  });

  test('a different build (timestamp) is rejected', () => {
    const a = write('build-a.exe', cleanMsvc64({ timeDateStamp: 1 }));
    const b = write('build-b.exe', expiroInfected64({ timeDateStamp: 2 }));
    expect(isSameBuild(buildIdentity(a), buildIdentity(b))).toBe(false);
  });
});
