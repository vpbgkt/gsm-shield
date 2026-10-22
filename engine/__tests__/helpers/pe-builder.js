'use strict';

/**
 * Synthetic PE builder for tests. Produces structurally valid PE32/PE32+ images
 * (no real code). The presets reproduce the layouts measured on real files in
 * the 2026-10-22 incident (see research/EXPIRO_TECHNICAL_REFERENCE.md):
 *
 *   clean MSVC x64 : .text .rdata .data .pdata .rsrc .reloc(R, small)
 *                    reloc dir -> .reloc, DllCharacteristics 0xC160,
 *                    EP stub "48 83 EC 28 E8 <rel32 into .text>"
 *   Expiro x64     : same, but .reloc enlarged and RWX, reloc dir = 0,
 *                    DllCharacteristics 0x8120 (DYNAMIC_BASE/CFG cleared),
 *                    EP stub CALL -> last section + (rawSize - 0x1000)
 */

const SEC = {
  CODE: 0x60000020, // CODE | EXECUTE | READ
  RDATA: 0x40000040, // INITIALIZED_DATA | READ
  DATA: 0xc0000040, // INITIALIZED_DATA | READ | WRITE
  RELOC: 0x42000040, // INITIALIZED_DATA | DISCARDABLE | READ
  RWX_DATA: 0xe0000040, // INITIALIZED_DATA | EXECUTE | READ | WRITE (as seen on infected .reloc)
  RWX_CODE: 0xe0000020,
};

const align = (v, a) => Math.ceil(v / a) * a;

/**
 * @param {object} o
 * @param {boolean} [o.is64=true]
 * @param {{name: string, characteristics: number, rawSize: number, virtualSize?: number, fill?: number}[]} o.sections
 * @param {number} [o.entrySection=0]
 * @param {number} [o.entryOffset=0x100]
 * @param {(ctx) => Buffer} [o.epBytes] callback returning bytes to place at the EP (ctx has sections with VAs)
 * @param {number} [o.dllCharacteristics=0xC160]
 * @param {'auto'|'zero'} [o.relocDir='auto'] auto: point at the .reloc section if present
 * @param {number} [o.timeDateStamp=0x60000000]
 * @param {boolean} [o.isDll=false]
 * @returns {Buffer}
 */
function buildPE(o) {
  const is64 = o.is64 !== false;
  const fileAlign = 0x200;
  const sectAlign = 0x1000;
  const optSize = is64 ? 0xf0 : 0xe0;
  const peOff = 0x80;
  const secTable = peOff + 4 + 20 + optSize;
  const headersSize = align(secTable + o.sections.length * 40, fileAlign);

  let rawPtr = headersSize;
  let va = sectAlign;
  const secs = o.sections.map((s) => {
    const vs = s.virtualSize || s.rawSize;
    const out = { ...s, virtualSize: vs, virtualAddress: va, rawOffset: rawPtr };
    rawPtr += align(s.rawSize, fileAlign);
    va += align(Math.max(vs, s.rawSize), sectAlign);
    return out;
  });
  const sizeOfImage = va;
  const buf = Buffer.alloc(rawPtr, 0);

  buf.write('MZ', 0, 'latin1');
  buf.writeUInt32LE(peOff, 0x3c);
  buf.write('PE\0\0', peOff, 'latin1');
  const coff = peOff + 4;
  buf.writeUInt16LE(is64 ? 0x8664 : 0x14c, coff);
  buf.writeUInt16LE(secs.length, coff + 2);
  buf.writeUInt32LE(o.timeDateStamp || 0x60000000, coff + 4);
  buf.writeUInt16LE(optSize, coff + 16);
  buf.writeUInt16LE((is64 ? 0x0022 : 0x0102) | (o.isDll ? 0x2000 : 0), coff + 18);

  const opt = coff + 20;
  const epSec = secs[o.entrySection || 0];
  const entryRva = epSec.virtualAddress + (o.entryOffset === undefined ? 0x100 : o.entryOffset);
  buf.writeUInt16LE(is64 ? 0x20b : 0x10b, opt);
  buf.writeUInt32LE(entryRva, opt + 16);
  if (is64) buf.writeBigUInt64LE(0x140000000n, opt + 24); else buf.writeUInt32LE(0x400000, opt + 28);
  buf.writeUInt32LE(sectAlign, opt + 32);
  buf.writeUInt32LE(fileAlign, opt + 36);
  buf.writeUInt32LE(sizeOfImage, opt + 56);
  buf.writeUInt32LE(headersSize, opt + 60);
  buf.writeUInt16LE(3, opt + 68);
  buf.writeUInt16LE(o.dllCharacteristics === undefined ? 0xc160 : o.dllCharacteristics, opt + 70);
  buf.writeUInt32LE(16, opt + (is64 ? 108 : 92));
  const dd = opt + (is64 ? 112 : 96);
  const reloc = secs.find((s) => s.name === '.reloc');
  if (reloc && (o.relocDir || 'auto') === 'auto') {
    buf.writeUInt32LE(reloc.virtualAddress, dd + 5 * 8);
    buf.writeUInt32LE(Math.min(reloc.rawSize, 0x100), dd + 5 * 8 + 4);
  }

  secs.forEach((s, i) => {
    const t = secTable + i * 40;
    buf.write(s.name.padEnd(8, '\0').slice(0, 8), t, 'latin1');
    buf.writeUInt32LE(s.virtualSize, t + 8);
    buf.writeUInt32LE(s.virtualAddress, t + 12);
    buf.writeUInt32LE(s.rawSize, t + 16);
    buf.writeUInt32LE(s.rawSize ? s.rawOffset : 0, t + 20);
    buf.writeUInt32LE(s.characteristics >>> 0, t + 36);
    if (s.rawSize) buf.fill(s.fill === undefined ? 0xcc : s.fill, s.rawOffset, s.rawOffset + s.rawSize);
  });

  if (o.epBytes) {
    const bytes = o.epBytes({ sections: secs, entryRva });
    bytes.copy(buf, epSec.rawOffset + (entryRva - epSec.virtualAddress));
  }
  return buf;
}

/** "sub rsp,28h; call rel32; add rsp,28h; jmp ..." with the call aimed at `target`. */
function msvcStub64(entryRva, target) {
  const b = Buffer.from([0x48, 0x83, 0xec, 0x28, 0xe8, 0, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xe9, 0x6a, 0xfe, 0xff, 0xff]);
  b.writeInt32LE(target - (entryRva + 9), 5);
  return b;
}

/** "call rel32; jmp rel32" (32-bit MSVC CRT entry) with the call aimed at `target`. */
function msvcStub32(entryRva, target) {
  const b = Buffer.from([0xe8, 0, 0, 0, 0, 0xe9, 0x10, 0x00, 0x00, 0x00]);
  b.writeInt32LE(target - (entryRva + 5), 1);
  return b;
}

const baseSections = (relocRaw, relocChars) => [
  { name: '.text', characteristics: SEC.CODE, rawSize: 0x2000 },
  { name: '.rdata', characteristics: SEC.RDATA, rawSize: 0x800, fill: 0x11 },
  { name: '.data', characteristics: SEC.DATA, rawSize: 0x200, virtualSize: 0x1000, fill: 0 },
  { name: '.pdata', characteristics: SEC.RDATA, rawSize: 0x200, fill: 0x22 },
  { name: '.rsrc', characteristics: SEC.RDATA, rawSize: 0x200, fill: 0x33 },
  { name: '.reloc', characteristics: relocChars, rawSize: relocRaw, fill: 0x44 },
];

function cleanMsvc64(extra = {}) {
  return buildPE({
    sections: baseSections(0x200, SEC.RELOC),
    epBytes: ({ sections, entryRva }) => msvcStub64(entryRva, sections[0].virtualAddress + 0x400),
    ...extra,
  });
}

function expiroInfected64({ bodySize = 0x20000, ...extra } = {}) {
  return buildPE({
    sections: baseSections(0x200 + bodySize, SEC.RWX_DATA),
    relocDir: 'zero',
    dllCharacteristics: 0x8120,
    epBytes: ({ sections, entryRva }) => {
      const last = sections[sections.length - 1];
      return msvcStub64(entryRva, last.virtualAddress + last.rawSize - 0x1000);
    },
    ...extra,
  });
}

function expiroInfected32({ bodySize = 0x20000 } = {}) {
  return buildPE({
    is64: false,
    sections: [
      { name: '.text', characteristics: SEC.CODE, rawSize: 0x2000 },
      { name: '.rdata', characteristics: SEC.RDATA, rawSize: 0x800, fill: 0x11 },
      { name: '.data', characteristics: SEC.DATA, rawSize: 0x200, fill: 0 },
      { name: '.reloc', characteristics: SEC.RWX_DATA, rawSize: 0x200 + bodySize, fill: 0x44 },
    ],
    relocDir: 'zero',
    dllCharacteristics: 0x8100,
    epBytes: ({ sections, entryRva }) => {
      const last = sections[sections.length - 1];
      return msvcStub32(entryRva, last.virtualAddress + last.rawSize - 0x1000);
    },
  });
}

module.exports = { SEC, buildPE, msvcStub64, msvcStub32, cleanMsvc64, expiroInfected64, expiroInfected32, baseSections };
