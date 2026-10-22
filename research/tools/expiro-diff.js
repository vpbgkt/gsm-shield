#!/usr/bin/env node
/**
 * research/tools/expiro-diff.js
 *
 * Read-only forensic diff of a CLEAN and an INFECTED copy of the SAME PE build.
 * Purpose: document exactly what Expiro changes and test whether the bytes it
 * overwrites in the host can be recovered from the infected file (which decides
 * whether true in-place repair is feasible, or whether replacement is required).
 *
 * It never writes to or executes either file.
 *
 * usage: node expiro-diff.js <clean.exe> <infected.bin>
 */
'use strict';
const fs = require('fs');

function parse(buf) {
  const pe = buf.readUInt32LE(0x3c);
  const coff = pe + 4;
  const nSec = buf.readUInt16LE(coff + 2);
  const optSize = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  const is64 = buf.readUInt16LE(opt) === 0x20b;
  const epRva = buf.readUInt32LE(opt + 16);
  const checksum = buf.readUInt32LE(opt + 64);
  const dllchar = buf.readUInt16LE(opt + 70);
  const ddBase = opt + (is64 ? 112 : 96);
  const dir = (i) => ({ rva: buf.readUInt32LE(ddBase + i * 8), size: buf.readUInt32LE(ddBase + i * 8 + 4) });
  const st = opt + optSize;
  const sec = [];
  for (let i = 0; i < nSec; i++) {
    const s = st + i * 40;
    sec.push({
      name: buf.slice(s, s + 8).toString('latin1').replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(s + 8), va: buf.readUInt32LE(s + 12),
      rsize: buf.readUInt32LE(s + 16), roff: buf.readUInt32LE(s + 20),
      chars: buf.readUInt32LE(s + 36),
    });
  }
  return { pe, is64, epRva, checksum, dllchar, reloc: dir(5), security: dir(4), sec, st, optSize };
}
function rvaToOff(p, rva) {
  for (const s of p.sec) { if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rsize)) return s.roff + (rva - s.va); }
  return -1;
}
function hx(b) { return Buffer.isBuffer(b) ? b.toString('hex').replace(/(..)/g, '$1 ').trim() : b; }

const [cleanPath, infPath] = process.argv.slice(2);
const A = fs.readFileSync(cleanPath); // clean
const B = fs.readFileSync(infPath);   // infected
const pa = parse(A), pb = parse(B);

console.log(`clean    ${cleanPath}  ${A.length} bytes`);
console.log(`infected ${infPath}  ${B.length} bytes   (+${B.length - A.length})`);
console.log(`EP: clean 0x${pa.epRva.toString(16)}  infected 0x${pb.epRva.toString(16)}  ${pa.epRva === pb.epRva ? '(unchanged)' : '(CHANGED)'}`);
console.log(`DllCharacteristics: clean 0x${pa.dllchar.toString(16)} infected 0x${pb.dllchar.toString(16)}`);
console.log(`reloc dir: clean rva=0x${pa.reloc.rva.toString(16)}/sz=${pa.reloc.size} infected rva=0x${pb.reloc.rva.toString(16)}/sz=${pb.reloc.size}`);
console.log(`security dir: clean 0x${pa.security.rva.toString(16)}/${pa.security.size} infected 0x${pb.security.rva.toString(16)}/${pb.security.size}`);
console.log('\nsections (clean -> infected):');
for (let i = 0; i < Math.max(pa.sec.length, pb.sec.length); i++) {
  const a = pa.sec[i], b = pb.sec[i];
  const f = (s) => s ? `${s.name.padEnd(8)} raw=0x${s.rsize.toString(16).padStart(7)} chars=0x${s.chars.toString(16).padStart(8)}` : '(none)';
  console.log(`  [${i}] ${f(a)}  ->  ${f(b)}`);
}

// Diff the common prefix (original file length) to find host patches, excluding the last section
// of the infected file (which holds the appended body) and the zeroed relocation region.
const lastClean = pa.sec[pa.sec.length - 1];
const n = Math.min(A.length, lastClean.roff); // bytes before the last section's raw data
let i = 0; const ranges = [];
while (i < n) {
  if (A[i] !== B[i]) { const s = i; while (i < n && A[i] !== B[i]) i++; ranges.push([s, i]); } else i++;
}
console.log(`\nbyte differences before the last section (0..0x${n.toString(16)}): ${ranges.length} range(s)`);
function whichSec(p, off) { for (const s of p.sec) if (off >= s.roff && off < s.roff + s.rsize) return s.name; return 'header'; }
for (const [s, e] of ranges) {
  const len = e - s, sec = whichSec(pa, s);
  const show = Math.min(len, 16);
  console.log(`  @0x${s.toString(16).padStart(6)} len=${String(len).padStart(5)} ${sec.padEnd(8)} clean[${hx(A.slice(s, s + show))}] inf[${hx(B.slice(s, s + show))}]`);
  // If this looks like a code patch (in an executable section), decode a 5-byte rel32 branch
  if (sec === '.text' || sec === 'CODE') {
    for (let k = Math.max(0, s - 1); k <= s + 1 && k + 5 <= B.length; k++) {
      if (B[k] === 0xe8 || B[k] === 0xe9) {
        // find the section at this file offset to get its RVA
        let secObj = pb.sec.find(x => k >= x.roff && k < x.roff + x.rsize);
        if (!secObj) continue;
        const rvaHere = secObj.va + (k - secObj.roff);
        const target = (rvaHere + 5 + B.readInt32LE(k + 1)) >>> 0;
        const tgtSec = pb.sec.find(x => target >= x.va && target < x.va + Math.max(x.vsize, x.rsize));
        console.log(`      infected ${B[k] === 0xe8 ? 'CALL' : 'JMP'} at file 0x${k.toString(16)} (rva 0x${rvaHere.toString(16)}) -> rva 0x${target.toString(16)} in [${tgtSec ? tgtSec.name : '?'}]`);
        console.log(`      clean bytes there: ${hx(A.slice(k, k + 5))}   infected: ${hx(B.slice(k, k + 5))}`);
      }
    }
  }
}

// Recoverability test: can the clean bytes that were overwritten be found verbatim in the infected body?
const body = B.slice(lastClean.roff); // appended region
console.log(`\nrecoverability: searching the ${body.length}-byte appended region for the clean host's overwritten bytes`);
for (const [s, e] of ranges) {
  if (whichSec(pa, s) === 'header') continue;
  const needle = A.slice(s, Math.min(e, s + 16));
  if (needle.length < 4) continue;
  const at = body.indexOf(needle);
  console.log(`  clean bytes @0x${s.toString(16)} (${hx(needle)}): ${at >= 0 ? 'FOUND in body at body+0x' + at.toString(16) + ' (=> plaintext, recoverable)' : 'not found verbatim (encrypted/compressed => needs decryption)'}`);
}
// Also test: is the clean entry-point RVA or original section table stored verbatim in the body?
const epLE = Buffer.alloc(4); epLE.writeUInt32LE(pa.epRva);
console.log(`  clean EP RVA 0x${pa.epRva.toString(16)} as dword in body: ${body.indexOf(epLE) >= 0 ? 'FOUND at body+0x' + body.indexOf(epLE).toString(16) : 'not found'}`);
console.log('\nNote: this tool only reads. Repair = overwrite host with a verified clean copy of the same build; see expiro-disinfector.js.');
