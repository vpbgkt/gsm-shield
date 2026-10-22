#!/usr/bin/env node
/**
 * research/tools/validate-structural.js
 *
 * Read-only validation of engine/expiro-structural.js against real files.
 * Never executes or modifies anything.
 *
 * Usage:
 *   node research/tools/validate-structural.js <root> [<root> ...] [--csv=out.csv] [--all-pe]
 *
 * Prints verdict counts, every infected/suspicious file, and (with --csv)
 * writes one row per PE file that was not clean.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { analyzeExpiroStructure } = require('../../engine/expiro-structural');

const EXTS = new Set(['.exe', '.dll', '.scr', '.com', '.cpl', '.ocx', '.sys', '.tmp', '.efi']);
const args = process.argv.slice(2);
const roots = args.filter((a) => !a.startsWith('--'));
const csvArg = args.find((a) => a.startsWith('--csv='));
const allPe = args.includes('--all-pe');
if (roots.length === 0) {
  console.error('usage: node research/tools/validate-structural.js <root> [...] [--csv=out.csv] [--all-pe]');
  process.exit(1);
}

const counts = { files: 0, pe: 0, clean: 0, suspicious: 0, infected: 0, error: 0, dirErrors: 0 };
const rows = [];
const t0 = Date.now();

function walk(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { counts.dirErrors++; return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) { walk(full); continue; }
    if (!e.isFile()) continue;
    if (!allPe && !EXTS.has(path.extname(e.name).toLowerCase())) continue;
    counts.files++;
    const r = analyzeExpiroStructure(full);
    if (!r.isPE) { if (r.verdict === 'error') counts.error++; continue; }
    counts.pe++;
    counts[r.verdict]++;
    if (r.verdict !== 'clean') {
      rows.push({ verdict: r.verdict, score: r.score, file: full, last: r.layout.lastSection.name,
        lastRaw: '0x' + r.layout.lastSection.rawSize.toString(16), indicators: r.indicators.map((i) => i.id).join('+'),
        family: r.layout.family || '' });
    }
  }
}

for (const root of roots) {
  const st = fs.statSync(root);
  if (st.isDirectory()) walk(root); else { counts.files++; const r = analyzeExpiroStructure(root); if (r.isPE) { counts.pe++; counts[r.verdict]++; if (r.verdict !== 'clean') rows.push({ verdict: r.verdict, score: r.score, file: root, last: r.layout.lastSection.name, lastRaw: '0x' + r.layout.lastSection.rawSize.toString(16), indicators: r.indicators.map((i) => i.id).join('+'), family: r.layout.family || '' }); } }
}

rows.sort((a, b) => (a.verdict === b.verdict ? a.file.localeCompare(b.file) : a.verdict === 'infected' ? -1 : 1));
for (const r of rows) console.log(`${r.verdict.padEnd(10)} ${String(r.score).padStart(3)} ${r.last.padEnd(8)} ${r.lastRaw.padEnd(10)} ${r.indicators}  ${r.file}`);
console.log(`\nroots=${roots.join(', ')} elapsed=${((Date.now() - t0) / 1000).toFixed(1)}s`);
console.log(JSON.stringify(counts));
if (csvArg) {
  const out = csvArg.slice(6);
  const esc = (v) => `"${String(v).replace(/"/g, '""')}"`;
  fs.writeFileSync(out, ['verdict,score,last,lastRaw,indicators,family,file', ...rows.map((r) => [r.verdict, r.score, r.last, r.lastRaw, r.indicators, r.family, r.file].map(esc).join(','))].join('\n'));
  console.log(`csv: ${out}`);
}
