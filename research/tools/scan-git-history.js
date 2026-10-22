#!/usr/bin/env node
/**
 * research/tools/scan-git-history.js  <localRepoPath>
 * Read-only: scans every PE-type blob across ALL git history of a local repo
 * for the Expiro layout. Extracts blob bytes exactly via `git cat-file`
 * (Buffer, no shell pipe), never writes or executes them.
 */
'use strict';
const { execFileSync } = require('child_process');
const path = require('path');
const { analyzeExpiroStructure } = require('../../engine/expiro-structural');
const fs = require('fs');
const os = require('os');

const repo = process.argv[2];
const GIT = 'C:\\Program Files\\Git\\cmd\\git.exe';
const EXT = new Set(['.exe', '.dll', '.scr', '.com', '.cpl', '.ocx', '.sys', '.efi', '.tmp', '.msi']);
const git = (args) => execFileSync(GIT, ['-C', repo, ...args], { maxBuffer: 512 * 1024 * 1024 });

const objs = git(['rev-list', '--objects', '--all']).toString('utf8').split(/\r?\n/).filter(Boolean);
const pe = objs.map(l => { const i = l.indexOf(' '); return i < 0 ? null : { sha: l.slice(0, i), p: l.slice(i + 1) }; })
  .filter(o => o && EXT.has(path.extname(o.p).toLowerCase()));
const bySha = new Map(); for (const o of pe) if (!bySha.has(o.sha)) bySha.set(o.sha, o.p);
console.log(`# ${repo}`);
console.log(`PE-type blobs across all history: ${bySha.size}`);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'histblob-'));
const infected = [];
for (const [sha, p] of bySha) {
  let buf; try { buf = git(['cat-file', 'blob', sha]); } catch { continue; }
  const f = path.join(tmp, sha + '.bin'); fs.writeFileSync(f, buf);
  const a = analyzeExpiroStructure(f);
  if (a.verdict === 'infected') infected.push({ sha, p, size: buf.length });
  fs.unlinkSync(f);
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`INFECTED history blobs: ${infected.length}`);
for (const i of infected) console.log(`  ${i.sha}  ${String(i.size).padStart(9)}  ${i.p}`);
// Show which of these blobs are reachable from current HEAD (i.e., present in a checkout)
const headShas = new Set(git(['ls-tree', '-r', 'HEAD']).toString('utf8').split(/\r?\n/).filter(Boolean)
  .map(l => l.split(/\s+/)[2]));
const inHead = infected.filter(i => headShas.has(i.sha));
console.log(`\nof those, present in current HEAD (would land in a fresh clone's working tree): ${inHead.length}`);
for (const i of inHead) console.log(`  ${i.p}`);
