#!/usr/bin/env node
/**
 * research/tools/scan-github-repo.js
 *
 * Scan a public GitHub repo for Expiro-infected executables WITHOUT cloning or
 * executing anything. For the default branch (and optionally all branches) it
 * lists every PE-type blob via the GitHub API, downloads each to an isolated
 * folder with a NON-executable name, and runs the structural detector on it.
 *
 * usage: node scan-github-repo.js <owner/repo> [--all-branches] [--out <dir>]
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { analyzeExpiroStructure } = require('../../engine/expiro-structural');

const EXT = new Set(['.exe', '.dll', '.scr', '.com', '.cpl', '.ocx', '.sys', '.efi', '.tmp', '.msi']);
const repo = process.argv[2];
const allBranches = process.argv.includes('--all-branches');
const outArg = process.argv.indexOf('--out');
if (!repo || !repo.includes('/')) { console.error('usage: node scan-github-repo.js <owner/repo> [--all-branches]'); process.exit(1); }
const [owner, name] = repo.split('/');
const work = outArg > 0 ? process.argv[outArg + 1] : fs.mkdtempSync(path.join(os.tmpdir(), 'ghscan-'));
fs.mkdirSync(work, { recursive: true });

const headers = { 'User-Agent': 'expiro-scan', 'Accept': 'application/vnd.github+json' };
if (process.env.GH_TOKEN) headers.Authorization = 'Bearer ' + process.env.GH_TOKEN;

async function gh(url) {
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} for ${url}`);
  return r.json();
}
async function download(url, dest) {
  const r = await fetch(url, { headers: { 'User-Agent': 'expiro-scan' } });
  if (!r.ok) throw new Error(`${r.status} for ${url}`);
  fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
}

(async () => {
  const meta = await gh(`https://api.github.com/repos/${owner}/${name}`);
  let branches = [meta.default_branch];
  if (allBranches) { const bs = await gh(`https://api.github.com/repos/${owner}/${name}/branches?per_page=100`); branches = [...new Set(bs.map(b => b.name))]; }
  console.log(`# ${repo}  default=${meta.default_branch}  branches scanned: ${branches.join(', ')}`);

  const results = []; const seenBlob = new Set();
  for (const br of branches) {
    const commit = await gh(`https://api.github.com/repos/${owner}/${name}/commits/${br}`);
    const tree = await gh(`https://api.github.com/repos/${owner}/${name}/git/trees/${commit.sha}?recursive=1`);
    const exes = tree.tree.filter(t => t.type === 'blob' && EXT.has(path.extname(t.path).toLowerCase()));
    for (const b of exes) {
      if (seenBlob.has(b.sha)) { continue; } seenBlob.add(b.sha);
      const dest = path.join(work, b.sha + '.bin'); // non-executable name; never run
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${name}/${encodeURIComponent(br)}/` + b.path.split('/').map(encodeURIComponent).join('/');
      try {
        await download(rawUrl, dest);
        const head = fs.readFileSync(dest, { encoding: 'latin1', flag: 'r' }).slice(0, 60);
        if (head.startsWith('version https://git-lfs')) { results.push({ br, path: b.path, size: b.size, verdict: 'lfs-pointer', ind: 'stored via Git LFS - fetch separately' }); continue; }
        const a = analyzeExpiroStructure(dest);
        results.push({ br, path: b.path, size: b.size, verdict: a.isPE ? a.verdict : 'not-pe', ind: a.indicators ? a.indicators.map(i => i.id).join('+') : '' });
      } catch (e) { results.push({ br, path: b.path, size: b.size, verdict: 'error', ind: e.message }); }
    }
  }
  results.sort((a, b) => (a.verdict === b.verdict ? a.path.localeCompare(b.path) : a.verdict === 'infected' ? -1 : 1));
  console.log(`PE-type blobs found: ${results.length}`);
  for (const r of results) console.log(`  ${r.verdict.padEnd(11)} ${String(r.size).padStart(9)} ${r.path}${r.ind ? '  [' + r.ind + ']' : ''}`);
  const inf = results.filter(r => r.verdict === 'infected');
  console.log(`\nINFECTED in ${repo}: ${inf.length}`);
  for (const r of inf) console.log(`  ${r.path}`);
  fs.rmSync(work, { recursive: true, force: true });
})().catch(e => { console.error('ERROR', e.message); process.exit(1); });
