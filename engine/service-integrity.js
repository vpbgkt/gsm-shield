/**
 * engine/service-integrity.js
 *
 * Detect Expiro's service-based persistence.
 *
 * Evidence (2026-10-22 incident, research/EXPIRO_INCIDENT_2026-10-22.md):
 *   - Event 7040: "The start type of the OpenSSH Authentication Agent service
 *     was changed from disabled to auto start", seconds after the infected
 *     Intel RST service (RstMwService) ran on first boot.
 *   - ssh-agent, Intel PIE, MidiSrv, PerceptionSimulation, ReFsDedupSvc,
 *     PerfHost, COMSysApp (dllhost.exe), Edge/Brave updaters: service binaries
 *     infected and then started together at the next boot.
 *   - Public analyses describe the same behaviour (Stop Malvertising: disabled
 *     services set to start automatically; Virus Bulletin / Allievi: service
 *     enumeration and infection of the service executable).
 *
 * The pure functions here are platform-independent and unit-tested; the
 * Windows data source reads the registry through reg.exe (read-only).
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { analyzeExpiroStructure } = require('./expiro-structural');

const START = { BOOT: 0, SYSTEM: 1, AUTO: 2, MANUAL: 3, DISABLED: 4 };

/**
 * Services that ship disabled or manual on Windows 11 and that Expiro was seen
 * switching to Auto. "Auto" on one of these without a baseline is suspicious.
 */
const EXPECTED_NOT_AUTO = new Set([
  'ssh-agent', 'perceptionsimulation', 'midisrv', 'refsdedupsvc', 'perfhost',
  'comsysapp', 'sensordataservice', 'wmpnetworksvc', 'alg', 'msdtc',
]);

/**
 * Turn a service ImagePath into a plain executable path.
 * Handles quotes, arguments, %SystemRoot%, \SystemRoot\ and "system32\..." forms.
 * @param {string} imagePath
 * @param {object} [env=process.env]
 * @returns {string|null}
 */
function normalizeImagePath(imagePath, env = process.env) {
  if (!imagePath || typeof imagePath !== 'string') return null;
  let p = imagePath.trim();
  const winDir = env.SystemRoot || env.SYSTEMROOT || env.windir || 'C:\\Windows';
  p = p.replace(/%([^%]+)%/g, (m, name) => {
    const key = Object.keys(env).find((k) => k.toLowerCase() === name.toLowerCase());
    return key ? env[key] : m;
  });
  if (p.startsWith('"')) {
    const end = p.indexOf('"', 1);
    p = end > 0 ? p.slice(1, end) : p.slice(1);
  } else {
    const m = p.match(/^(.+?\.(exe|sys|dll|com))(\s|$)/i);
    if (m) p = m[1];
  }
  if (/^\\SystemRoot\\/i.test(p)) p = path.win32.join(winDir, p.slice('\\SystemRoot\\'.length));
  else if (/^\\\?\?\\/.test(p)) p = p.slice(4);
  else if (/^system32\\/i.test(p)) p = path.win32.join(winDir, p);
  return p;
}

/**
 * Parse `reg query <Services> /s /v <Value>` output into { serviceName: value }.
 * Only keys exactly one level below ...\Services\ are kept.
 * @param {string} text
 * @param {string} valueName
 */
function parseRegQuery(text, valueName) {
  const out = {};
  let current = null;
  const keyRe = /^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\\]+)\s*$/i;
  const valRe = new RegExp(`^\\s+${valueName}\\s+(REG_\\w+)\\s+(.*)$`, 'i');
  for (const raw of String(text).split(/\r?\n/)) {
    const k = raw.match(keyRe);
    if (k) { current = k[1]; continue; }
    if (/^HKEY_/i.test(raw)) { current = null; continue; }
    if (!current) continue;
    const v = raw.match(valRe);
    if (v) {
      const type = v[1].toUpperCase();
      const data = v[2].trim();
      out[current] = type === 'REG_DWORD' ? parseInt(data, 16) : data;
    }
  }
  return out;
}

/**
 * Assess service records.
 * @param {{name: string, start: number, imagePath: string|null}[]} services
 * @param {object} [options]
 * @param {Object<string, number>} [options.baseline] previous start types by lower-case name
 * @param {(p: string) => {verdict: string}} [options.analyze] structural analyzer (injectable for tests)
 * @param {(p: string) => boolean} [options.exists]
 * @returns {{findings: object[], checked: number}}
 */
function assessServices(services, options = {}) {
  const analyze = options.analyze || ((p) => analyzeExpiroStructure(p, { scanBranches: false }));
  const exists = options.exists || ((p) => fs.existsSync(p));
  const baseline = options.baseline || null;
  const findings = [];
  let checked = 0;
  for (const s of services) {
    const name = String(s.name);
    const key = name.toLowerCase();
    const exe = normalizeImagePath(s.imagePath);
    if (baseline && Object.prototype.hasOwnProperty.call(baseline, key)) {
      const before = baseline[key];
      if ((before === START.DISABLED || before === START.MANUAL) && s.start === START.AUTO) {
        findings.push({ service: name, type: 'start-type-escalated', severity: 'high', detail: `start type changed ${before} -> ${s.start} (Expiro persistence pattern)`, imagePath: exe });
      }
    } else if (baseline && s.start === START.AUTO) {
      findings.push({ service: name, type: 'new-auto-start-service', severity: 'low', detail: 'auto-start service not present in the baseline', imagePath: exe });
    } else if (!baseline && EXPECTED_NOT_AUTO.has(key) && s.start === START.AUTO) {
      findings.push({ service: name, type: 'unexpected-auto-start', severity: 'medium', detail: 'service normally disabled/manual is set to Auto', imagePath: exe });
    }
    if (!exe || !/\.(exe|com)$/i.test(exe)) continue; // drivers/svchost-hosted DLL services are out of scope
    if (/\\svchost\.exe$/i.test(exe)) continue;
    if (!exists(exe)) {
      findings.push({ service: name, type: 'binary-missing', severity: 'info', detail: 'service binary is missing (deleted by a previous remediation?)', imagePath: exe });
      continue;
    }
    checked++;
    const r = analyze(exe);
    if (r && r.verdict === 'infected') {
      findings.push({ service: name, type: 'binary-infected', severity: 'critical', detail: 'service binary has the Expiro infection layout', imagePath: exe, startType: s.start });
    }
  }
  return { findings, checked };
}

function runReg(args) {
  return new Promise((resolve, reject) => {
    execFile('reg.exe', args, { windowsHide: true, maxBuffer: 64 * 1024 * 1024 }, (err, stdout) => {
      if (err && !stdout) reject(err); else resolve(stdout || '');
    });
  });
}

/**
 * Read service records from the Windows registry (read-only).
 * @returns {Promise<{name: string, start: number, imagePath: string|null}[]>}
 */
async function readWindowsServices() {
  const root = 'HKLM\\SYSTEM\\CurrentControlSet\\Services';
  const [startText, imageText] = await Promise.all([
    runReg(['query', root, '/s', '/v', 'Start']),
    runReg(['query', root, '/s', '/v', 'ImagePath']),
  ]);
  const starts = parseRegQuery(startText, 'Start');
  const images = parseRegQuery(imageText, 'ImagePath');
  return Object.keys(starts).map((name) => ({ name, start: starts[name], imagePath: images[name] || null }));
}

/** Build a baseline object { lowerName: start } from service records. */
function makeBaseline(services) {
  const b = {};
  for (const s of services) b[String(s.name).toLowerCase()] = s.start;
  return b;
}

module.exports = {
  START,
  EXPECTED_NOT_AUTO,
  normalizeImagePath,
  parseRegQuery,
  assessServices,
  readWindowsServices,
  makeBaseline,
};
