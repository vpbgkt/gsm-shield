'use strict';

/**
 * engine/clamd-manager.js
 *
 * Manages the ClamAV daemon (clamd.exe) lifecycle so scans are near-instant.
 *
 * WHY: clamscan.exe reloads the entire ~3.6M-signature database (~14s) on
 * EVERY launch. clamd loads it ONCE and stays warm in memory; clamdscan.exe
 * then queries the running daemon over a local TCP socket, returning results
 * in milliseconds (measured: 213ms for an EICAR scan vs ~14s cold).
 *
 * Design:
 *   - start()  spawns clamd with a generated config (local TCP 127.0.0.1),
 *              then polls PING/PONG until the daemon is ready.
 *   - isReady() reports whether the daemon is up and responding.
 *   - getScanInvocation() returns { exe, baseArgs } for clamdscan when ready,
 *              or null so callers can fall back to cold clamscan.
 *   - stop()   terminates the daemon (called on app quit).
 *
 * All paths resolve correctly both in a packaged app (process.resourcesPath)
 * and in dev/test (local assets/). The config is written to a writable
 * AppData location because the install dir is not writable by a normal user.
 */

const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Local loopback port for the daemon. Non-default (clamd default is 3310) to
// reduce the chance of colliding with another clamd on the machine.
const CLAMD_HOST = '127.0.0.1';
const CLAMD_PORT = 13310;

let _proc = null;        // spawned clamd child process
let _ready = false;      // becomes true once PING->PONG succeeds
let _starting = null;    // in-flight start() promise (dedupes concurrent starts)

/** Resolve the directory containing clamav binaries + definitions. */
function resolveClamavDir() {
  const resourcesPath = process.resourcesPath || path.join(__dirname, '..', 'assets');
  return path.join(resourcesPath, 'clamav');
}

/** Resolve a writable AppData dir for the generated config + daemon log. */
function resolveAppDataDir() {
  try {
    const { app } = require('electron');
    if (app && typeof app.getPath === 'function') {
      return path.join(app.getPath('appData'), 'GSMShieldAV');
    }
  } catch (_) { /* not in Electron */ }
  const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(appData, 'GSMShieldAV');
}

function clamdExe() { return path.join(resolveClamavDir(), 'clamd.exe'); }
function clamdscanExe() { return path.join(resolveClamavDir(), 'clamdscan.exe'); }
function configPath() { return path.join(resolveAppDataDir(), 'clamd.conf'); }

/**
 * Write a clamd.conf with absolute paths for THIS environment.
 * Must NOT contain the word "Example" or clamd refuses to start.
 * @returns {string} the config file path
 */
function writeConfig() {
  const appDataDir = resolveAppDataDir();
  fs.mkdirSync(appDataDir, { recursive: true });
  const dbDir = resolveClamavDir();
  const logFile = path.join(appDataDir, 'clamd.log');

  const conf = [
    'LogTime yes',
    'LogFileMaxSize 5M',
    `LogFile ${logFile}`,
    `DatabaseDirectory ${dbDir}`,
    `TCPSocket ${CLAMD_PORT}`,
    `TCPAddr ${CLAMD_HOST}`,
    'MaxThreads 4',
    'Foreground yes',
    // Reasonable safety limits (defaults are fine, set explicitly for clarity)
    'MaxScanSize 400M',
    'MaxFileSize 100M',
    'StreamMaxLength 100M',
    '',
  ].join('\n');

  const cfgPath = configPath();
  fs.writeFileSync(cfgPath, conf, 'utf8');
  return cfgPath;
}

/**
 * Send a single command to clamd over TCP and resolve with the response.
 * @param {string} command e.g. 'PING'
 * @param {number} timeoutMs
 * @returns {Promise<string>}
 */
function sendCommand(command, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let data = '';
    const done = (err, val) => {
      socket.destroy();
      if (err) reject(err); else resolve(val);
    };
    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => done(new Error('clamd command timeout')));
    socket.on('error', (e) => done(e));
    socket.on('data', (buf) => { data += buf.toString(); });
    socket.on('close', () => done(null, data.trim()));
    socket.connect(CLAMD_PORT, CLAMD_HOST, () => {
      socket.write(command + '\n');
    });
  });
}

/**
 * Poll PING until PONG (daemon ready) or the overall timeout elapses.
 * @param {number} overallTimeoutMs
 * @returns {Promise<boolean>}
 */
async function waitUntilReady(overallTimeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < overallTimeoutMs) {
    try {
      const resp = await sendCommand('PING', 2000);
      if (/PONG/i.test(resp)) return true;
    } catch (_) {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

/**
 * Start the clamd daemon (idempotent). Resolves to true when ready.
 * If clamd.exe is missing or fails to start, resolves false and the caller
 * should fall back to cold clamscan.
 * @returns {Promise<boolean>}
 */
async function start() {
  if (_ready) return true;
  if (_starting) return _starting;

  _starting = (async () => {
    const exe = clamdExe();
    if (!fs.existsSync(exe)) {
      console.error('[clamd] clamd.exe not found at', exe);
      return false;
    }

    let cfg;
    try {
      cfg = writeConfig();
    } catch (err) {
      console.error('[clamd] failed to write config:', err.message);
      return false;
    }

    console.log('[clamd] starting daemon...');
    try {
      _proc = spawn(exe, ['--config-file=' + cfg], {
        windowsHide: true,
        stdio: ['ignore', 'ignore', 'ignore'],
      });
    } catch (err) {
      console.error('[clamd] spawn failed:', err.message);
      return false;
    }

    _proc.on('exit', (code) => {
      console.log('[clamd] daemon exited with code', code);
      _ready = false;
      _proc = null;
    });
    _proc.on('error', (err) => {
      console.error('[clamd] process error:', err.message);
      _ready = false;
    });

    const ok = await waitUntilReady(60000);
    _ready = ok;
    if (ok) {
      console.log('[clamd] daemon ready on', CLAMD_HOST + ':' + CLAMD_PORT);
    } else {
      console.error('[clamd] daemon did not become ready in time');
      stop();
    }
    return ok;
  })();

  try {
    return await _starting;
  } finally {
    _starting = null;
  }
}

/** @returns {boolean} whether the daemon is up and responding. */
function isReady() {
  return _ready === true;
}

/**
 * Get the clamdscan invocation for a warm daemon scan, or null if the daemon
 * is not ready (caller should fall back to cold clamscan).
 *
 * clamdscan output format matches clamscan (`file: OK` / `file: sig FOUND`),
 * so the existing streaming parser in scanner.js works unchanged.
 *
 * @returns {{ exe: string, baseArgs: string[] } | null}
 */
function getScanInvocation() {
  if (!_ready) return null;
  return {
    exe: clamdscanExe(),
    baseArgs: [
      '--config-file=' + configPath(),
      '--multiscan',   // use the daemon's worker threads
      '--stdout',
      '--no-summary',
    ],
  };
}

/** Stop the daemon (called on app quit). */
function stop() {
  _ready = false;
  if (_proc && !_proc.killed) {
    try { _proc.kill(); } catch (_) { /* ignore */ }
  }
  _proc = null;
}

module.exports = {
  start,
  stop,
  isReady,
  getScanInvocation,
  // exposed for diagnostics/tests
  _internals: { CLAMD_HOST, CLAMD_PORT, writeConfig, sendCommand, resolveClamavDir },
};
