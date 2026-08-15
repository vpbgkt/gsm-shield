'use strict';

/**
 * monitor/service-wrapper.js
 *
 * Entry point for the node-windows Windows background service.
 *
 * Responsibilities:
 *  - Reads watch paths and realtime-protection flag from
 *    AppData/GSMShieldAV/service-config.json.
 *  - If the config file is absent, or realtimeProtection is false, exits cleanly.
 *  - Starts monitor/monitor.js (or a stub if the module is not yet present).
 *  - On threat detection: appends a JSON record to
 *    AppData/GSMShieldAV/threat-events.json  (file-based IPC with the Electron
 *    window — no direct IPC channel is used here).
 *  - On path error from the monitor: logs to AppData/GSMShieldAV/service.log.
 *  - Handles unhandled promise rejections and uncaught exceptions by logging
 *    and continuing (service keeps running).
 *
 * Requirements: 11.1, 11.2, 11.3, 11.4
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

// ─── Paths ────────────────────────────────────────────────────────────────────

/**
 * Resolve the AppData/GSMShieldAV directory without depending on Electron.
 * Uses process.env.APPDATA when available (Windows service environment), falls
 * back to the OS home-based roaming path.
 */
function resolveAppDataDir() {
  const base =
    process.env.APPDATA ||
    path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(base, 'GSMShieldAV');
}

const APP_DATA_DIR     = resolveAppDataDir();
const CONFIG_PATH      = path.join(APP_DATA_DIR, 'service-config.json');
const THREAT_LOG_PATH  = path.join(APP_DATA_DIR, 'threat-events.json');
const SERVICE_LOG_PATH = path.join(APP_DATA_DIR, 'service.log');

// ─── Logging ──────────────────────────────────────────────────────────────────

/**
 * Append a timestamped line to service.log.
 * Never throws — if the write fails we suppress the error to keep the
 * service alive.
 *
 * @param {string} message
 */
function log(message) {
  const line = `[${new Date().toISOString()}] ${message}\n`;
  process.stdout.write(line); // node-windows captures stdout to its own log
  try {
    fs.mkdirSync(APP_DATA_DIR, { recursive: true });
    fs.appendFileSync(SERVICE_LOG_PATH, line, 'utf8');
  } catch (_) {
    // Suppress — if we can't write the log there is nothing more we can do
  }
}

// ─── Threat event writer (Requirement 11.3) ───────────────────────────────────

/**
 * Append a single threat-event record to threat-events.json.
 * The Electron main process reads this file on next window open and pushes
 * the events to the renderer via IPC (file-based IPC pattern).
 *
 * Record shape: { filePath, threatName, detectedAt }
 *
 * @param {{ filePath: string, threatName: string }} threat
 */
function appendThreatEvent({ filePath, threatName }) {
  const record = {
    filePath,
    threatName,
    detectedAt: new Date().toISOString(),
  };

  try {
    fs.mkdirSync(APP_DATA_DIR, { recursive: true });

    // Read the existing array (or start fresh if file is absent / malformed)
    let events = [];
    try {
      if (fs.existsSync(THREAT_LOG_PATH)) {
        const raw = fs.readFileSync(THREAT_LOG_PATH, 'utf8').trim();
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) events = parsed;
        }
      }
    } catch (readErr) {
      log(`[appendThreatEvent] Could not read existing events, starting fresh: ${readErr.message}`);
    }

    events.push(record);
    fs.writeFileSync(THREAT_LOG_PATH, JSON.stringify(events, null, 2), 'utf8');
    log(`Threat event recorded: ${threatName} — ${filePath}`);
  } catch (writeErr) {
    log(`[appendThreatEvent] Failed to write threat event: ${writeErr.message}`);
  }
}

// ─── Config reader ────────────────────────────────────────────────────────────

/**
 * Read and parse service-config.json.
 * Returns null if the file is absent or cannot be parsed.
 *
 * Expected shape: { watchPaths: string[], realtimeProtection: boolean }
 *
 * @returns {{ watchPaths: string[], realtimeProtection: boolean } | null}
 */
function readConfig() {
  try {
    if (!fs.existsSync(CONFIG_PATH)) {
      log('service-config.json not found — exiting cleanly.');
      return null;
    }
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    const cfg = JSON.parse(raw);
    return cfg;
  } catch (err) {
    log(`Failed to read service-config.json: ${err.message} — exiting cleanly.`);
    return null;
  }
}

// ─── Monitor loader ───────────────────────────────────────────────────────────

/**
 * Attempt to load monitor/monitor.js from the same directory.
 * If the module does not exist yet (pre-implementation state), returns a
 * minimal stub so the service-wrapper compiles and can be referenced by
 * node-windows without crashing.
 *
 * @returns {{ startMonitor: Function, stopMonitor: Function }}
 */
function loadMonitor() {
  const monitorPath = path.join(__dirname, 'monitor.js');

  if (fs.existsSync(monitorPath)) {
    try {
      // eslint-disable-next-line import/no-dynamic-require
      return require(monitorPath);
    } catch (err) {
      log(`Failed to load monitor.js: ${err.message} — falling back to stub.`);
    }
  } else {
    log('monitor.js not found — using stub monitor. Real-time scanning is inactive.');
  }

  // ── Stub: used when monitor.js is not yet implemented ────────────────────
  return {
    /**
     * Stub startMonitor — logs the watch paths and calls onError immediately
     * to let callers know the real module is unavailable.
     *
     * @param {string[]} watchPaths
     * @param {{ onThreat: Function, onError: Function }} callbacks
     * @returns {object} A minimal watcher-like object
     */
    startMonitor(watchPaths, { onError }) {
      log(`[stub] startMonitor called with ${watchPaths.length} path(s) — monitor.js not yet available.`);
      // Do NOT call onError in stub; just keep a no-op watcher so the service
      // stays alive waiting for monitor.js to be deployed.
      return {
        _stub: true,
        close: () => {},
      };
    },

    /**
     * Stub stopMonitor — no-op.
     */
    stopMonitor(watcher) {
      if (watcher && watcher._stub) return;
    },
  };
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/**
 * Kick off the service event loop.
 *
 * Flow:
 *  1. Read service-config.json.
 *  2. Exit cleanly if config absent or realtimeProtection is false.
 *  3. Start the monitor with the configured watch paths.
 *  4. Append threat events to threat-events.json as they arrive.
 *  5. Log path errors to service.log.
 *  6. Keep the process alive indefinitely via setInterval.
 */
function main() {
  log('GSM Shield AV service-wrapper starting.');

  const config = readConfig();

  // Exit cleanly when no config or protection disabled (Requirement 11.2)
  if (!config) {
    log('No valid config — service exiting cleanly.');
    process.exit(0);
  }

  if (config.realtimeProtection === false) {
    log('realtimeProtection is false in config — service exiting cleanly.');
    process.exit(0);
  }

  const watchPaths = Array.isArray(config.watchPaths) ? config.watchPaths : [];

  if (watchPaths.length === 0) {
    log('No watch paths configured — service exiting cleanly.');
    process.exit(0);
  }

  log(`Starting monitor on ${watchPaths.length} path(s): ${watchPaths.join(', ')}`);

  const monitor = loadMonitor();

  // Start the real-time monitor (Requirement 11.1, 10.1–10.7)
  const watcher = monitor.startMonitor(watchPaths, {
    /**
     * Called by monitor.js for every detected threat.
     * Appends a JSON record to threat-events.json (Requirement 11.3).
     *
     * @param {{ filePath: string, threatName: string }} threat
     */
    onThreat(threat) {
      log(`Threat detected: ${threat.threatName} — ${threat.filePath}`);
      appendThreatEvent(threat);
    },

    /**
     * Called by monitor.js when a watch path becomes invalid/inaccessible.
     * Logs the error to service.log; the service keeps running on remaining paths.
     *
     * @param {{ path: string, error: Error|string }} errorInfo
     */
    onError(errorInfo) {
      const msg =
        (errorInfo && errorInfo.error)
          ? (errorInfo.error.message || String(errorInfo.error))
          : String(errorInfo);
      const p = (errorInfo && errorInfo.path) ? errorInfo.path : '(unknown path)';
      log(`Monitor path error on "${p}": ${msg}`);
    },
  });

  log('Monitor started. Service is running.');

  // ── Keep the Node.js event loop alive ────────────────────────────────────
  // node-windows services need a persistent event loop; setInterval prevents
  // the process from exiting when the Chokidar watcher is the only active handle.
  const keepAlive = setInterval(() => {
    // Heartbeat — intentionally a no-op. Chokidar events drive real activity.
  }, 60_000);

  // Allow the interval to be garbage-collected if the process receives a
  // shutdown signal from the Windows Service Control Manager.
  if (keepAlive.unref) keepAlive.unref();

  // ── Graceful shutdown ─────────────────────────────────────────────────────
  function shutdown(signal) {
    log(`Received ${signal} — shutting down service.`);
    clearInterval(keepAlive);
    try {
      if (watcher && typeof monitor.stopMonitor === 'function') {
        monitor.stopMonitor(watcher);
      }
    } catch (err) {
      log(`Error during monitor shutdown: ${err.message}`);
    }
    process.exit(0);
  }

  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

// ─── Global error handlers (Requirement — keep service alive) ─────────────────

/**
 * Catch unhandled promise rejections so the service does not crash.
 * Logs the rejection and continues.
 */
process.on('unhandledRejection', (reason) => {
  const msg = (reason instanceof Error) ? reason.message : String(reason);
  log(`Unhandled promise rejection: ${msg}`);
  // Do NOT re-throw — service must keep running
});

/**
 * Catch uncaught synchronous exceptions so the service does not crash.
 * Logs the exception and continues.
 */
process.on('uncaughtException', (err) => {
  log(`Uncaught exception: ${err.message}`);
  // Do NOT re-throw — service must keep running
});

// ─── Run ──────────────────────────────────────────────────────────────────────
main();
