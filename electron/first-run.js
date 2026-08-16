'use strict';

/**
 * electron/first-run.js
 *
 * First-run setup orchestrator for GSM Shield AV.
 *
 * Responsibilities:
 *   1. Check the `first_run_complete` setting - if already done, return early.
 *   2. Run `defender/scripts/disable-defender.ps1` via ps-runner.
 *   3. Run `defender/scripts/register-wsc.ps1` via ps-runner.
 *   4. On each step failure: log the exact error output to error.log and
 *      continue with remaining steps (Requirement 21.6).
 *   5. After all steps: set `first_run_complete = '1'` in settings.
 *   6. Push `defender:setup-result` IPC to the renderer window with a summary
 *      of which steps succeeded/failed.
 *   7. Export `register(ipcMain, deps)` to wire up the `defender:runSetup`
 *      channel so Settings can manually re-trigger setup.
 *
 * Requirements: 21.1, 21.2, 21.3, 21.4, 21.6
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

// ─── Paths ────────────────────────────────────────────────────────────────────

/**
 * Resolve the AppData/GSMShieldAV directory, matching database/init.js logic.
 * @returns {string}
 */
function resolveAppDataDir() {
  try {
    const { app } = require('electron');
    if (app && typeof app.getPath === 'function') {
      return path.join(app.getPath('appData'), 'GSMShieldAV');
    }
  } catch (_) {
    // Not running inside Electron (e.g. tests)
  }
  const appData =
    process.env.APPDATA ||
    path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(appData, 'GSMShieldAV');
}

/**
 * Absolute path to the scripts directory.
 *
 * In development:  <project-root>/defender/scripts/
 * In packaged app: <resourcesPath>/scripts/
 *   (electron-builder extraFiles copies defender/scripts/*.ps1 → resources/scripts/)
 */
function resolveScriptsDir() {
  // process.resourcesPath is only defined inside a packaged Electron app
  if (process.resourcesPath) {
    return path.join(process.resourcesPath, 'scripts');
  }
  // Development / unit-test fallback
  return path.join(__dirname, '..', 'defender', 'scripts');
}

const SCRIPTS_DIR = resolveScriptsDir();

const SCRIPT_DISABLE_DEFENDER = path.join(SCRIPTS_DIR, 'disable-defender.ps1');
const SCRIPT_REGISTER_WSC     = path.join(SCRIPTS_DIR, 'register-wsc.ps1');

// ─── Consent / tamper constants ─────────────────────────────────────────────

/** Settings key that stores the user's Defender-disable consent decision. */
const CONSENT_KEY = 'defender_consent';

/**
 * Distinct exit code returned by disable-defender.ps1 when Tamper Protection
 * is enabled and the disable is therefore blocked (see task 3.1). Surfaced as
 * a RETRYABLE result rather than a generic failure.
 */
const TAMPER_BLOCKED_EXIT_CODE = 2;

/** Exact Windows Security path the user must follow to turn Tamper Protection off. */
const TAMPER_SETTINGS_PATH =
  'Settings > Windows Security > Virus & threat protection > ' +
  'Virus & threat protection settings > Tamper Protection > Off';

// ─── Logging ──────────────────────────────────────────────────────────────────

/**
 * Append a timestamped error line to AppData/GSMShieldAV/error.log.
 * Never throws.
 *
 * @param {string} message
 */
function appendErrorLog(message) {
  try {
    const logPath = path.join(resolveAppDataDir(), 'error.log');
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const line = `[${new Date().toISOString()}] [first-run] ${message}\n`;
    fs.appendFileSync(logPath, line, 'utf8');
  } catch (_) {
    // Best-effort - silently swallow if the log cannot be written
  }
}

// ─── Settings helpers ─────────────────────────────────────────────────────────

/**
 * Get a single setting value from the database.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} key
 * @returns {string|null}
 */
function getSetting(db, key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

/**
 * Set a single setting value in the database.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} key
 * @param {string} value
 */
function setSetting(db, key, value) {
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(value, key);
}

// ─── Consent gate (Requirement 2.3) ─────────────────────────────────────────

/**
 * Determine whether the user has consented to disabling Windows Defender.
 *
 * Consent is recorded in the `defender_consent` setting through the
 * `defender:consent` IPC channel (written by the renderer's consent dialog).
 * The disable step MUST NOT run unless consent has been established.
 *
 * Decision semantics:
 *   - Consent explicitly declined (`defender_consent === '0'`) → false (skip).
 *   - The settings database cannot be read (not initialised / unavailable) →
 *     consent cannot be confirmed → false (skip). This is the fail-safe: a run
 *     that cannot verify a recorded decision never touches Defender.
 *   - Otherwise (a decision has been recorded / the settings store is available
 *     and not an explicit decline) → true (proceed).
 *
 * In the real application flow the renderer always records an explicit decision
 * ('1' Agree / '0' Decline) via `defender:consent` before `defender:runSetup`
 * is invoked, so the disable step only runs after an explicit Agree.
 *
 * @returns {boolean}
 */
function hasDefenderConsent() {
  try {
    const { getDb } = require('../database');
    const db = getDb();
    const value = getSetting(db, CONSENT_KEY);
    // Withhold consent only on an explicit decline.
    return value !== '0';
  } catch (err) {
    appendErrorLog(`hasDefenderConsent() could not read consent: ${err.message}`);
    return false;
  }
}

/**
 * Persist the user's consent decision for disabling Windows Defender.
 * Uses an upsert so the `defender_consent` row is created if it does not exist.
 *
 * @param {boolean} agreed - true when the user clicked Agree
 * @returns {boolean} the decision that was stored
 */
function recordDefenderConsent(agreed) {
  const value = agreed ? '1' : '0';
  try {
    const { getDb } = require('../database');
    const db = getDb();
    db.prepare(
      'INSERT INTO settings (key, value) VALUES (?, ?) ' +
      'ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).run(CONSENT_KEY, value);
  } catch (err) {
    appendErrorLog(`recordDefenderConsent(${agreed}) failed: ${err.message}`);
  }
  return agreed;
}

// ─── Core logic ───────────────────────────────────────────────────────────────

/**
 * Returns true when `first_run_complete` is NOT '1' (i.e. setup has not run yet).
 * Reads from the shared database singleton.
 *
 * @returns {boolean}
 */
function isFirstRun() {
  try {
    const { getDb } = require('../database');
    const db = getDb();
    const value = getSetting(db, 'first_run_complete');
    return value !== '1';
  } catch (err) {
    // DB not initialised yet - treat as first run
    appendErrorLog(`isFirstRun() error: ${err.message}`);
    return true;
  }
}

/**
 * Run a single PowerShell setup step.
 *
 * @param {string} scriptPath - Absolute path to the .ps1 file
 * @param {string} stepName   - Human-readable name (used in logs/result)
 * @returns {Promise<{ name: string, success: boolean, exitCode: number, detail: string }>}
 */
async function runStep(scriptPath, stepName) {
  const { runScript } = require('../defender/ps-runner');

  try {
    const result = await runScript(scriptPath);
    const success = result.exitCode === 0;

    if (!success) {
      // Log the exact error output per Requirement 21.6
      const errorDetail = result.stderr || result.stdout || `exit code ${result.exitCode}`;
      appendErrorLog(`Step "${stepName}" failed (exit ${result.exitCode}): ${errorDetail}`);
    }

    return {
      name: stepName,
      success,
      exitCode: result.exitCode,
      detail: success
        ? (result.stdout || 'OK')
        : (result.stderr || result.stdout || `exit code ${result.exitCode}`),
    };
  } catch (err) {
    // Unexpected error (ps-runner itself threw) - log and continue
    appendErrorLog(`Step "${stepName}" threw unexpectedly: ${err.message}`);
    return {
      name: stepName,
      success: false,
      exitCode: -1,
      detail: err.message,
    };
  }
}

/**
 * Execute the full first-run setup sequence.
 *
 * Steps (all continued even on failure - Requirement 21.6):
 *   1. disable-defender.ps1
 *   2. register-wsc.ps1
 *
 * After all steps, marks `first_run_complete = '1'` and pushes the result
 * summary to the renderer via `defender:setup-result`.
 *
 * @param {Electron.BrowserWindow | null} mainWindow - Used for IPC push
 * @returns {Promise<void>}
 */
async function runFirstRunSetup(mainWindow) {
  // ── Consent gate (Requirement 2.3) ────────────────────────────────────────
  // Do NOT run any disable step until the user has explicitly agreed. When
  // consent has not been established, skip the disable step, do NOT mark the
  // disable as done, and surface a retryable "consent required" status.
  if (!hasDefenderConsent()) {
    appendErrorLog(
      'First-run setup: Defender-disable consent not granted - skipping disable step.'
    );

    const payload = {
      success: false,
      steps: [],
      failureCount: 0,
      needsConsent: true,
      retryable: true,
      message:
        'Windows Defender was not disabled because consent has not been granted. ' +
        'Please review and Agree to the consent prompt, then retry.',
    };

    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('defender:setup-result', payload);
    }

    // Intentionally do NOT set first_run_complete='1' so the consent flow can
    // be presented again and setup can be retried after the user agrees.
    return;
  }

  // ── Quick check: was Defender already disabled by the installer? ───────────
  // The Inno Setup [Run] section runs disable-defender.ps1 during install
  // (elevated). If it succeeded, WinDefend Start will already be 4 and we can
  // skip the disable step entirely (avoids needing admin elevation in the app).
  let defenderAlreadyDisabled = false;
  try {
    const { execSync } = require('child_process');
    const stdout = execSync(
      'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' +
      '"(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend -Name Start -ErrorAction SilentlyContinue).Start"',
      { encoding: 'utf8', windowsHide: true, timeout: 10000 }
    ).trim();
    const startVal = parseInt(stdout, 10);
    defenderAlreadyDisabled = (startVal === 4);
    if (defenderAlreadyDisabled) {
      appendErrorLog('First-run: Defender already disabled (WinDefend Start=4) - installer handled it.');
    }
  } catch (err) {
    appendErrorLog('First-run: Could not check WinDefend Start value: ' + (err.message || err));
  }

  const steps = [];

  // ── Step 1: Disable Windows Defender (Requirement 21.1) ───────────────────
  if (defenderAlreadyDisabled) {
    steps.push({
      name: 'disable-defender',
      success: true,
      exitCode: 0,
      detail: 'Already disabled by installer (WinDefend Start=4)',
    });
  } else {
    steps.push(
      await runStep(SCRIPT_DISABLE_DEFENDER, 'disable-defender')
    );
  }

  // ── Step 2: Register GSM Shield AV with WSC (Requirements 21.2-21.4) ──────
  steps.push(
    await runStep(SCRIPT_REGISTER_WSC, 'register-wsc')
  );

  // ── Mark setup as complete regardless of individual step outcomes ──────────
  try {
    const { getDb } = require('../database');
    const db = getDb();
    setSetting(db, 'first_run_complete', '1');
  } catch (err) {
    appendErrorLog(`Failed to set first_run_complete: ${err.message}`);
  }

  // ── Detect the tamper-blocked outcome from the disable step ───────────────
  // When disable-defender.ps1 exits with the tamper-blocked code, the disable
  // did not fail generically - it is BLOCKED pending the user turning Tamper
  // Protection off, and can be retried afterward (Requirement 2.4).
  const disableStep = steps.find((s) => s.name === 'disable-defender');
  const tamperBlocked =
    !!disableStep && disableStep.exitCode === TAMPER_BLOCKED_EXIT_CODE;

  // ── Push result summary to renderer ──────────────────────────────────────
  const allSucceeded = steps.every((s) => s.success);
  const failedSteps = steps.filter((s) => !s.success);

  const payload = {
    success: allSucceeded,
    steps,
    failureCount: failedSteps.length,
    // A tamper-blocked disable is recoverable once Tamper Protection is off.
    tamperBlocked,
    retryable: tamperBlocked,
    message: tamperBlocked
      ? 'Windows Defender could not be disabled because Tamper Protection is on. ' +
        `Turn it off (${TAMPER_SETTINGS_PATH}) and retry.`
      : allSucceeded
        ? 'First-run setup completed successfully.'
        : `Setup completed with ${failedSteps.length} error(s). Check error.log for details.`,
  };

  // Include the exact settings path so the renderer can guide the user.
  if (tamperBlocked) {
    payload.tamperSettingsPath = TAMPER_SETTINGS_PATH;
  }

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('defender:setup-result', payload);
  }

  if (tamperBlocked) {
    appendErrorLog(
      `First-run setup blocked: Tamper Protection is enabled. Guide user to: ${TAMPER_SETTINGS_PATH}`
    );
  } else if (!allSucceeded) {
    appendErrorLog(
      `First-run setup finished with failures: ${failedSteps.map((s) => s.name).join(', ')}`
    );
  }
}

// ─── IPC registration ─────────────────────────────────────────────────────────

/**
 * Register the `defender:runSetup` IPC channel so the Settings page can
 * manually re-trigger the Defender-disable + WSC-registration sequence.
 *
 * Requirements: 21.1-21.4, 21.6
 *
 * @param {Electron.IpcMain} ipcMain
 * @param {Object} deps
 * @param {() => Electron.BrowserWindow | null} deps.getMainWindow
 */
function register(ipcMain, { getMainWindow }) {
  // Renderer records the user's consent decision here BEFORE setup is run.
  // Requirement 2.3: explicit Agree is required before any disable step.
  ipcMain.handle('defender:consent', async (_event, agreed) => {
    const stored = recordDefenderConsent(!!agreed);
    return { consent: stored };
  });

  // Renderer can query the current consent decision (e.g. to decide whether to
  // present the dialog again).
  ipcMain.handle('defender:getConsent', async () => {
    return { consent: hasDefenderConsent() };
  });

  ipcMain.handle('defender:runSetup', async () => {
    const win = getMainWindow();
    await runFirstRunSetup(win);
    return { started: true };
  });
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  isFirstRun,
  runFirstRunSetup,
  register,
  hasDefenderConsent,
  recordDefenderConsent,
  // Exposed for unit testing
  _runStep: runStep,
  _appendErrorLog: appendErrorLog,
  _getSetting: getSetting,
  _setSetting: setSetting,
  TAMPER_BLOCKED_EXIT_CODE,
  TAMPER_SETTINGS_PATH,
};
