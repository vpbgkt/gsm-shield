const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const readline = require('readline');

/**
 * Resolve the path to clamscan.exe from the bundled resources directory
 * @returns {string} - Absolute path to clamscan.exe
 */
function resolveClamscanPath() {
  // In production, process.resourcesPath points to the resources directory
  // In development/test, fall back to a local bundled path
  const resourcesPath = process.resourcesPath || path.join(__dirname, '..', 'assets');
  return path.join(resourcesPath, 'clamav', 'clamscan.exe');
}

/**
 * Check if ClamAV virus definition files are present and valid
 * @returns {{ ok: boolean, detail: string }}
 */
function checkDefinitions() {
  const resourcesPath = process.resourcesPath || path.join(__dirname, '..', 'assets');
  const clamavDir = path.join(resourcesPath, 'clamav');
  const mainCvd = path.join(clamavDir, 'main.cvd');
  const dailyCvd = path.join(clamavDir, 'daily.cvd');

  try {
    // Check main.cvd exists and has size > 0
    const mainStats = fs.statSync(mainCvd);
    if (!mainStats.isFile() || mainStats.size === 0) {
      return {
        ok: false,
        detail: `main.cvd is missing or empty at ${mainCvd}`
      };
    }

    // Check daily.cvd exists and has size > 0
    const dailyStats = fs.statSync(dailyCvd);
    if (!dailyStats.isFile() || dailyStats.size === 0) {
      return {
        ok: false,
        detail: `daily.cvd is missing or empty at ${dailyCvd}`
      };
    }

    return {
      ok: true,
      detail: 'Virus definitions are valid'
    };
  } catch (error) {
    return {
      ok: false,
      detail: `Failed to verify virus definitions: ${error.message}`
    };
  }
}

/**
 * Scan one or more files/directories using ClamAV.
 *
 * IMPORTANT (performance): ClamAV's clamscan.exe reloads the entire signature
 * database (~3.6M signatures, ~14s) on EVERY process launch. To avoid paying
 * that cost multiple times, pass ALL targets to a single scan() call — they
 * are handed to one clamscan.exe invocation as multiple positional arguments,
 * so the database is loaded exactly once for the whole batch.
 *
 * @param {string|string[]} targetPath - Path or array of paths to scan
 * @param {Object} options - Scan options
 * @param {Function} options.onProgress - Progress callback: receives
 *        { filesScanned, threatsFound, currentFile, phase }. Throttled.
 *        `phase` is 'loading' until the first file verdict arrives, then 'scanning'.
 * @param {Function} options.onThreat - Threat detection callback
 * @param {AbortSignal} options.signal - AbortSignal for cancellation
 * @param {string[]} options.excludeDirs - Directory regex fragments to exclude
 * @returns {Promise<ScanResult>}
 */
async function scan(targetPath, { onProgress, onThreat, signal, excludeDirs } = {}) {
  const clamscanPath = resolveClamscanPath();
  const startTime = Date.now();

  const targets = Array.isArray(targetPath) ? targetPath : [targetPath];

  let filesScanned = 0;
  let threatsFound = 0;
  let currentFile = '';
  let phase = 'loading'; // 'loading' (DB load) -> 'scanning'
  let cancelled = false;
  let childProcess = null;

  return new Promise((resolve, reject) => {
    // Choose engine:
    //   - If the clamd daemon is warm AND no directory exclusions are needed
    //     (exclusions are only used for Full Scan), use clamdscan for a
    //     near-instant scan (daemon already holds the DB in memory).
    //   - Otherwise use cold clamscan.exe (loads the DB, ~14s), which also
    //     supports --exclude-dir needed by Full Scan.
    // Both emit the same "file: OK" / "file: sig FOUND" verdict lines, so the
    // streaming parser below is identical for either engine.
    let exe;
    let args;
    let engine;

    let daemon = null;
    if (!Array.isArray(excludeDirs) || excludeDirs.length === 0) {
      try {
        const clamd = require('./clamd-manager');
        daemon = clamd.getScanInvocation(); // null if daemon not ready
      } catch (_) {
        daemon = null;
      }
    }

    if (daemon) {
      engine = 'clamd';
      exe = daemon.exe;
      args = daemon.baseArgs.slice();
      for (const t of targets) args.push(t);
    } else {
      engine = 'clamscan';
      exe = clamscanPath;
      // --recursive:   scan subdirectories
      // --stdout:      send all output to stdout (allows progress tracking)
      // --no-summary:  suppress the "SCAN SUMMARY" footer, otherwise its lines
      //                get miscounted as scanned files.
      args = ['--recursive', '--stdout', '--no-summary'];
      const resourcesPath = process.resourcesPath || path.join(__dirname, '..', 'assets');
      const dbDir = path.join(resourcesPath, 'clamav');
      args.push('--database=' + dbDir);
      if (Array.isArray(excludeDirs)) {
        for (const dir of excludeDirs) args.push('--exclude-dir=' + dir);
      }
      for (const t of targets) args.push(t);
    }

    childProcess = spawn(exe, args, {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    // With cold clamscan there is a ~14s DB-load window before any file
    // verdict is produced, so start in the 'loading' phase to keep the UI
    // alive. With the warm clamd daemon there is no load, so go straight to
    // 'scanning'.
    phase = engine === 'clamscan' ? 'loading' : 'scanning';
    if (onProgress) {
      onProgress({ filesScanned: 0, threatsFound: 0, currentFile: '', phase, engine });
    }

    const stdout = readline.createInterface({
      input: childProcess.stdout,
      crlfDelay: Infinity
    });

    const stderr = readline.createInterface({
      input: childProcess.stderr,
      crlfDelay: Infinity
    });

    // Throttle progress callbacks so the UI updates smoothly (~4/sec) without
    // being flooded on fast directories. We always send the most-recent file.
    let lastProgressTime = 0;
    const PROGRESS_THROTTLE_MS = 250;

    function emitProgress(force) {
      const now = Date.now();
      if (onProgress && (force || now - lastProgressTime >= PROGRESS_THROTTLE_MS)) {
        onProgress({ filesScanned, threatsFound, currentFile, phase, engine });
        lastProgressTime = now;
      }
    }

    // Handle AbortSignal cancellation
    const abortHandler = () => {
      if (childProcess && !childProcess.killed) {
        cancelled = true;
        childProcess.kill('SIGTERM');
      }
    };

    if (signal) {
      if (signal.aborted) {
        // Already aborted before we started
        childProcess.kill('SIGTERM');
        cancelled = true;
      } else {
        signal.addEventListener('abort', abortHandler);
      }
    }

    // Parse stdout line by line for threat detections and progress.
    // With --no-summary, ClamAV emits exactly one verdict line per scanned
    // file, always ending in " OK" (clean) or " FOUND" (infected) — no other
    // line shape is emitted in this mode. Anchoring on these two exact
    // verdict suffixes (instead of a generic "key: value" pattern) prevents
    // any future non-file diagnostic/warning line from being miscounted as
    // a scanned file, which is the root cause of the file-count bug fixed
    // above (belt-and-suspenders against a regression of the same class).
    const THREAT_PATTERN = /^(.+): (.+) FOUND$/;
    const CLEAN_PATTERN = /^(.+): OK$/;

    stdout.on('line', (line) => {
      if (!line) return;

      const threatMatch = line.match(THREAT_PATTERN);
      if (threatMatch) {
        // First verdict line means the DB finished loading -> scanning phase.
        phase = 'scanning';
        filesScanned++;
        threatsFound++;

        const [, filePath, threatName] = threatMatch;
        currentFile = filePath.trim();
        // Threats are important — always push immediately (force).
        emitProgress(true);

        if (onThreat) {
          onThreat({ filePath: currentFile, threatName: threatName.trim() });
        }
        return;
      }

      const cleanMatch = line.match(CLEAN_PATTERN);
      if (cleanMatch) {
        phase = 'scanning';
        filesScanned++;
        currentFile = cleanMatch[1].trim();
        emitProgress();
      }
      // Any other line (LibClamAV warnings, blank separators, etc.) is
      // intentionally ignored for counting purposes.
    });

    // Log stderr output for debugging
    let stderrOutput = '';
    stderr.on('line', (line) => {
      stderrOutput += line + '\n';
    });

    // Handle process exit
    childProcess.on('exit', (exitCode) => {
      // Clean up signal listener
      if (signal) {
        signal.removeEventListener('abort', abortHandler);
      }

      const duration = Date.now() - startTime;

      // Handle exit codes:
      // 0 = clean (no threats found)
      // 1 = threats found (already parsed from stdout)
      // >=2 = error condition

      if (cancelled) {
        resolve({
          filesScanned,
          threatsFound,
          duration,
          cancelled: true,
          engine
        });
        return;
      }

      if (exitCode === 0 || exitCode === 1) {
        // Success case (0 = clean, 1 = threats found)
        resolve({
          filesScanned,
          threatsFound,
          duration,
          cancelled: false,
          engine
        });
      } else {
        // Error case (exit code >= 2)
        console.error(`[scanner] ClamAV exited with error code ${exitCode}`);
        console.error(`[scanner] stderr: ${stderrOutput}`);
        
        resolve({
          filesScanned,
          threatsFound,
          duration,
          cancelled: false,
          error: true,
          errorCode: exitCode,
          errorMessage: stderrOutput || `ClamAV exited with code ${exitCode}`
        });
      }
    });

    childProcess.on('error', (error) => {
      // Clean up signal listener
      if (signal) {
        signal.removeEventListener('abort', abortHandler);
      }

      console.error(`[scanner] Failed to spawn ClamAV: ${error.message}`);
      
      resolve({
        filesScanned: 0,
        threatsFound: 0,
        duration: Date.now() - startTime,
        cancelled: false,
        error: true,
        errorMessage: `Failed to start scanner: ${error.message}`
      });
    });
  });
}

module.exports = {
  scan,
  checkDefinitions
};
