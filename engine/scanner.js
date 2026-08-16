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
 * Scan a file or directory using ClamAV
 * @param {string} targetPath - Path to scan
 * @param {Object} options - Scan options
 * @param {Function} options.onProgress - Progress callback (throttled to 500ms)
 * @param {Function} options.onThreat - Threat detection callback
 * @param {AbortSignal} options.signal - AbortSignal for cancellation
 * @returns {Promise<ScanResult>}
 */
async function scan(targetPath, { onProgress, onThreat, signal, excludeDirs } = {}) {
  const clamscanPath = resolveClamscanPath();
  const startTime = Date.now();
  
  let filesScanned = 0;
  let threatsFound = 0;
  let cancelled = false;
  let childProcess = null;

  return new Promise((resolve, reject) => {
    // Spawn clamscan.exe with required arguments
    // --recursive:   scan subdirectories
    // --stdout:      send all output to stdout (allows progress tracking)
    // --no-summary:  suppress the "SCAN SUMMARY" footer (Known viruses: N,
    //                Engine version: X, Scanned files: N, Time: N sec, ...).
    //                CRITICAL: without this flag, every summary line matches
    //                the "key: value" file-line pattern below and gets
    //                miscounted as a scanned file (verified: 1 real file +
    //                10 summary lines = 11 reported "files scanned").
    const args = ['--recursive', '--stdout', '--no-summary'];

    // Add database path explicitly to ensure correct definitions are used
    const resourcesPath = process.resourcesPath || path.join(__dirname, '..', 'assets');
    const dbDir = path.join(resourcesPath, 'clamav');
    args.push('--database=' + dbDir);

    // Optional directory exclusions (e.g. for a Full Scan over a drive root,
    // to skip Windows system dirs / our own quarantine dir). Each entry is a
    // regex fragment matched against the full path by clamscan.
    if (Array.isArray(excludeDirs)) {
      for (const dir of excludeDirs) {
        args.push('--exclude-dir=' + dir);
      }
    }

    args.push(targetPath);

    childProcess = spawn(clamscanPath, args, {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const stdout = readline.createInterface({
      input: childProcess.stdout,
      crlfDelay: Infinity
    });

    const stderr = readline.createInterface({
      input: childProcess.stderr,
      crlfDelay: Infinity
    });

    // Throttle progress callbacks to max once per 500ms
    let lastProgressTime = 0;
    const PROGRESS_THROTTLE_MS = 500;

    function emitProgress() {
      const now = Date.now();
      if (onProgress && now - lastProgressTime >= PROGRESS_THROTTLE_MS) {
        onProgress({ filesScanned, threatsFound });
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
        filesScanned++;
        threatsFound++;
        emitProgress();

        const [, filePath, threatName] = threatMatch;
        if (onThreat) {
          onThreat({ filePath: filePath.trim(), threatName: threatName.trim() });
        }
        return;
      }

      if (CLEAN_PATTERN.test(line)) {
        filesScanned++;
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
          cancelled: true
        });
        return;
      }

      if (exitCode === 0 || exitCode === 1) {
        // Success case (0 = clean, 1 = threats found)
        resolve({
          filesScanned,
          threatsFound,
          duration,
          cancelled: false
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
