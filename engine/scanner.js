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
async function scan(targetPath, { onProgress, onThreat, signal } = {}) {
  const clamscanPath = resolveClamscanPath();
  const startTime = Date.now();
  
  let filesScanned = 0;
  let threatsFound = 0;
  let cancelled = false;
  let childProcess = null;

  return new Promise((resolve, reject) => {
    // Spawn clamscan.exe with required arguments
    // --no-summary: Don't print summary at the end
    // --infected: Only print infected files
    childProcess = spawn(clamscanPath, ['--no-summary', '--infected', targetPath], {
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

    // Parse stdout line by line for threat detections
    // ClamAV outputs threats in the format: <filepath>: <threat name> FOUND
    const THREAT_PATTERN = /^(.+): (.+) FOUND$/;

    stdout.on('line', (line) => {
      filesScanned++;
      emitProgress();

      const match = line.match(THREAT_PATTERN);
      if (match) {
        const [, filePath, threatName] = match;
        threatsFound++;
        
        if (onThreat) {
          onThreat({ filePath, threatName });
        }
      }
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
