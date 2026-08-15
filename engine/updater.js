const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const readline = require('readline');
const { getDb } = require('../database');

/**
 * Resolve the path to freshclam.exe from the bundled resources directory
 * @returns {string} - Absolute path to freshclam.exe
 */
function resolveFreshclamPath() {
  // In production, process.resourcesPath points to the resources directory
  // In development/test, fall back to a local bundled path
  const resourcesPath = process.resourcesPath || path.join(__dirname, '..', 'assets');
  return path.join(resourcesPath, 'clamav', 'freshclam.exe');
}

/**
 * Resolve the path to the ClamAV virus definitions directory
 * @returns {string} - Absolute path to the datadir containing .cvd files
 */
function resolveDefinitionsPath() {
  const resourcesPath = process.resourcesPath || path.join(__dirname, '..', 'assets');
  return path.join(resourcesPath, 'clamav');
}

/**
 * Verify that definition files exist and are non-zero size
 * @returns {boolean} - True if definitions are valid
 */
function verifyDefinitions() {
  const defsPath = resolveDefinitionsPath();
  const mainCvd = path.join(defsPath, 'main.cvd');
  const dailyCvd = path.join(defsPath, 'daily.cvd');

  try {
    // Check main.cvd exists and has size > 0
    const mainStats = fs.statSync(mainCvd);
    if (!mainStats.isFile() || mainStats.size === 0) {
      return false;
    }

    // Check daily.cvd exists and has size > 0
    const dailyStats = fs.statSync(dailyCvd);
    if (!dailyStats.isFile() || dailyStats.size === 0) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Update ClamAV virus definitions using FreshClam
 * @param {Object} options - Update options
 * @param {Function} options.onProgress - Progress callback with { status, percent }
 * @returns {Promise<UpdateResult>} - { success: boolean, version?: string, lastUpdate?: string, error?: string }
 */
async function updateDefinitions({ onProgress } = {}) {
  const freshclamPath = resolveFreshclamPath();
  const defsPath = resolveDefinitionsPath();

  let childProcess = null;

  return new Promise((resolve) => {
    // Spawn freshclam.exe with required arguments
    // --stdout: Print to stdout instead of stderr
    // --datadir=<path>: Specify where to download definitions
    childProcess = spawn(freshclamPath, [
      '--stdout',
      `--datadir=${defsPath}`
    ], {
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

    let currentStatus = 'Initializing update...';
    let currentPercent = 0;

    // Parse stdout for progress information
    stdout.on('line', (line) => {
      // FreshClam outputs various status lines during update
      // Look for common patterns to extract progress information
      
      // Check for download progress (e.g., "Downloading main.cvd [40%]")
      const downloadMatch = line.match(/Downloading\s+(\S+)\s+\[(\d+)%\]/i);
      if (downloadMatch) {
        const [, filename, percent] = downloadMatch;
        currentStatus = `Downloading ${filename}`;
        currentPercent = parseInt(percent, 10);
        
        if (onProgress) {
          onProgress({ status: currentStatus, percent: currentPercent });
        }
        return;
      }

      // Check for "Testing database" or similar status messages
      if (line.match(/Testing\s+database/i)) {
        currentStatus = 'Verifying definitions...';
        currentPercent = 95;
        
        if (onProgress) {
          onProgress({ status: currentStatus, percent: currentPercent });
        }
        return;
      }

      // Check for "Database updated" success message
      if (line.match(/Database.*updated/i) || line.match(/main\.cvd.*updated/i) || line.match(/daily\.cvd.*updated/i)) {
        currentStatus = 'Update complete';
        currentPercent = 100;
        
        if (onProgress) {
          onProgress({ status: currentStatus, percent: currentPercent });
        }
        return;
      }

      // Check for "Database is up-to-date" message
      if (line.match(/up.?to.?date/i)) {
        currentStatus = 'Definitions already up to date';
        currentPercent = 100;
        
        if (onProgress) {
          onProgress({ status: currentStatus, percent: currentPercent });
        }
        return;
      }

      // Generic progress update for any other informational lines
      if (line.trim().length > 0) {
        currentStatus = line.substring(0, 100); // Truncate long lines
        
        if (onProgress) {
          onProgress({ status: currentStatus, percent: currentPercent });
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
      // Exit code 0 indicates success
      if (exitCode === 0) {
        // Verify that definition files exist and are valid
        if (verifyDefinitions()) {
          // Update settings with new version and timestamp
          try {
            const db = getDb();
            const now = new Date().toISOString();
            
            // Try to extract version from the .cvd files or use a timestamp
            // For simplicity, we'll use the current timestamp as the version indicator
            const version = now.split('T')[0]; // YYYY-MM-DD format
            
            // Update settings table
            const updateStmt = db.prepare('UPDATE settings SET value = ? WHERE key = ?');
            updateStmt.run(version, 'definition_version');
            updateStmt.run(now, 'last_definition_update');

            resolve({
              success: true,
              version,
              lastUpdate: now
            });
          } catch (dbError) {
            console.error(`[updater] Failed to update settings: ${dbError.message}`);
            
            // Definitions were downloaded successfully but settings update failed
            // Still treat this as a success since the definitions are usable
            resolve({
              success: true,
              version: 'unknown',
              lastUpdate: new Date().toISOString(),
              error: `Settings update failed: ${dbError.message}`
            });
          }
        } else {
          // Verification failed - definitions may be corrupted
          console.error('[updater] Definition verification failed after update');
          
          resolve({
            success: false,
            error: 'Definition files verification failed. The downloaded files may be corrupted.'
          });
        }
      } else {
        // Non-zero exit code indicates failure
        console.error(`[updater] FreshClam exited with error code ${exitCode}`);
        console.error(`[updater] stderr: ${stderrOutput}`);
        
        resolve({
          success: false,
          error: stderrOutput || `FreshClam exited with code ${exitCode}`
        });
      }
    });

    childProcess.on('error', (error) => {
      console.error(`[updater] Failed to spawn FreshClam: ${error.message}`);
      
      resolve({
        success: false,
        error: `Failed to start updater: ${error.message}`
      });
    });
  });
}

module.exports = {
  updateDefinitions
};
