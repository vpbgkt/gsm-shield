/**
 * defender/ps-runner.js
 * 
 * Safe PowerShell script caller for Windows Defender replacement operations.
 * 
 * Spawns PowerShell with ExecutionPolicy Bypass and NonInteractive flags.
 * Never throws on non-zero exit codes — gracefully returns all results.
 * 
 * Requirements: 21.1, 21.6
 */

const { spawn } = require('child_process');
const path = require('path');

/**
 * Execute a PowerShell script safely.
 * 
 * @param {string} scriptPath - Absolute path to the .ps1 script file
 * @param {string[]} [params=[]] - Optional parameters to pass to the script
 * @returns {Promise<{exitCode: number, stdout: string, stderr: string}>}
 * 
 * @example
 * const result = await runScript('C:/path/to/script.ps1', ['arg1', 'arg2']);
 * if (result.exitCode !== 0) {
 *   console.error('Script failed:', result.stderr);
 * }
 */
async function runScript(scriptPath, params = []) {
  return new Promise((resolve) => {
    // Validate scriptPath
    if (!scriptPath || typeof scriptPath !== 'string') {
      resolve({
        exitCode: -1,
        stdout: '',
        stderr: 'Invalid script path provided'
      });
      return;
    }

    // Normalize the script path
    const normalizedPath = path.resolve(scriptPath);

    // Build PowerShell arguments
    // -ExecutionPolicy Bypass: Allow script execution without policy restrictions
    // -NonInteractive: Run without user prompts (required for automated execution)
    // -File: Specify script file to execute
    const args = [
      '-ExecutionPolicy',
      'Bypass',
      '-NonInteractive',
      '-File',
      normalizedPath,
      ...(Array.isArray(params) ? params : [])
    ];

    let stdout = '';
    let stderr = '';

    // Spawn powershell.exe
    const ps = spawn('powershell.exe', args, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    // Capture stdout
    ps.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    // Capture stderr
    ps.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    // Handle process exit - NEVER throw, always resolve
    ps.on('close', (exitCode) => {
      resolve({
        exitCode: exitCode ?? 0,
        stdout: stdout.trim(),
        stderr: stderr.trim()
      });
    });

    // Handle spawn errors (e.g., powershell.exe not found)
    ps.on('error', (error) => {
      resolve({
        exitCode: -1,
        stdout: '',
        stderr: `Failed to spawn PowerShell: ${error.message}`
      });
    });
  });
}

module.exports = {
  runScript
};
