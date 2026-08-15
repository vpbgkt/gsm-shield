/**
 * scripts/build.js — Three-stage build orchestrator for GSM Shield AV
 *
 * Stages:
 *   Stage 1 (Req 23.1): Build React renderer with Vite
 *                        cd renderer && npm run build
 *                        Output: renderer/dist/
 *
 *   Stage 2 (Req 23.2): Package with electron-builder (Windows x64, unpacked dir + ASAR)
 *                        electron-builder --win --x64 --dir
 *                        Output: dist/win-unpacked/
 *
 *   Stage 3 (Req 23.3): Compile installer with Inno Setup 6
 *                        iscc installer/setup.iss
 *                        Output: dist/installer/GSMShieldAV-Setup.exe
 *
 * CLI flags:
 *   --stage1   Run Stage 1 only
 *   --stage2   Run Stage 2 only
 *   --stage3   Run Stage 3 only
 *   (no flags) Run all three stages in order
 *
 * Inno Setup graceful skip:
 *   If `iscc` is not found on PATH, Stage 3 logs a warning and is skipped
 *   rather than failing the build. Inno Setup must be installed separately.
 */

'use strict';

const { execSync, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ROOT_DIR = path.resolve(__dirname, '..');

/** Print a clearly visible stage header to stdout. */
function printHeader(label) {
  const line = '='.repeat(60);
  console.log(`\n${line}`);
  console.log(`  ${label}`);
  console.log(`${line}\n`);
}

/**
 * Run a shell command synchronously.
 * Streams stdout/stderr to the terminal in real time.
 * Throws if the process exits with a non-zero code.
 *
 * @param {string} cmd  - The command string to execute
 * @param {object} opts - Options forwarded to execSync (cwd, env, etc.)
 */
function run(cmd, opts = {}) {
  console.log(`> ${cmd}\n`);
  try {
    execSync(cmd, {
      stdio: 'inherit',
      cwd: ROOT_DIR,
      ...opts,
    });
  } catch (err) {
    // execSync throws when the child process exits non-zero.
    // The child's output has already been streamed to the terminal.
    console.error(`\n[BUILD ERROR] Command failed: ${cmd}`);
    console.error(`Exit code: ${err.status}`);
    process.exit(err.status || 1);
  }
}

/**
 * Check whether a binary is available on PATH without throwing.
 *
 * @param {string} binary - Executable name to probe (e.g. 'iscc')
 * @returns {boolean}
 */
function isOnPath(binary) {
  // Use `where` on Windows, `which` on Unix-like systems
  const probe = process.platform === 'win32' ? 'where' : 'which';
  const result = spawnSync(probe, [binary], { encoding: 'utf8' });
  return result.status === 0;
}

// ---------------------------------------------------------------------------
// Build stages
// ---------------------------------------------------------------------------

/**
 * Stage 1 — Build the React renderer with Vite.
 * Runs inside renderer/ so that vite.config.js picks up the correct outDir.
 * Requirement 23.1
 */
function stage1() {
  printHeader('Stage 1 — Build React renderer (Vite)');
  const rendererDir = path.join(ROOT_DIR, 'renderer');

  if (!fs.existsSync(rendererDir)) {
    console.error('[BUILD ERROR] renderer/ directory not found. Cannot run Stage 1.');
    process.exit(1);
  }

  run('npm run build', { cwd: rendererDir });

  const distDir = path.join(rendererDir, 'dist');
  if (!fs.existsSync(distDir)) {
    console.error('[BUILD ERROR] Stage 1 completed but renderer/dist/ was not created.');
    process.exit(1);
  }

  console.log('\n[Stage 1 DONE] renderer/dist/ created successfully.\n');
}

/**
 * Stage 2 — Package with electron-builder (Windows x64, unpacked dir).
 * Produces dist/win-unpacked/ (directory target, not an EXE installer).
 * The ASAR archive is embedded per electron-builder.yml configuration.
 * Requirement 23.2
 */
function stage2() {
  printHeader('Stage 2 — Package with electron-builder (Windows x64, --dir)');
  run('npx electron-builder --win --x64 --dir');

  const unpackedDir = path.join(ROOT_DIR, 'dist', 'win-unpacked');
  if (!fs.existsSync(unpackedDir)) {
    console.error('[BUILD ERROR] Stage 2 completed but dist/win-unpacked/ was not created.');
    process.exit(1);
  }

  console.log('\n[Stage 2 DONE] dist/win-unpacked/ created successfully.\n');
}

/**
 * Stage 3 — Compile installer with Inno Setup 6.
 * Requires `iscc` (Inno Setup Compiler) to be installed and on PATH.
 * If it is not found, a warning is logged and this stage is skipped gracefully.
 * Requirement 23.3
 */
function stage3() {
  printHeader('Stage 3 — Compile installer (Inno Setup 6)');

  if (!isOnPath('iscc')) {
    console.warn(
      '[Stage 3 WARNING] `iscc` (Inno Setup Compiler) was not found on PATH.\n' +
      '  Stage 3 is being skipped.\n' +
      '  To produce the installer, install Inno Setup 6 from https://jrsoftware.org/isinfo.php\n' +
      '  and ensure `iscc` is available on your PATH, then re-run:\n' +
      '    node scripts/build.js --stage3\n'
    );
    return;
  }

  const issFile = path.join(ROOT_DIR, 'installer', 'setup.iss');
  if (!fs.existsSync(issFile)) {
    console.error('[BUILD ERROR] installer/setup.iss not found. Cannot run Stage 3.');
    process.exit(1);
  }

  run(`iscc "${issFile}"`);

  const outputExe = path.join(ROOT_DIR, 'dist', 'installer', 'GSMShieldAV-Setup.exe');
  if (!fs.existsSync(outputExe)) {
    console.warn(
      '[Stage 3 WARNING] iscc ran but dist/installer/GSMShieldAV-Setup.exe was not found.\n' +
      '  The OutputDir in setup.iss may differ — check dist/installer/ manually.'
    );
  } else {
    console.log('\n[Stage 3 DONE] dist/installer/GSMShieldAV-Setup.exe created successfully.\n');
  }
}

// ---------------------------------------------------------------------------
// Entry point — parse CLI flags and run selected stage(s)
// ---------------------------------------------------------------------------

/**
 * Main function.
 * When this module is executed directly (node scripts/build.js [flags]),
 * it parses argv and runs the appropriate stage(s).
 * When required by another module (e.g., in tests), it exports the stage
 * functions without running anything.
 */
function main() {
  const args = process.argv.slice(2);

  const runStage1 = args.includes('--stage1');
  const runStage2 = args.includes('--stage2');
  const runStage3 = args.includes('--stage3');
  const runAll = !runStage1 && !runStage2 && !runStage3;

  console.log('GSM Shield AV — Build Pipeline');
  console.log(`Working directory: ${ROOT_DIR}`);

  if (runAll) {
    console.log('Running all three stages...');
    stage1();
    stage2();
    stage3();
    printHeader('Build Complete — all stages finished');
  } else {
    if (runStage1) stage1();
    if (runStage2) stage2();
    if (runStage3) stage3();
  }
}

// Run only when this file is the entry point, not when required/imported.
if (require.main === module) {
  main();
}

// Export stage functions for testing and programmatic use.
module.exports = { stage1, stage2, stage3, isOnPath };
