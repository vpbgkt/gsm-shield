#!/usr/bin/env node
'use strict';

/**
 * bin/gsmshield.js — GSM Shield AV Official Command-Line Interface (CLI)
 *
 * Scan for Expiro, quarantine (neutralized) infected files, check services and
 * bundled binaries. Expiro cannot be repaired in place: infected files are
 * quarantined or replaced with a verified same-build clean copy.
 *
 * Commands:
 *   gsmshield scan <path>
 *   gsmshield disinfect <path> [--dry-run] [--trusted-source=<dir>]
 *   gsmshield clean-system
 *   gsmshield services [--save-baseline=<file>] [--baseline=<file>]
 *   gsmshield verify-binaries
 *   gsmshield memory-hunt
 *   gsmshield restore-clean
 *   gsmshield status
 */

const fs = require('fs');
const path = require('path');
const { scanFile, scanFiles, detectExpiroInfection, EXPIRO_SIGNATURES, STRUCTURAL_EXTENSIONS } = require('../engine/expiro-detector');
const ExpiroDisinfector = require('../engine/expiro-disinfector');

// Loaded lazily: it needs the better-sqlite3 native module, while scan,
// services and verify-binaries must work with plain Node (no npm install),
// e.g. on a freshly reinstalled machine.
let _quarantine = null;
function getQuarantine() {
  if (!_quarantine) _quarantine = require('../engine/quarantine');
  return _quarantine;
}

function optionValue(name) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : null;
}

const args = process.argv.slice(2);
const command = args[0] ? args[0].toLowerCase() : 'help';

function printHeader() {
  console.log('=====================================================================');
  console.log(' GSM SHIELD AV — CLI THREAT DEFENSE & DISINFECTION SYSTEM');
  console.log(' Expiro engine v3: structural layout detection + legacy heuristics');
  console.log('=====================================================================\n');
}

function printUsage() {
  printHeader();
  console.log('Usage: node bin/gsmshield.js <command> [options]\n');
  console.log('Commands:');
  console.log('  scan <target>             Scan a file or directory for the Expiro infection layout');
  console.log('  disinfect <target>        Quarantine infected files (or restore a verified clean copy)');
  console.log('  clean-system              Sweep common user locations and quarantine infections');
  console.log('  services                  Check service binaries and start types for Expiro persistence');
  console.log('  verify-binaries           Verify bundled ClamAV executables against the known-good manifest');
  console.log('  memory-hunt               Inspect active processes and startup persistence in RAM');
  console.log('  restore-clean             Restore verified false positives from quarantine');
  console.log('  status                    Display protection stack status and quarantine stats');
  console.log('  help                      Show this help message\n');
  console.log('Options:');
  console.log('  --dry-run                 Simulate actions without modifying or moving files');
  console.log('  --trusted-source=<dir>    Directory with clean vendor copies to restore from (verified same build)');
  console.log('  --save-baseline=<file>    (services) save current start types as a baseline');
  console.log('  --baseline=<file>         (services) compare against a saved baseline\n');
}

const EXCLUDED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'quarantine',
  'backups',
  '$recycle.bin',
  'system volume information',
]);

async function collectPEFiles(targetPath, maxDepth = 4) {
  const peFiles = [];
  const peExts = new Set(STRUCTURAL_EXTENSIONS);

  function walk(currentDir, depth) {
    if (depth > maxDepth) return;
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(currentDir, entry.name);
        const nameLower = entry.name.toLowerCase();
        if (entry.isDirectory()) {
          if (!EXCLUDED_DIRS.has(nameLower)) {
            walk(full, depth + 1);
          }
        } else if (entry.isFile()) {
          const ext = path.extname(full).toLowerCase();
          if (peExts.has(ext)) {
            peFiles.push(full);
          }
        }
      }
    } catch (_) {}
  }

  const stat = fs.statSync(targetPath);
  if (stat.isDirectory()) {
    walk(targetPath, 0);
  } else if (stat.isFile()) {
    peFiles.push(targetPath);
  }
  return peFiles;
}

async function cmdScan() {
  const target = args[1];
  if (!target) {
    console.error('Error: Please specify a file or directory to scan.');
    console.log('Example: node bin/gsmshield.js scan "C:\\Program Files\\Git"');
    process.exit(1);
  }

  if (!fs.existsSync(target)) {
    console.error(`Error: Target path does not exist: ${target}`);
    process.exit(1);
  }

  printHeader();
  console.log(`[i] Gathering PE executables in: ${target}...`);
  const peFiles = await collectPEFiles(target, 5);
  console.log(`[i] Found ${peFiles.length} executable(s) to analyze.\n`);

  let infected = [];
  let scanned = 0;

  for (const f of peFiles) {
    const res = await scanFile(f);
    scanned++;
    if (res.isInfected) {
      infected.push(res);
      console.log(`\n[!] INFECTED: ${res.filePath} (${res.confidence}% Confidence)`);
      (res.reasons || []).forEach((r) => console.log(`    - ${r}`));
    } else if (scanned % 50 === 0 || scanned === peFiles.length) {
      process.stdout.write(`  Analyzed: ${scanned}/${peFiles.length} | Threats: ${infected.length}\r`);
    }
  }

  console.log('\n\n=====================================================================');
  console.log(' SCAN SUMMARY');
  console.log('=====================================================================');
  console.log(`Total Files Analyzed:  ${peFiles.length}`);
  console.log(`Clean Executables:     ${peFiles.length - infected.length}`);
  console.log(`Infections Found:      ${infected.length}`);

  if (infected.length > 0) {
    console.log('\nTo disinfect these files without damaging programs, run:');
    console.log(`node bin/gsmshield.js disinfect "${target}"`);
  }
}

async function cmdDisinfect() {
  const target = args[1];
  const isDryRun = args.includes('--dry-run');

  if (!target) {
    console.error('Error: Please specify a file or directory to disinfect.');
    process.exit(1);
  }

  if (!fs.existsSync(target)) {
    console.error(`Error: Target path does not exist: ${target}`);
    process.exit(1);
  }

  printHeader();
  console.log(`[i] Target: ${target}`);
  console.log(`[i] Mode:   ${isDryRun ? 'DRY-RUN (Simulation)' : 'LIVE DISINFECTION'}\n`);

  const peFiles = await collectPEFiles(target, 5);
  const trusted = optionValue('trusted-source');
  const disinfector = new ExpiroDisinfector(getQuarantine(), { trustedSourceDirs: trusted ? [trusted] : [] });
  let processed = 0;
  let disinfected = 0;

  for (const f of peFiles) {
    const detection = detectExpiroInfection(f);
    if (detection.isInfected) {
      processed++;
      console.log(`\n[!] Processing Threat: ${f}`);
      console.log(`    Threat: ${detection.threatName} (${detection.confidence}% Confidence)`);
      (detection.reasons || []).forEach((r) => console.log(`    - ${r}`));

      if (!isDryRun) {
        const result = await disinfector.disinfectFile(f, detection);
        console.log(`    Action Taken: ${result.action.toUpperCase()}`);
        if (result.quarantinePath) console.log(`    Quarantined (neutralized): ${result.quarantinePath}`);
        if (result.recommendation) console.log(`    Next step: ${result.recommendation}`);
        if (result.success) disinfected++;
      } else {
        console.log('    [DRY-RUN] Would restore a verified same-build clean copy if supplied, otherwise quarantine.');
      }
    }
  }

  console.log('\n=====================================================================');
  console.log(' DISINFECTION SUMMARY');
  console.log('=====================================================================');
  console.log(`Threats Identified:  ${processed}`);
  if (!isDryRun) {
    console.log(`Successfully Fixed:  ${disinfected}`);
  }
}

async function cmdCleanSystem() {
  const customTarget = args[1] && !args[1].startsWith('--') ? args[1] : null;
  const isDryRun = args.includes('--dry-run');

  printHeader();
  console.log(`[*] Initiating System Threat Sweep & Safe Disinfection (${isDryRun ? 'DRY-RUN' : 'LIVE'})...\n`);

  const targetConfigs = customTarget
    ? [{ path: customTarget, depth: 5 }]
    : [
        { path: path.join(process.env.USERPROFILE, 'Downloads'), depth: 5 },
        { path: path.join(process.env.USERPROFILE, 'Desktop'), depth: 4 },
        { path: path.join(process.env.USERPROFILE, 'Documents'), depth: 4 },
        { path: process.env.TEMP, depth: 3 },
        { path: path.join(process.env.USERPROFILE, 'AppData', 'Local', 'Temp'), depth: 3 },
        { path: path.join(process.env.USERPROFILE, 'AppData', 'Local', 'Programs'), depth: 4 },
        { path: 'C:\\Windows\\Temp', depth: 2 },
        { path: 'C:\\Users\\Public', depth: 3 },
      ].filter((cfg) => cfg.path && fs.existsSync(cfg.path));

  const disinfector = new ExpiroDisinfector(getQuarantine());
  let totalScanned = 0;
  let threatsFound = 0;
  let fixedCount = 0;

  for (const cfg of targetConfigs) {
    console.log(`\n[*] Sweeping Location: ${cfg.path} (Depth: ${cfg.depth})`);
    const files = await collectPEFiles(cfg.path, cfg.depth);
    console.log(`    Found ${files.length} PE executables.`);

    for (const f of files) {
      totalScanned++;
      const det = detectExpiroInfection(f);
      if (det.isInfected) {
        threatsFound++;
        console.log(`\n[!] Threat Detected: ${f}`);
        console.log(`    Threat: ${det.threatName} (Confidence: ${det.confidence}%)`);
        (det.reasons || []).forEach((r) => console.log(`    - ${r}`));

        if (!isDryRun) {
          const res = await disinfector.disinfectFile(f, det);
          console.log(`    Action: ${res.action.toUpperCase()}`);
          if (res.recommendation) console.log(`    Next step: ${res.recommendation}`);
          if (res.success) fixedCount++;
        } else {
          console.log('    [DRY-RUN] Would quarantine (neutralized).');
        }
      } else if (totalScanned % 100 === 0) {
        process.stdout.write(`  Analyzed ${totalScanned} files... (Threats: ${threatsFound})\r`);
      }
    }
  }

  console.log('\n\n=====================================================================');
  console.log(' SYSTEM CLEANUP COMPLETE');
  console.log('=====================================================================');
  console.log(`Total PE Files Checked: ${totalScanned}`);
  console.log(`Threats Identified:     ${threatsFound}`);
  console.log(`Safely Handled/Fixed:   ${fixedCount}`);
}

async function cmdMemoryHunt() {
  printHeader();
  console.log('[*] Launching Expiro RAM & Persistence Hunter...\n');
  const { execSync } = require('child_process');
  try {
    const scriptPath = path.join(__dirname, '..', 'research', 'tools', 'memory-hunter.ps1');
    execSync(`powershell -ExecutionPolicy Bypass -File "${scriptPath}"`, { stdio: 'inherit' });
  } catch (err) {
    console.error('Failed to run memory hunter:', err.message);
  }
}

async function cmdRestoreClean() {
  printHeader();
  console.log('[*] Running Safe False-Positive Restoration from Quarantine...\n');
  const restoreScript = path.join(__dirname, '..', 'research', 'tools', 'safe-restore-quarantine.js');
  require(restoreScript);
}

async function cmdStatus() {
  printHeader();
  console.log('GSM SHIELD AV SUBSYSTEM STATUS:');
  console.log('  Expiro engine:          v3 (structural layout + legacy heuristics)');
  console.log(`  Detection Threshold:    ${EXPIRO_SIGNATURES.detectionThreshold}% (legacy layer)`);
  const qDir = getQuarantine().QUARANTINE_DIR;
  const qCount = fs.existsSync(qDir) ? fs.readdirSync(qDir).length : 0;
  console.log(`  Quarantine:             ${qCount} file(s) in ${qDir}`);
  for (const legacy of ['C:\\GSMShield\\Quarantine', 'C:\\GSMShield\\Backups']) {
    if (fs.existsSync(legacy)) {
      console.log(`  WARNING: legacy folder ${legacy} holds ${fs.readdirSync(legacy).length} entr(y/ies) stored as runnable files. Do not execute; review and delete.`);
    }
  }
  const { verifyManifestDirectory } = require('../engine/binary-integrity');
  const v = verifyManifestDirectory(path.join(__dirname, '..', 'assets', 'clamav'));
  console.log(`  Bundled ClamAV:         ${v.ok ? 'verified against manifest' : 'FAILED verification (run verify-binaries)'}\n`);
}

async function cmdServices() {
  printHeader();
  const svc = require('../engine/service-integrity');
  const services = await svc.readWindowsServices();
  const saveTo = optionValue('save-baseline');
  if (saveTo) {
    fs.writeFileSync(saveTo, JSON.stringify(svc.makeBaseline(services), null, 2));
    console.log(`[i] Baseline of ${services.length} services written to ${saveTo}`);
  }
  const baselineFile = optionValue('baseline');
  const baseline = baselineFile ? JSON.parse(fs.readFileSync(baselineFile, 'utf8')) : null;
  const { findings, checked } = svc.assessServices(services, { baseline });
  console.log(`[i] Services read: ${services.length}; executables checked: ${checked}`);
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  for (const f of findings) console.log(`  [${f.severity.toUpperCase()}] ${f.service}: ${f.detail}${f.imagePath ? ` (${f.imagePath})` : ''}`);
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) {
    console.log('\nInfected or hijacked services found. Do NOT reboot before disabling them (elevated):');
    console.log('  sc.exe config <name> start= disabled   then follow research/DISINFECTION_PROCEDURE.md');
    process.exitCode = 2;
  }
}

async function cmdVerifyBinaries() {
  printHeader();
  const { verifyManifestDirectory } = require('../engine/binary-integrity');
  const dir = path.join(__dirname, '..', 'assets', 'clamav');
  const { ok, results } = verifyManifestDirectory(dir);
  for (const r of results) console.log(`  ${r.ok ? 'OK  ' : 'FAIL'} ${r.file} — ${r.reason}`);
  console.log(ok ? '\nAll bundled ClamAV executables match the known-good manifest.' : '\nVerification FAILED. Do not build or run GSM Shield until fixed.');
  if (!ok) process.exitCode = 2;
}

async function main() {
  switch (command) {
    case 'scan':
      await cmdScan();
      break;
    case 'disinfect':
      await cmdDisinfect();
      break;
    case 'clean-system':
      await cmdCleanSystem();
      break;
    case 'memory-hunt':
      await cmdMemoryHunt();
      break;
    case 'restore-clean':
      await cmdRestoreClean();
      break;
    case 'status':
      await cmdStatus();
      break;
    case 'services':
      await cmdServices();
      break;
    case 'verify-binaries':
      await cmdVerifyBinaries();
      break;
    case 'help':
    default:
      printUsage();
      break;
  }
}

main().catch((err) => {
  console.error('\n[!] Fatal Error:', err.message);
  process.exit(1);
});
