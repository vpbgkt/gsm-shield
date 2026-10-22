/**
 * research/tools/safe-restore-quarantine.js
 *
 * Analyzes all files in C:\GSMShield\Quarantine and restores files that are
 * structurally clean (engine v3) back to their original installation paths.
 *
 * HISTORICAL NOTE: before 2026-10-22 this script relied on the v2 heuristics,
 * which do not detect real Expiro. Any restore performed with that version
 * must be treated as possibly having re-introduced infected files.
 *
 * Usage:
 *   node research/tools/safe-restore-quarantine.js --dry-run
 *   node research/tools/safe-restore-quarantine.js --restore
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { detectExpiroInfection, EXPIRO_SIGNATURES } = require('../../engine/expiro-detector');

const QUARANTINE_DIR = 'C:\\GSMShield\\Quarantine';
const LOG_FILE = path.join(QUARANTINE_DIR, 'quarantine_log.txt');
const RESTORE_LOG = 'C:\\GSMShield\\restored_log.txt';

const isDryRun = !process.argv.includes('--restore');

async function run() {
  console.log('=====================================================================');
  console.log(' GSM SHIELD AV — SAFE QUARANTINE RESTORATION AUDIT (ENGINE v2)');
  console.log(` Mode: ${isDryRun ? 'DRY-RUN (Simulating restoration)' : 'LIVE RESTORATION'}`);
  console.log('=====================================================================\n');

  if (!fs.existsSync(LOG_FILE)) {
    console.error(`[!] Quarantine log not found at: ${LOG_FILE}`);
    process.exit(1);
  }

  const logLines = fs.readFileSync(LOG_FILE, 'utf8').split(/\r?\n/).filter(Boolean);
  console.log(`[i] Total quarantine records in log: ${logLines.length}\n`);

  // Map each log entry to its quarantine file path
  // quarantine script used:
  //   $quarantinePath = Join-Path $quarantineDir $file.Name
  //   while (Test-Path $quarantinePath) { $quarantinePath = Join-Path $quarantineDir "$($file.BaseName)_$counter$($file.Extension)" }
  const nameCounts = new Map();
  const records = [];

  for (const line of logLines) {
    const parts = line.split(' | ');
    if (parts.length < 3) continue;

    const originalPath = parts[1].trim();
    const fileName = path.basename(originalPath);
    const ext = path.extname(fileName);
    const baseName = path.basename(fileName, ext);

    const count = nameCounts.get(fileName) || 0;
    nameCounts.set(fileName, count + 1);

    let quarantineName = fileName;
    if (count > 0) {
      quarantineName = `${baseName}_${count}${ext}`;
    }

    const quarantinePath = path.join(QUARANTINE_DIR, quarantineName);
    records.push({
      originalPath,
      quarantinePath,
      quarantineName,
      oldConfidence: parts[2] ? parts[2].replace('Confidence: ', '') : 'unknown',
    });
  }

  let cleanCount = 0;
  let infectedCount = 0;
  let missingCount = 0;
  let restoredCount = 0;
  let alreadyExistsCount = 0;
  const restoreLogEntries = [];

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];

    if (!fs.existsSync(rec.quarantinePath)) {
      missingCount++;
      continue;
    }

    // Run the detector (v3: structural layer + legacy heuristics).
    // WARNING (2026-10-22): the v2-only detector scored real Expiro infections
    // at 0, so earlier runs of this script could restore INFECTED files as
    // "false positives". A restore now requires an explicit structural
    // verdict of 'clean' in addition to a low legacy score.
    const assessment = detectExpiroInfection(rec.quarantinePath);
    const confidence = assessment.confidence || 0;
    const structurallyClean = !!(assessment.structural && assessment.structural.verdict === 'clean');

    if (confidence < 50 && !assessment.isInfected && structurallyClean) {
      cleanCount++;

      if (!isDryRun) {
        try {
          const destDir = path.dirname(rec.originalPath);
          if (!fs.existsSync(destDir)) {
            fs.mkdirSync(destDir, { recursive: true });
          }

          if (fs.existsSync(rec.originalPath)) {
            alreadyExistsCount++;
          } else {
            fs.copyFileSync(rec.quarantinePath, rec.originalPath);
            restoredCount++;
            const logEntry = `RESTORED | ${new Date().toISOString()} | ${rec.originalPath} | Score: ${confidence}% | From: ${rec.quarantineName}`;
            restoreLogEntries.push(logEntry);
          }
        } catch (err) {
          console.error(`[-] Error restoring ${rec.originalPath}: ${err.message}`);
        }
      }
    } else {
      infectedCount++;
      console.warn(`[!] KEEPING QUARANTINED: ${rec.quarantineName} (Original: ${rec.originalPath})`);
      console.warn(`    Confidence: ${confidence}% | Reasons: ${(assessment.reasons || []).join(', ')}`);
    }

    if ((i + 1) % 150 === 0 || i === records.length - 1) {
      process.stdout.write(`  Processed ${i + 1}/${records.length} files...\r`);
    }
  }

  console.log('\n\n=====================================================================');
  console.log(' AUDIT & RESTORATION RESULTS');
  console.log('=====================================================================');
  console.log(`  Total Logged Entries:       ${records.length}`);
  console.log(`  Verified Clean / Safe:      ${cleanCount} (${((cleanCount / records.length) * 100).toFixed(1)}%)`);
  console.log(`  Flagged Real Threats Kept:  ${infectedCount}`);
  console.log(`  Missing in Quarantine:      ${missingCount}`);

  if (!isDryRun) {
    console.log(`  Successfully Restored:      ${restoredCount}`);
    console.log(`  Already Existing at Dest:   ${alreadyExistsCount}`);

    if (restoreLogEntries.length > 0) {
      fs.appendFileSync(RESTORE_LOG, restoreLogEntries.join('\n') + '\n');
      console.log(`\n[✓] Restoration log written to: ${RESTORE_LOG}`);
    }
  } else {
    console.log('\n[i] Dry-run complete. No files were moved.');
    console.log('    To execute live restoration, run:');
    console.log('    node research/tools/safe-restore-quarantine.js --restore');
  }
}

run().catch(console.error);
