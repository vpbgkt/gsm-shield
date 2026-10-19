/**
 * Emergency script to enable real-time protection in GSM Shield AV database
 */

const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');

const dbPath = path.join(
  process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'),
  'GSMShieldAV',
  'gsm-shield.db'
);

console.log(`\n=== GSM Shield AV Protection Settings ===\n`);
console.log(`Database: ${dbPath}\n`);

try {
  const db = new Database(dbPath);
  
  // Check current settings
  console.log('Current Settings:');
  const realtimeRow = db.prepare("SELECT value FROM settings WHERE key = 'realtime_protection'").get();
  const autoQuarantineRow = db.prepare("SELECT value FROM settings WHERE key = 'auto_quarantine'").get();
  const monitoredPathsRow = db.prepare("SELECT value FROM settings WHERE key = 'monitored_paths'").get();
  
  console.log(`  Real-Time Protection: ${realtimeRow ? realtimeRow.value : 'NOT SET'} ${realtimeRow?.value === '1' ? '(ENABLED)' : '(DISABLED)'}`);
  console.log(`  Auto-Quarantine: ${autoQuarantineRow ? autoQuarantineRow.value : 'NOT SET'} ${autoQuarantineRow?.value === '1' ? '(ENABLED)' : '(DISABLED)'}`);
  
  let monitoredPaths = [];
  try {
    if (monitoredPathsRow && monitoredPathsRow.value) {
      monitoredPaths = JSON.parse(monitoredPathsRow.value);
    }
  } catch (e) {
    console.error('  Error parsing monitored paths:', e.message);
  }
  console.log(`  Monitored Paths: ${monitoredPaths.length} path(s)`);
  monitoredPaths.forEach(p => console.log(`    - ${p}`));
  
  // Enable both settings if not already enabled
  let changed = false;
  
  if (!realtimeRow || realtimeRow.value !== '1') {
    console.log(`\nEnabling Real-Time Protection...`);
    db.prepare("UPDATE settings SET value = '1' WHERE key = 'realtime_protection'").run();
    changed = true;
  }
  
  if (!autoQuarantineRow || autoQuarantineRow.value !== '1') {
    console.log(`Enabling Auto-Quarantine...`);
    db.prepare("UPDATE settings SET value = '1' WHERE key = 'auto_quarantine'").run();
    changed = true;
  }
  
  // Add default monitored paths if none exist
  if (monitoredPaths.length === 0) {
    console.log(`\nAdding default monitored paths...`);
    const defaultPaths = [
      'C:\\Users',
      'C:\\Program Files',
      'C:\\Program Files (x86)'
    ];
    const pathsJson = JSON.stringify(defaultPaths);
    db.prepare("UPDATE settings SET value = ? WHERE key = 'monitored_paths'").run(pathsJson);
    console.log(`  Added ${defaultPaths.length} default paths`);
    changed = true;
  }
  
  db.close();
  
  if (changed) {
    console.log(`\n✓ Protection settings updated!`);
    console.log(`\nNext step: Restart GSM Shield AV for changes to take effect`);
    console.log(`  1. Close GSM Shield AV`);
    console.log(`  2. Run: Start-Process "dist\\win-unpacked\\GSM Shield AV.exe"`);
  } else {
    console.log(`\n✓ Protection is already enabled!`);
    console.log(`\nIf protection isn't working:`);
    console.log(`  1. Make sure GSM Shield AV is running`);
    console.log(`  2. Restart the application`);
  }
  
} catch (error) {
  console.error(`\n✗ Error: ${error.message}`);
  if (error.message.includes('SQLITE_CANTOPEN')) {
    console.error(`\nDatabase file not found. GSM Shield AV may not have been started yet.`);
    console.error(`Start GSM Shield AV first, then run this script.`);
  }
  process.exit(1);
}

console.log('');
