// Enable Expiro Protection Programmatically
// This script runs as a standalone process to enable protection

const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');
const fs = require('fs');

// Locate the database
const appDataPath = path.join(os.homedir(), 'AppData', 'Roaming', 'gsm-shield-av');
const dbPath = path.join(appDataPath, 'database.db');

console.log('🛡️ GSM Shield AV - Expiro Protection Enabler\n');

if (!fs.existsSync(dbPath)) {
    console.log('❌ Database not found. GSM Shield AV may not have been initialized yet.');
    console.log(`   Expected location: ${dbPath}`);
    console.log('   Please launch GSM Shield AV first, then run this script.\n');
    process.exit(1);
}

try {
    console.log('📂 Opening database...');
    const db = new Database(dbPath);
    
    // Check current protection status
    console.log('🔍 Checking current protection status...\n');
    
    const currentSettings = db.prepare('SELECT * FROM settings WHERE key = ?').get('expiro_protection_enabled');
    
    if (currentSettings) {
        const isEnabled = currentSettings.value === 'true' || currentSettings.value === '1';
        console.log(`Current Status: ${isEnabled ? '✅ ENABLED' : '❌ DISABLED'}`);
        
        if (isEnabled) {
            console.log('\n✅ Expiro protection is already enabled!');
            db.close();
            process.exit(0);
        }
    }
    
    // Enable Expiro protection
    console.log('⚙️  Enabling Expiro real-time protection...');
    
    db.prepare(`
        INSERT OR REPLACE INTO settings (key, value, updated_at)
        VALUES ('expiro_protection_enabled', 'true', datetime('now'))
    `).run();
    
    // Add critical monitored paths if not present
    const paths = [
        'C:\\Program Files',
        'C:\\Program Files (x86)',
        `C:\\Users\\${os.userInfo().username}\\AppData\\Local`,
        `C:\\Users\\${os.userInfo().username}\\Downloads`
    ];
    
    console.log('📁 Configuring monitored paths...');
    
    for (const monitorPath of paths) {
        const existing = db.prepare('SELECT * FROM monitored_paths WHERE path = ?').get(monitorPath);
        
        if (!existing) {
            db.prepare(`
                INSERT INTO monitored_paths (path, enabled, created_at)
                VALUES (?, 1, datetime('now'))
            `).run(monitorPath);
            console.log(`   ✓ Added: ${monitorPath}`);
        } else {
            console.log(`   • Already monitored: ${monitorPath}`);
        }
    }
    
    db.close();
    
    console.log('\n✅ SUCCESS! Expiro protection has been enabled!');
    console.log('\n📋 Next Steps:');
    console.log('   1. Restart GSM Shield AV to apply changes');
    console.log('   2. Verify protection is active in the UI');
    console.log('   3. Proceed with Expiro removal');
    console.log('\n⚠️  IMPORTANT: Restart GSM Shield AV now for changes to take effect!\n');
    
} catch (error) {
    console.error('❌ ERROR:', error.message);
    console.error('\nFailed to enable protection. Please enable manually in the GSM Shield AV UI.');
    process.exit(1);
}
