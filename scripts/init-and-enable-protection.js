// Initialize database and enable Expiro protection
// This manually creates the database and enables protection

const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');
const fs = require('fs');

const appDataPath = path.join(os.homedir(), 'AppData', 'Roaming', 'GSMShieldAV');
const dbPath = path.join(appDataPath, 'gsm-shield.db');

console.log('🛡️ GSM Shield AV - Database Initializer & Protection Enabler\n');
console.log(`📂 Database path: ${dbPath}\n`);

// Create directory if it doesn't exist
if (!fs.existsSync(appDataPath)) {
    console.log('📁 Creating GSMShieldAV directory...');
    fs.mkdirSync(appDataPath, { recursive: true });
}

try {
    console.log('📂 Opening/creating database...');
    const db = new Database(dbPath);
    
    // Create tables if they don't exist
    console.log('🔧 Initializing database schema...\n');
    
    // Settings table
    db.exec(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        );
    `);
    
    // Monitored paths table
    db.exec(`
        CREATE TABLE IF NOT EXISTS monitored_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT,
            updated_at TEXT
        );
    `);
    
    // Scan history table
    db.exec(`
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT,
            files_scanned INTEGER,
            threats_found INTEGER,
            start_time TEXT,
            end_time TEXT,
            status TEXT
        );
    `);
    
    // Quarantine table
    db.exec(`
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT,
            quarantine_path TEXT,
            threat_name TEXT,
            detected_at TEXT,
            file_hash TEXT
        );
    `);
    
    console.log('✅ Database schema initialized\n');
    
    // Enable Expiro protection
    console.log('⚙️  Enabling Expiro real-time protection...');
    
    db.prepare(`
        INSERT OR REPLACE INTO settings (key, value, updated_at)
        VALUES ('expiro_protection_enabled', 'true', datetime('now'))
    `).run();
    
    console.log('   ✓ Expiro protection enabled\n');
    
    // Add monitored paths
    const username = os.userInfo().username;
    const paths = [
        { path: 'C:\\Program Files', priority: 'high' },
        { path: 'C:\\Program Files (x86)', priority: 'high' },
        { path: `C:\\Users\\${username}\\AppData\\Local`, priority: 'medium' },
        { path: `C:\\Users\\${username}\\Downloads`, priority: 'high' },
        { path: `C:\\Users\\${username}\\Desktop`, priority: 'medium' }
    ];
    
    console.log('📁 Configuring monitored paths...');
    
    for (const item of paths) {
        try {
            db.prepare(`
                INSERT OR IGNORE INTO monitored_paths (path, enabled, created_at, updated_at)
                VALUES (?, 1, datetime('now'), datetime('now'))
            `).run(item.path);
            console.log(`   ✓ ${item.priority.toUpperCase()} priority: ${item.path}`);
        } catch (err) {
            console.log(`   • Already exists: ${item.path}`);
        }
    }
    
    // Set other important settings
    console.log('\n⚙️  Configuring protection settings...');
    
    const settings = [
        ['realtime_protection', 'true'],
        ['scan_on_download', 'true'],
        ['scan_on_execute', 'true'],
        ['quarantine_infected', 'true'],
        ['expiro_confidence_threshold', '50']
    ];
    
    for (const [key, value] of settings) {
        db.prepare(`
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
        `).run(key, value);
        console.log(`   ✓ ${key}: ${value}`);
    }
    
    // Verify settings
    console.log('\n🔍 Verifying configuration...');
    const expiroEnabled = db.prepare('SELECT value FROM settings WHERE key = ?').get('expiro_protection_enabled');
    const monitoredCount = db.prepare('SELECT COUNT(*) as count FROM monitored_paths WHERE enabled = 1').get();
    
    console.log(`   • Expiro Protection: ${expiroEnabled?.value === 'true' ? '✅ ENABLED' : '❌ DISABLED'}`);
    console.log(`   • Monitored Paths: ${monitoredCount.count} directories`);
    
    db.close();
    
    console.log('\n✅ SUCCESS! Database initialized and protection enabled!');
    console.log('\n📋 Next Steps:');
    console.log('   1. Start GSM Shield AV');
    console.log('   2. Protection will be automatically active');
    console.log('   3. Proceed with full Expiro removal\n');
    console.log('⚠️  You can now start GSM Shield AV and protection will be active!\n');
    
} catch (error) {
    console.error('❌ ERROR:', error.message);
    console.error(error.stack);
    process.exit(1);
}
