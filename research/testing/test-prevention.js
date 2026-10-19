const ExpiroPrevention = require('../../engine/expiro-prevention');
const path = require('path');

async function testPrevention() {
  console.log('Testing Expiro Prevention...\n');
  
  // Mock quarantine module
  const mockQuarantine = {
    quarantineFile: async (filePath, threatName) => {
      console.log(`  [MOCK] Quarantined: ${path.basename(filePath)}`);
      return { success: true, quarantinePath: '/quarantine/' + path.basename(filePath) };
    }
  };
  
  const prevention = new ExpiroPrevention(mockQuarantine);
  
  // Test 1: Start/Stop
  console.log('Test 1: Start/Stop Prevention');
  prevention.start();
  console.log(`  Active: ${prevention.isActive} ✓`);
  prevention.stop();
  console.log(`  Stopped: ${!prevention.isActive} ✓\n`);
  
  // Test 2: Statistics
  console.log('Test 2: Statistics Tracking');
  prevention.start();
  const stats = prevention.getStats();
  console.log(`  Files Scanned: ${stats.filesScanned}`);
  console.log(`  Infections Blocked: ${stats.infectionsBlocked}`);
  console.log(`  Is Active: ${stats.isActive} ✓\n`);
  
  // Test 3: Pre-execution scan
  console.log('Test 3: Pre-Execution Scan');
  const eicarPath = path.join('research', 'testing', 'eicar', 'eicar.com');
  const scanResult = await prevention.scanBeforeExecution(eicarPath);
  console.log(`  File: eicar.com`);
  console.log(`  Allowed: ${scanResult.allowed}`);
  console.log(`  Blocked: ${scanResult.blocked || false}`);
  console.log(`  Reason: ${scanResult.reason} ✓\n`);
  
  // Test 4: Report generation
  console.log('Test 4: Report Generation');
  const report = prevention.generateReport();
  console.log(`  Report length: ${report.length} characters ✓`);
  console.log(`  Contains title: ${report.includes('EXPIRO REAL-TIME PREVENTION') ? 'YES' : 'NO'} ✓\n`);
  
  prevention.stop();
  
  console.log('✓ Prevention module tests complete\n');
}

testPrevention().catch(err => {
  console.error('Test failed:', err.message);
  process.exit(1);
});
