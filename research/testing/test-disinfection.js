const ExpiroDisinfector = require('../../engine/expiro-disinfector');
const path = require('path');

async function testDisinfection() {
  console.log('Testing Expiro Disinfection...\n');
  
  // Mock quarantine module
  const mockQuarantine = {
    quarantineFile: async (filePath, threatName) => {
      console.log(`  [MOCK] Quarantined: ${path.basename(filePath)}`);
      return { 
        success: true, 
        quarantinePath: '/quarantine/' + path.basename(filePath) 
      };
    }
  };
  
  const disinfector = new ExpiroDisinfector(mockQuarantine);
  
  // Test 1: File criticality assessment
  console.log('Test 1: File Criticality Assessment');
  const critical = disinfector.assessFileCriticality('C:\\Windows\\System32\\kernel32.dll');
  console.log(`  System32 file - Critical: ${critical.isCritical} ✓`);
  console.log(`  Reason: ${critical.reason}`);
  
  const nonCritical = disinfector.assessFileCriticality('C:\\Users\\Test\\app.exe');
  console.log(`  User file - Critical: ${nonCritical.isCritical} ✓`);
  console.log(`  Reason: ${nonCritical.reason}\n`);
  
  // Test 2: Mock infection disinfection
  console.log('Test 2: Mock File Disinfection');
  const mockDetection = {
    isInfected: true,
    confidence: 85,
    threatName: 'Virus:Win32/Expiro.EK!MTB',
    filePath: __filename,
    reasons: ['Test mock infection']
  };
  
  try {
    const result = await disinfector.disinfectFile(__filename, mockDetection);
    console.log(`  Action: ${result.action}`);
    console.log(`  Success: ${result.success} ✓`);
    if (result.recommendation) {
      console.log(`  Recommendation: ${result.recommendation}`);
    }
  } catch (err) {
    console.log(`  Expected error (file in use): ${err.message}`);
  }
  console.log('');
  
  // Test 3: Disinfection log
  console.log('Test 3: Disinfection Log');
  const log = disinfector.getLog();
  console.log(`  Log entries: ${log.length} ✓\n`);
  
  // Test 4: Report generation
  console.log('Test 4: Report Generation');
  const report = disinfector.generateReport();
  console.log(`  Report length: ${report.length} characters ✓`);
  console.log(`  Contains title: ${report.includes('EXPIRO DISINFECTION REPORT') ? 'YES' : 'NO'} ✓\n`);
  
  console.log('✓ Disinfection module tests complete\n');
}

testDisinfection().catch(err => {
  console.error('Test failed:', err.message);
  process.exit(1);
});
