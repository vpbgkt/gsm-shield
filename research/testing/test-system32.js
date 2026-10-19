const expiroDetector = require('../../engine/expiro-detector');
const fs = require('fs');
const path = require('path');

async function testSystemFiles() {
  console.log('Testing Expiro Detector on Clean System Files...\n');
  
  // Test legitimate Windows system files
  const testFiles = [
    'C:\\Windows\\System32\\notepad.exe',
    'C:\\Windows\\System32\\calc.exe',
    'C:\\Windows\\System32\\cmd.exe',
    'C:\\Windows\\System32\\taskmgr.exe',
    'C:\\Windows\\System32\\mspaint.exe',
  ];
  
  console.log('Scanning 5 known-clean Windows executables...\n');
  
  const results = [];
  for (const filePath of testFiles) {
    if (!fs.existsSync(filePath)) {
      console.log(`⚠ Skipping: ${path.basename(filePath)} (not found)`);
      continue;
    }
    
    const result = await expiroDetector.scanFile(filePath);
    results.push(result);
    
    console.log(`File: ${path.basename(filePath)}`);
    console.log(`  Status: ${result.isInfected ? '⚠ INFECTED' : '✓ CLEAN'}`);
    console.log(`  Confidence: ${result.confidence}%`);
    if (result.reasons && result.reasons.length > 0) {
      console.log(`  Reasons:`, result.reasons);
    }
    console.log('');
  }
  
  // Summary
  const infected = results.filter(r => r.isInfected).length;
  const clean = results.filter(r => !r.isInfected).length;
  
  console.log('===== FALSE POSITIVE TEST RESULTS =====');
  console.log(`Total Scanned: ${results.length}`);
  console.log(`Clean: ${clean}`);
  console.log(`False Positives: ${infected}`);
  console.log(`False Positive Rate: ${((infected / results.length) * 100).toFixed(2)}%`);
  console.log('');
  
  if (infected === 0) {
    console.log('✓ PASSED: No false positives detected on clean system files');
  } else {
    console.log('⚠ WARNING: False positives detected - heuristics may need tuning');
  }
}

testSystemFiles().catch(err => {
  console.error('Test failed:', err.message);
  process.exit(1);
});
