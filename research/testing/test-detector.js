const expiroDetector = require('../../engine/expiro-detector');
const path = require('path');

async function testDetection() {
  console.log('Testing Expiro Detector...\n');
  
  // Test 1: Scan non-PE file (should be safe)
  console.log('Test 1: Non-PE file (this test file)');
  const result1 = await expiroDetector.scanFile(__filename);
  console.log(`  Result: ${result1.isInfected ? 'INFECTED' : 'CLEAN'}`);
  console.log(`  Confidence: ${result1.confidence}%\n`);
  
  // Test 2: Scan EICAR files
  console.log('Test 2: EICAR test files');
  const eicarPath = path.join('research', 'testing', 'eicar', 'eicar.com');
  const result2 = await expiroDetector.scanFile(eicarPath);
  console.log(`  Result: ${result2.isInfected ? 'INFECTED' : 'CLEAN'}`);
  console.log(`  Confidence: ${result2.confidence}%`);
  if (result2.reasons && result2.reasons.length > 0) {
    console.log(`  Reasons:`, result2.reasons);
  }
  console.log('');
  
  // Test 3: Batch scanning
  console.log('Test 3: Batch file scanning');
  const files = [
    __filename,
    eicarPath,
  ];
  
  const results = await expiroDetector.scanFiles(files, (progress) => {
    console.log(`  Progress: ${progress.scanned}/${progress.total} (${progress.infected} infected)`);
  });
  
  console.log(`\nScan Complete:`);
  console.log(`  Total: ${results.length}`);
  console.log(`  Infected: ${results.filter(r => r.isInfected).length}`);
  console.log(`  Clean: ${results.filter(r => !r.isInfected).length}`);
  
  console.log('\n✓ Detection module tests complete\n');
}

testDetection().catch(err => {
  console.error('Test failed:', err.message);
  process.exit(1);
});
