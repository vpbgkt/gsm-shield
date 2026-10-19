const expiroDetector = require('../../engine/expiro-detector');
const fs = require('fs');
const path = require('path');

async function performanceBenchmark() {
  console.log('===== EXPIRO DETECTOR PERFORMANCE BENCHMARK =====\n');
  
  // Collect 50 Windows system executables
  const system32Path = 'C:\\Windows\\System32';
  const allExes = fs.readdirSync(system32Path)
    .filter(f => f.endsWith('.exe'))
    .slice(0, 50)
    .map(f => path.join(system32Path, f));
  
  console.log(`Collected ${allExes.length} test files\n`);
  
  // Warm-up scan
  console.log('Warming up...');
  await expiroDetector.scanFile(allExes[0]);
  console.log('✓ Warm-up complete\n');
  
  // Benchmark: Single file scans
  console.log('Test 1: Single File Scan Performance');
  const singleScanTimes = [];
  for (let i = 0; i < 10; i++) {
    const start = Date.now();
    await expiroDetector.scanFile(allExes[i]);
    const elapsed = Date.now() - start;
    singleScanTimes.push(elapsed);
  }
  
  const avgSingle = singleScanTimes.reduce((a, b) => a + b, 0) / singleScanTimes.length;
  const minSingle = Math.min(...singleScanTimes);
  const maxSingle = Math.max(...singleScanTimes);
  
  console.log(`  Average: ${avgSingle.toFixed(2)}ms`);
  console.log(`  Min: ${minSingle}ms`);
  console.log(`  Max: ${maxSingle}ms`);
  console.log(`  Throughput: ${(1000 / avgSingle).toFixed(2)} files/sec\n`);
  
  // Benchmark: Batch scan
  console.log('Test 2: Batch Scan Performance');
  const batchStart = Date.now();
  let progressCount = 0;
  
  await expiroDetector.scanFiles(allExes, (progress) => {
    progressCount++;
  });
  
  const batchElapsed = Date.now() - batchStart;
  const avgBatch = batchElapsed / allExes.length;
  
  console.log(`  Total time: ${(batchElapsed / 1000).toFixed(2)}s`);
  console.log(`  Files scanned: ${allExes.length}`);
  console.log(`  Average per file: ${avgBatch.toFixed(2)}ms`);
  console.log(`  Throughput: ${(allExes.length / (batchElapsed / 1000)).toFixed(2)} files/sec`);
  console.log(`  Progress callbacks: ${progressCount}\n`);
  
  // Memory usage
  const memUsage = process.memoryUsage();
  console.log('Test 3: Memory Usage');
  console.log(`  RSS: ${(memUsage.rss / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  Heap Used: ${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  Heap Total: ${(memUsage.heapTotal / 1024 / 1024).toFixed(2)} MB\n`);
  
  // Performance verdict
  console.log('===== PERFORMANCE VERDICT =====');
  if (avgSingle < 100) {
    console.log('✓ EXCELLENT: Average scan time < 100ms');
  } else if (avgSingle < 250) {
    console.log('✓ GOOD: Average scan time < 250ms');
  } else {
    console.log('⚠ NEEDS OPTIMIZATION: Average scan time > 250ms');
  }
  
  if (memUsage.heapUsed / 1024 / 1024 < 100) {
    console.log('✓ EXCELLENT: Memory usage < 100 MB');
  } else {
    console.log('⚠ HIGH MEMORY: Consider optimization');
  }
  
  console.log('\n✓ Performance benchmark complete');
}

performanceBenchmark().catch(err => {
  console.error('Benchmark failed:', err.message);
  process.exit(1);
});
