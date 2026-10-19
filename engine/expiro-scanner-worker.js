/**
 * engine/expiro-scanner-worker.js
 * 
 * High-Performance Background Worker Thread for Win32/Expiro Heuristic Scans.
 * 
 * Offloads CPU-intensive PE parsing, section entropy calculations, and
 * directory traversal from the Electron Main Process. This ensures the
 * main process message pump runs at 60 FPS and Windows OS never marks
 * the application window as "Not Responding".
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { parentPort, workerData } = require('worker_threads');
const { detectExpiroInfection, EXPIRO_SIGNATURES } = require('./expiro-detector');

if (!parentPort) {
  throw new Error('expiro-scanner-worker must be executed as a worker thread.');
}

let isCancelled = false;

parentPort.on('message', (msg) => {
  if (msg && msg.type === 'cancel') {
    isCancelled = true;
  }
});

const skipNames = new Set([
  '$recycle.bin',
  'system volume information',
  'recovery',
  'node_modules',
  '.git',
  'winsxs',
  'servicing',
  'assembly',
  'microsoft.net',
  'installer',
  '$windows.~bt',
  '$windows.~ws',
]);

const peExts = new Set(['.exe', '.dll', '.scr']);

/**
 * Fast asynchronous non-blocking directory crawler
 * Gathers PE executable paths while periodically yielding to the event loop.
 * 
 * @param {string} rootDir 
 * @param {number} maxDepth 
 * @returns {Promise<string[]>}
 */
async function discoverFiles(rootDir, maxDepth) {
  const discovered = [];
  const queue = [{ dir: rootDir, depth: 0 }];
  let dirsProcessed = 0;

  while (queue.length > 0) {
    if (isCancelled) break;
    const { dir, depth } = queue.shift();
    if (depth > maxDepth) continue;

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const lowerName = entry.name.toLowerCase();
        if (skipNames.has(lowerName)) continue;

        const fullPath = path.join(dir, entry.name);
        const lowerPath = fullPath.toLowerCase();

        // Skip quarantine & backup directories
        if (lowerPath.includes('\\gsmshield\\quarantine') ||
            lowerPath.includes('\\gsmshieldav\\quarantine') ||
            lowerPath.includes('\\gsmshield\\backups')) {
          continue;
        }

        if (entry.isDirectory()) {
          try {
            if (fs.lstatSync(fullPath).isSymbolicLink()) continue;
          } catch (_) {}
          queue.push({ dir: fullPath, depth: depth + 1 });
        } else if (entry.isFile()) {
          const ext = path.extname(fullPath).toLowerCase();
          if (peExts.has(ext)) {
            discovered.push(fullPath);
          }
        }
      }
    } catch (_) {}

    dirsProcessed++;
    if (dirsProcessed % 30 === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }

  return discovered;
}

/**
 * Main worker execution routine
 */
async function run() {
  try {
    const { dirPath, maxDepth = 4, threshold, filePaths: directFilePaths } = workerData || {};

    if (threshold && typeof threshold === 'number') {
      EXPIRO_SIGNATURES.detectionThreshold = threshold;
    }

    let filesToScan = [];

    if (Array.isArray(directFilePaths) && directFilePaths.length > 0) {
      filesToScan = directFilePaths;
    } else if (dirPath && fs.existsSync(dirPath)) {
      parentPort.postMessage({
        type: 'status',
        message: 'Discovering files...',
      });
      filesToScan = await discoverFiles(dirPath, maxDepth);
    } else {
      parentPort.postMessage({
        type: 'error',
        error: 'Target directory or files do not exist.',
      });
      return;
    }

    const total = filesToScan.length;
    let scanned = 0;
    let infectedCount = 0;
    const infectedDetections = [];
    let lastProgressTime = 0;

    for (const filePath of filesToScan) {
      if (isCancelled) break;

      try {
        const detection = detectExpiroInfection(filePath);
        scanned++;

        if (detection.isInfected) {
          infectedCount++;
          infectedDetections.push(detection);
        }
      } catch (err) {
        scanned++;
      }

      const now = Date.now();
      if (now - lastProgressTime >= 100 || scanned === total) {
        lastProgressTime = now;
        parentPort.postMessage({
          type: 'progress',
          scanned,
          total,
          infected: infectedCount,
          currentFile: filePath,
        });
      }

      if (scanned % 20 === 0) {
        await new Promise((resolve) => setImmediate(resolve));
      }
    }

    parentPort.postMessage({
      type: 'complete',
      totalFiles: scanned,
      results: infectedDetections,
      summary: {
        total: scanned,
        infected: infectedCount,
        clean: scanned - infectedCount,
      },
      cancelled: isCancelled,
    });
  } catch (err) {
    parentPort.postMessage({
      type: 'error',
      error: err.message,
    });
  }
}

run();
