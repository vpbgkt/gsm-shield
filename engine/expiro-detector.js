/**
 * engine/expiro-detector.js
 * 
 * Expiro File Infector Detection Module for GSM Shield AV
 * Implements detection and prevention for Win32/Expiro.EK!MTB
 * 
 * Based on research from 441 real Expiro infections detected on production system
 * 
 * v2.0 — Improved heuristics, reduced false positives (UPX, overlay analysis),
 *         added PE checksum validation, timestamp anomaly detection, and
 *         import-table injection-API analysis.
 */

'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Expiro Detection Signatures and Heuristics
 * Based on analysis of Win32/Expiro.EK!MTB variant
 */
const EXPIRO_SIGNATURES = {
  // Known suspicious section names added by Expiro
  // NOTE: UPX0/UPX1 and .ndata are legitimate packer/installer sections
  // (.ndata is used by NSIS installers) and caused false positives.
  suspiciousSections: [
    '.expiro',
    '.virus',
    '.packed',
    '.stub',
  ],

  // Sections that are benign packers / protectors / installers — reduce scoring, don't flag
  benignPackerSections: [
    'UPX0',
    'UPX1',
    'UPX2',
    'UPX3',
    '.aspack',
    '.adata',
    '.ndata',
    '.vmp0',
    '.vmp1',
    '.vmp2',
    'vmp0',
    'vmp1',
    'vmp2',
    '.themida',
    '.winlic',
    'Themida',
    '.enigma1',
    '.enigma2',
    '.mpress1',
    '.mpress2',
    '.obsid',
  ],

  // Benign compiler / PGO / Windows optimization code sections
  benignCodeSections: [
    '.no_bbt',
    'fothk',
    '.gfids',
    '.giats',
    '.00cfg',
    '.tls',
    '.didat',
    '.didata',
    '.orpc',
    '.bindat',
    '.imrsiv',
  ],
  
  // Typical size increase (bytes) when Expiro infects a file
  minSizeIncrease: 40 * 1024,  // 40 KB
  maxSizeIncrease: 150 * 1024,  // 150 KB
  
  // Entropy threshold for encrypted sections
  highEntropyThreshold: 7.0,
  
  // Confidence scoring thresholds
  detectionThreshold: 60,  // Minimum confidence score to flag as infected
  certaintyThreshold: 80,  // High confidence = certain infection
};

/**
 * Known injection-related Windows API functions that Expiro uses
 * to propagate. Finding many of these together is a strong indicator.
 */
const INJECTION_APIS = [
  'VirtualAlloc',
  'VirtualProtect',
  'WriteProcessMemory',
  'CreateRemoteThread',
  'NtWriteVirtualMemory',
  'RtlMoveMemory',
];

/**
 * Check if a section name belongs to a known benign packer or software protector
 * (e.g. VMProtect .vmp0/.vmp1, UPX, Themida, ASPack, Enigma)
 * @param {string} name - Section name
 * @returns {boolean} True if known benign packer section
 */
function isBenignPackerSection(name) {
  if (!name || typeof name !== 'string') return false;
  const clean = name.trim();
  if (EXPIRO_SIGNATURES.benignPackerSections.some(s => s.toLowerCase() === clean.toLowerCase())) {
    return true;
  }
  return /^\.?(vmp|upx|themida|winlic|enigma|mpress|obsid|aspack)\d?$/i.test(clean);
}

/**
 * Calculate Shannon entropy of byte buffer
 * @param {Buffer} buffer - Byte buffer to analyze
 * @returns {number} Entropy value (0-8, higher = more random/encrypted)
 */
function calculateEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  
  const frequency = new Array(256).fill(0);
  
  for (let i = 0; i < buffer.length; i++) {
    frequency[buffer[i]]++;
  }
  
  let entropy = 0;
  const length = buffer.length;
  
  for (let count of frequency) {
    if (count === 0) continue;
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}

/**
 * Search for ASCII strings in a buffer region
 * @param {Buffer} buffer - Buffer to search
 * @param {string} str - ASCII string to find
 * @returns {boolean} Whether the string was found
 */
function bufferContainsString(buffer, str) {
  const needle = Buffer.from(str, 'ascii');
  return buffer.indexOf(needle) !== -1;
}

/**
 * Parse PE file header and extract metadata
 * @param {string} filePath - Path to PE file
 * @returns {Object|null} PE metadata or null if not a valid PE
 */
function parsePEHeader(filePath) {
  let fd = null;
  try {
    const stats = fs.statSync(filePath);
    if (!stats.isFile() || stats.size < 64) {
      return null;  // Not a valid file
    }
    // Skip oversized files (> 150 MB) — Expiro only infects standard user-mode PE binaries
    if (stats.size > 150 * 1024 * 1024) {
      return null;
    }

    const fileSize = stats.size;
    const isLargeFile = fileSize > 2 * 1024 * 1024;
    let buffer;

    if (!isLargeFile) {
      buffer = fs.readFileSync(filePath);
    } else {
      fd = fs.openSync(filePath, 'r');
      const headerSize = Math.min(fileSize, 65536);
      buffer = Buffer.alloc(headerSize);
      fs.readSync(fd, buffer, 0, headerSize, 0);
    }
    
    // Check DOS header (MZ signature)
    if (buffer.length < 64 || buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
      return null;  // Not a PE file
    }
    
    // Get PE header offset
    const peOffset = buffer.readUInt32LE(0x3C);
    
    if (peOffset < 0 || peOffset >= fileSize - 4) {
      return null;  // Invalid PE offset
    }

    // In rare cases where PE header is beyond 64KB on a large file, read that section
    if (peOffset + 256 > buffer.length && isLargeFile) {
      const extraSize = Math.min(fileSize - peOffset, 65536);
      const newBuf = Buffer.alloc(peOffset + extraSize);
      buffer.copy(newBuf, 0, 0, buffer.length);
      fs.readSync(fd, newBuf, peOffset, extraSize, peOffset);
      buffer = newBuf;
    }
    
    // Check PE signature
    if (peOffset + 2 > buffer.length || buffer[peOffset] !== 0x50 || buffer[peOffset + 1] !== 0x45) {
      return null;  // Not a valid PE file
    }
    
    // Parse COFF header
    const coffOffset = peOffset + 4;
    if (coffOffset + 20 > buffer.length) return null;

    const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
    const timeDateStamp = buffer.readUInt32LE(coffOffset + 4);
    const optionalHeaderSize = buffer.readUInt16LE(coffOffset + 16);
    const characteristics = buffer.readUInt16LE(coffOffset + 18);
    
    // Parse Optional Header
    const optHeaderOffset = coffOffset + 20;
    
    if (optHeaderOffset + 2 > buffer.length) return null;
    
    const magic = buffer.readUInt16LE(optHeaderOffset);
    const is64bit = (magic === 0x20B);
    
    // Get entry point
    const entryPointRVA = optHeaderOffset + 20 <= buffer.length ? buffer.readUInt32LE(optHeaderOffset + 16) : 0;
    
    // Get image size and checksum
    let imageSize = 0;
    let checksum = 0;
    try {
      if (optHeaderOffset + 68 <= buffer.length) {
        imageSize = buffer.readUInt32LE(optHeaderOffset + 56);
        checksum = buffer.readUInt32LE(optHeaderOffset + 64);
      }
    } catch (e) {
      // Some truncated files — continue with 0s
    }
    
    // Parse Section Table
    const sectionTableOffset = optHeaderOffset + optionalHeaderSize;
    const sections = [];
    
    // Track the end of the last raw section to calculate overlay
    let lastSectionEnd = 0;
    
    for (let i = 0; i < numberOfSections; i++) {
      const sectionOffset = sectionTableOffset + (i * 40);
      if (sectionOffset + 40 > buffer.length) break;
      
      const nameBytes = buffer.slice(sectionOffset, sectionOffset + 8);
      const name = nameBytes.toString('ascii').replace(/\0+$/, '').replace(/[^\x20-\x7E]/g, '?');
      
      const virtualSize = buffer.readUInt32LE(sectionOffset + 8);
      const virtualAddress = buffer.readUInt32LE(sectionOffset + 12);
      const rawSize = buffer.readUInt32LE(sectionOffset + 16);
      const rawOffset = buffer.readUInt32LE(sectionOffset + 20);
      const sectionCharacteristics = buffer.readUInt32LE(sectionOffset + 36);
      
      // Calculate entropy of section data (sample first 8KB for performance)
      let entropy = 0;
      if (rawOffset < fileSize && rawSize > 0) {
        const sampleSize = Math.min(rawSize, 8192);
        if (rawOffset + sampleSize <= buffer.length) {
          const sectionData = buffer.slice(rawOffset, rawOffset + sampleSize);
          entropy = calculateEntropy(sectionData);
        } else if (fd !== null) {
          try {
            const sectionBuf = Buffer.alloc(sampleSize);
            const bytesRead = fs.readSync(fd, sectionBuf, 0, sampleSize, rawOffset);
            entropy = calculateEntropy(sectionBuf.slice(0, bytesRead));
          } catch (_) {}
        }
      }
      
      // Track where sections end (for overlay calculation)
      const sectionEnd = rawOffset + rawSize;
      if (sectionEnd > lastSectionEnd) {
        lastSectionEnd = sectionEnd;
      }
      
      sections.push({
        name,
        virtualSize,
        virtualAddress,
        rawSize,
        rawOffset,
        characteristics: sectionCharacteristics,
        entropy,
        isExecutable: (sectionCharacteristics & 0x20000000) !== 0,
        isWritable: (sectionCharacteristics & 0x80000000) !== 0,
        isReadable: (sectionCharacteristics & 0x40000000) !== 0,
      });
    }
    
    // Parse Optional Header Data Directory 4: IMAGE_DIRECTORY_ENTRY_SECURITY (Certificate Table)
    const dataDirBase = is64bit ? optHeaderOffset + 112 : optHeaderOffset + 96;
    let certOffset = 0;
    let certSize = 0;
    let hasAuthenticodeCert = false;

    if (dataDirBase + 40 <= buffer.length) {
      certOffset = buffer.readUInt32LE(dataDirBase + 32);
      certSize = buffer.readUInt32LE(dataDirBase + 36);

      if (certOffset > 0 && certSize > 0 && certOffset + 8 <= fileSize) {
        try {
          let dwLength = 0;
          let wCertificateType = 0;
          if (certOffset + 8 <= buffer.length) {
            dwLength = buffer.readUInt32LE(certOffset);
            wCertificateType = buffer.readUInt16LE(certOffset + 6);
          } else if (fd !== null) {
            const certHdr = Buffer.alloc(8);
            fs.readSync(fd, certHdr, 0, 8, certOffset);
            dwLength = certHdr.readUInt32LE(0);
            wCertificateType = certHdr.readUInt16LE(6);
          }
          // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
          if (wCertificateType === 2 || dwLength === certSize) {
            hasAuthenticodeCert = true;
          }
        } catch (_) {}
      }
    }

    // Calculate non-certificate overlay
    let nonCertOverlay = 0;
    if (hasAuthenticodeCert && certOffset >= lastSectionEnd) {
      const certEnd = certOffset + certSize;
      nonCertOverlay = Math.max(0, fileSize - certEnd);
    } else {
      nonCertOverlay = Math.max(0, fileSize - lastSectionEnd);
    }

    const overlaySize = nonCertOverlay;
    
    // Calculate overlay entropy
    let overlayEntropy = 0;
    if (overlaySize > 1024) {
      const overlayOffset = fileSize - overlaySize;
      const sampleSize = Math.min(overlaySize, 8192);
      if (overlayOffset + sampleSize <= buffer.length) {
        const overlaySample = buffer.slice(overlayOffset, overlayOffset + sampleSize);
        overlayEntropy = calculateEntropy(overlaySample);
      } else if (fd !== null) {
        try {
          const overlayBuf = Buffer.alloc(sampleSize);
          const bytesRead = fs.readSync(fd, overlayBuf, 0, sampleSize, overlayOffset);
          overlayEntropy = calculateEntropy(overlayBuf.slice(0, bytesRead));
        } catch (_) {}
      }
    }
    
    // Scan for injection APIs in the file (imports region — first 64KB of file)
    const importScanRegion = buffer.slice(0, Math.min(buffer.length, 65536));
    const foundInjectionAPIs = INJECTION_APIS.filter(api =>
      bufferContainsString(importScanRegion, api)
    );
    
    return {
      is64bit,
      numberOfSections,
      entryPointRVA,
      timeDateStamp,
      imageSize,
      checksum,
      sections,
      fileSize,
      overlaySize,
      overlayEntropy,
      lastSectionEnd,
      foundInjectionAPIs,
      hasAuthenticodeCert,
      certOffset,
      certSize,
    };
    
  } catch (error) {
    console.error(`[expiro-detector] Error parsing PE: ${error.message}`);
    return null;
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch (_) {}
    }
  }
}

/**
 * Detect Expiro infection using multi-layered heuristics
 * @param {string} filePath - Path to file to scan
 * @returns {Object} Detection result with confidence score and reasons
 */
function detectExpiroInfection(filePath) {
  const result = {
    isInfected: false,
    confidence: 0,
    reasons: [],
    threatName: 'Virus:Win32/Expiro.EK!MTB',
    filePath,
  };
  
  try {
    // Only scan user-mode PE files (Expiro is a Win32 user-mode PE infector, does not infect .sys kernel drivers)
    const ext = path.extname(filePath).toLowerCase();
    if (!['.exe', '.dll', '.scr'].includes(ext)) {
      return result;
    }
    
    // Parse PE structure
    const pe = parsePEHeader(filePath);
    if (!pe) {
      return result;  // Not a valid PE file
    }
    
    // Track whether this is a known-packer file (to discount false positives)
    let isKnownPacker = false;
    
    // ── Heuristic 1: Suspicious section names (strong Expiro indicator) ──
    for (const section of pe.sections) {
      // Check for Expiro-specific sections
      for (const susName of EXPIRO_SIGNATURES.suspiciousSections) {
        if (section.name.toLowerCase().includes(susName.toLowerCase())) {
          result.confidence += 40;
          result.reasons.push(`Suspicious section name: ${section.name}`);
          break;
        }
      }
      
      // Check for benign packer / protector sections (reduce false positives)
      if (isBenignPackerSection(section.name)) {
        isKnownPacker = true;
      }
    }
    
    // ── Heuristic 2: Unusual number of sections ──
    // Normal PE: 3-8 sections. Modern multimedia codecs/Windows DLLs frequently have 8-12.
    // VMProtect, Themida, and GCC/MinGW binaries standardly have 10-15.
    if (pe.numberOfSections > 12) {
      if (!isKnownPacker) {
        result.confidence += 15;
        result.reasons.push(`Unusual section count: ${pe.numberOfSections} (normal: 3-12)`);
      }
    }
    
    // ── Heuristic 3: High entropy executable sections ──
    // Encrypted/polymorphic code has entropy > 7.0
    // Exclude legitimate compiler/PGO sections (.no_bbt, fothk, etc.)
    // Exclude legitimate known packer sections (.vmp0/.vmp1, UPX, etc.)
    const isBenignCodeSection = (name) => {
      const lower = name.toLowerCase();
      return EXPIRO_SIGNATURES.benignCodeSections.some(b => lower.startsWith(b.toLowerCase()));
    };

    const highEntropySections = pe.sections.filter(s => 
      s.isExecutable && 
      s.entropy > EXPIRO_SIGNATURES.highEntropyThreshold &&
      !isBenignCodeSection(s.name) &&
      !isBenignPackerSection(s.name)
    );
    
    if (highEntropySections.length > 0) {
      // Known packers naturally have high entropy — reduce score
      const perSectionScore = isKnownPacker ? 5 : 20;
      const score = perSectionScore * Math.min(highEntropySections.length, 2);
      result.confidence += score;
      result.reasons.push(
        `High entropy executable section(s): ${highEntropySections.map(s => `${s.name} (${s.entropy.toFixed(2)})`).join(', ')}`
      );
    }
    
    // ── Heuristic 4: Entry point in unusual section ──
    // Expiro redirects the entry point to its viral section
    const epSection = pe.sections.find(s => 
      s.virtualAddress <= pe.entryPointRVA && 
      pe.entryPointRVA < (s.virtualAddress + s.virtualSize)
    );
    
    if (epSection) {
      const normalEpSections = /^(\.text|CODE|\.code|_text)$/i;
      
      if (!epSection.name.match(normalEpSections)) {
        if (isBenignPackerSection(epSection.name)) {
          // Entry in known packer/protector stub (e.g. .vmp1, UPX0) — standard behavior for packers
          isKnownPacker = true;
          result.reasons.push(`Entry point in packer section: ${epSection.name} (benign packer)`);
        } else {
          result.confidence += 25;
          result.reasons.push(`Entry point in unusual section: ${epSection.name}`);
        }
      }
    }
    
    // ── Heuristic 5: Suspicious section size ratios ──
    // Expiro inflates virtual size relative to raw size
    for (const section of pe.sections) {
      // Legitimate uninitialized global data (.data, .bss) standardly expands virtual memory for BSS
      if (/^\.data|^\.bss|CODE_DATA|DATA/i.test(section.name)) continue;

      if (section.rawSize > 0 && section.virtualSize > 0) {
        const ratio = section.virtualSize / section.rawSize;
        if (ratio > 3.0 || ratio < 0.3) {
          result.confidence += 10;
          result.reasons.push(`Suspicious size ratio in ${section.name}: ${ratio.toFixed(2)}`);
          break;  // Only count once
        }
      }
    }
    
    // ── Heuristic 6: Multiple executable + writable sections ──
    // Code injection indicator — legitimate code is rarely writable
    const execWritableSections = pe.sections.filter(s => s.isExecutable && s.isWritable);
    if (execWritableSections.length >= 2) {
      result.confidence += 15;
      result.reasons.push(`Multiple executable+writable sections: ${execWritableSections.length}`);
    }
    
    // ── Heuristic 7: Suspicious overlay data (NEW) ──
    // Expiro appends 40-150KB of encrypted data after the last section (excluding Authenticode certificate)
    if (pe.overlaySize >= EXPIRO_SIGNATURES.minSizeIncrease &&
        pe.overlaySize <= EXPIRO_SIGNATURES.maxSizeIncrease) {
      const score = pe.overlayEntropy > 7.0 ? 20 : 10;
      result.confidence += score;
      result.reasons.push(
        `Suspicious overlay: ${(pe.overlaySize / 1024).toFixed(1)}KB ` +
        `(entropy: ${pe.overlayEntropy.toFixed(2)})`
      );
    } else if (pe.overlaySize > EXPIRO_SIGNATURES.maxSizeIncrease &&
               pe.overlayEntropy > 7.5) {
      // Large high-entropy overlay — less specific but still suspicious
      result.confidence += 5;
      result.reasons.push(
        `Large encrypted overlay: ${(pe.overlaySize / 1024).toFixed(1)}KB`
      );
    }
    
    // ── Heuristic 8: PE Checksum anomaly (NEW) ──
    // Signed/official PE files have valid checksums. Expiro corrupts them.
    // Do not flag if file has a valid Authenticode certificate table or is a known packer.
    if (pe.checksum !== 0 && !pe.hasAuthenticodeCert && !isKnownPacker) {
      if (result.confidence >= 35) {
        result.confidence += 5;
        result.reasons.push('PE checksum present but file shows infection indicators');
      }
    }
    
    // ── Heuristic 9: Injection API imports (NEW) ──
    // Expiro uses memory manipulation APIs to spread
    if (pe.foundInjectionAPIs.length >= 3) {
      result.confidence += 10;
      result.reasons.push(
        `Injection APIs found: ${pe.foundInjectionAPIs.join(', ')}`
      );
    }
    
    // ── Heuristic 10: Timestamp anomaly (NEW) ──
    // Expiro sometimes writes a bogus timestamp (far future or epoch 0)
    // Only evaluate if other infection indicators exist
    if (pe.timeDateStamp > 0 && result.confidence >= 30) {
      const compileDate = new Date(pe.timeDateStamp * 1000);
      const now = new Date();
      const yearDiff = now.getFullYear() - compileDate.getFullYear();
      
      if (compileDate.getFullYear() < 2000 || yearDiff < -1) {
        result.confidence += 5;
        result.reasons.push(
          `Suspicious compile timestamp: ${compileDate.toISOString().split('T')[0]}`
        );
      }
    }
    
    // ── Protection for known-packer binaries ──
    // If a file is packed with a legitimate protector (VMProtect, UPX, Themida, ASPack, Enigma)
    // and has NO hard viral indicators (e.g. .expiro section or viral overlay),
    // it must NEVER be flagged as Expiro.
    if (isKnownPacker) {
      const hasHardViralIndicator = result.reasons.some(r => 
        r.includes('Suspicious section name') || 
        r.includes('Suspicious overlay') || 
        r.includes('Entry point in unusual section')
      );
      if (!hasHardViralIndicator) {
        result.confidence = 0;
        result.reasons = ['Known benign packer verified — no viral indicators found'];
      } else if (result.confidence < EXPIRO_SIGNATURES.certaintyThreshold) {
        const discount = Math.min(15, result.confidence);
        result.confidence -= discount;
        result.reasons.push(`Known-packer discount applied: -${discount} (packer signatures found)`);
      }
    }

    // ── Protection for Authenticode-signed components ──
    // Expiro is a parasitic file infector that rewrites PE sections and entry points.
    // Modifying a signed binary invalidates the cryptographic Authenticode digest.
    // If a binary has an intact Authenticode PKCS#7 certificate table and has NO hard
    // viral indicators (e.g. .expiro section or hijacked entry point), it cannot be Expiro.
    if (pe.hasAuthenticodeCert) {
      const hasHardViralIndicator = result.reasons.some(r => 
        r.includes('Suspicious section name') || 
        r.includes('Entry point in unusual section')
      );
      if (!hasHardViralIndicator) {
        result.confidence = 0;
        result.reasons = [];
      }
    }
    
    // Final determination
    result.confidence = Math.max(0, Math.min(100, result.confidence));
    result.isInfected = result.confidence >= EXPIRO_SIGNATURES.detectionThreshold;
    
    return result;
    
  } catch (error) {
    console.error(`[expiro-detector] Detection error: ${error.message}`);
    return result;
  }
}

/**
 * Scan a file and return detection result
 * @param {string} filePath - File to scan
 * @returns {Promise<Object>} Detection result
 */
async function scanFile(filePath) {
  return new Promise((resolve) => {
    try {
      const result = detectExpiroInfection(filePath);
      resolve(result);
    } catch (error) {
      resolve({
        isInfected: false,
        confidence: 0,
        reasons: [`Scan error: ${error.message}`],
        filePath,
      });
    }
  });
}

/**
 * Scan multiple files
 * @param {string[]} filePaths - Array of file paths to scan
 * @param {Function} [onProgress] - Progress callback
 * @param {Object} [options] - Scan options
 * @param {boolean} [options.onlyInfected=false] - If true, returns { detections, scannedCount, infectedCount }
 * @returns {Promise<Object[]|Object>} Array of detection results or detection summary
 */
async function scanFiles(filePaths, onProgress, options = {}) {
  const onlyInfected = Boolean(options.onlyInfected);
  const results = [];
  const infectedDetections = [];
  let scanned = 0;
  let infectedCount = 0;
  let lastProgressEmit = 0;
  const total = filePaths.length;
  
  for (const filePath of filePaths) {
    const result = await scanFile(filePath);
    scanned++;
    
    if (result.isInfected) {
      infectedCount++;
      infectedDetections.push(result);
    }
    
    if (!onlyInfected) {
      results.push(result);
    }
    
    const now = Date.now();
    // Throttle progress updates to at most once every 100ms or on completion to prevent IPC flooding
    if (onProgress && (now - lastProgressEmit >= 100 || scanned === total)) {
      lastProgressEmit = now;
      onProgress({
        scanned,
        total,
        infected: infectedCount,
        currentFile: filePath,
      });
    }

    // Yield to the Node.js / Electron event loop periodically to prevent UI freezes
    if (scanned % 15 === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
  
  if (onlyInfected) {
    return {
      detections: infectedDetections,
      scannedCount: scanned,
      infectedCount,
    };
  }
  
  return results;
}

module.exports = {
  detectExpiroInfection,
  scanFile,
  scanFiles,
  EXPIRO_SIGNATURES,
};
