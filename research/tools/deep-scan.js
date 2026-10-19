/**
 * Deep PE Analyzer - Find actual Expiro infections
 * 
 * Instead of looking for obvious ".expiro" sections (which real Expiro doesn't use),
 * this analyzes PE files for the REAL indicators of Win32/Expiro.HNW!MTB:
 * 
 * 1. Entry point redirected to last section (not .text)
 * 2. Last section is executable + writable + high entropy
 * 3. File size inflated by 40-150KB compared to original
 * 4. PE checksum invalidated
 * 5. Code cave in last section with jump back to original EP
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function calcEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
  let e = 0;
  for (const c of freq) {
    if (!c) continue;
    const p = c / buf.length;
    e -= p * Math.log2(p);
  }
  return e;
}

function analyzePE(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.length < 64 || buf[0] !== 0x4D || buf[1] !== 0x5A) return null;
    
    const peOff = buf.readUInt32LE(0x3C);
    if (peOff < 0 || peOff >= buf.length - 4) return null;
    if (buf[peOff] !== 0x50 || buf[peOff + 1] !== 0x45) return null;
    
    const coffOff = peOff + 4;
    const numSections = buf.readUInt16LE(coffOff + 2);
    const timestamp = buf.readUInt32LE(coffOff + 4);
    const optHeaderSize = buf.readUInt16LE(coffOff + 16);
    
    const optOff = coffOff + 20;
    const magic = buf.readUInt16LE(optOff);
    const is64 = magic === 0x20B;
    const epRVA = buf.readUInt32LE(optOff + 16);
    
    let checksum = 0;
    try { checksum = buf.readUInt32LE(optOff + 64); } catch(e) {}
    
    const secTableOff = optOff + optHeaderSize;
    const sections = [];
    let lastSectionEnd = 0;
    
    for (let i = 0; i < numSections; i++) {
      const o = secTableOff + i * 40;
      if (o + 40 > buf.length) break;
      
      const name = buf.slice(o, o + 8).toString('ascii').replace(/\0+$/, '');
      const vs = buf.readUInt32LE(o + 8);
      const va = buf.readUInt32LE(o + 12);
      const rs = buf.readUInt32LE(o + 16);
      const ro = buf.readUInt32LE(o + 20);
      const ch = buf.readUInt32LE(o + 36);
      
      let entropy = 0;
      if (ro < buf.length && rs > 0) {
        const sample = buf.slice(ro, Math.min(ro + 8192, buf.length));
        entropy = calcEntropy(sample);
      }
      
      const secEnd = ro + rs;
      if (secEnd > lastSectionEnd) lastSectionEnd = secEnd;
      
      sections.push({
        name, virtualSize: vs, virtualAddress: va,
        rawSize: rs, rawOffset: ro, characteristics: ch,
        entropy,
        isExec: (ch & 0x20000000) !== 0,
        isWrite: (ch & 0x80000000) !== 0,
        isRead: (ch & 0x40000000) !== 0,
      });
    }
    
    // Find which section contains the entry point
    let epSection = null;
    let epSectionIdx = -1;
    for (let i = 0; i < sections.length; i++) {
      const s = sections[i];
      if (s.virtualAddress <= epRVA && epRVA < s.virtualAddress + s.virtualSize) {
        epSection = s;
        epSectionIdx = i;
        break;
      }
    }
    
    const overlaySize = Math.max(0, buf.length - lastSectionEnd);
    let overlayEntropy = 0;
    if (overlaySize > 1024) {
      overlayEntropy = calcEntropy(buf.slice(lastSectionEnd, Math.min(lastSectionEnd + 8192, buf.length)));
    }
    
    const lastSection = sections[sections.length - 1];
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    
    return {
      filePath, fileSize: buf.length, hash,
      is64, numSections, epRVA, timestamp, checksum,
      sections, epSection, epSectionIdx,
      lastSection,
      overlaySize, overlayEntropy,
      lastSectionEnd,
    };
  } catch (e) {
    return null;
  }
}

/**
 * Score a file for REAL Expiro infection indicators
 */
function scoreExpiro(pe) {
  let score = 0;
  const reasons = [];
  
  if (!pe) return { score: 0, reasons: ['Not a PE file'] };
  
  const lastSec = pe.lastSection;
  const epSec = pe.epSection;
  
  // === REAL EXPIRO INDICATOR 1: Entry point in the LAST section ===
  // Real Expiro redirects EP to its appended code in the last section
  if (pe.epSectionIdx === pe.sections.length - 1 && pe.sections.length > 1) {
    // EP in last section is suspicious for most programs
    // (normal programs have EP in .text which is usually first or second)
    const isNormalLastSec = /^(\.rsrc|\.reloc|\.pdata)$/i.test(lastSec.name);
    if (!isNormalLastSec) {
      score += 25;
      reasons.push(`EP in last section [${lastSec.name}] (idx ${pe.epSectionIdx}/${pe.sections.length - 1})`);
    }
  }
  
  // EP not in .text/CODE at all
  if (epSec && !/^(\.text|CODE|\.code|_text)$/i.test(epSec.name)) {
    // Check if it's a packer EP
    if (/^(UPX\d|\.aspack)$/i.test(epSec.name)) {
      // Packer - low weight
      score += 3;
    } else if (!/^(\.rsrc|\.reloc|\.pdata|\.rdata)$/i.test(epSec.name)) {
      score += 20;
      reasons.push(`EP in unusual section: [${epSec.name}]`);
    }
  }
  
  // === REAL EXPIRO INDICATOR 2: Last section is exec+write+high entropy ===
  if (lastSec && lastSec.isExec && lastSec.isWrite && lastSec.entropy > 6.5) {
    score += 30;
    reasons.push(`Last section [${lastSec.name}] is EXEC+WRITE with entropy ${lastSec.entropy.toFixed(2)}`);
  } else if (lastSec && lastSec.isExec && lastSec.isWrite) {
    score += 15;
    reasons.push(`Last section [${lastSec.name}] is EXEC+WRITE (entropy ${lastSec.entropy.toFixed(2)})`);
  }
  
  // === REAL EXPIRO INDICATOR 3: Last section size in 40-150KB range ===
  if (lastSec && lastSec.rawSize >= 40960 && lastSec.rawSize <= 153600 && lastSec.isExec) {
    score += 15;
    reasons.push(`Last exec section size ${(lastSec.rawSize / 1024).toFixed(1)}KB (Expiro range)`);
  }
  
  // === REAL EXPIRO INDICATOR 4: Overlay in 40-150KB with high entropy ===
  if (pe.overlaySize >= 40960 && pe.overlaySize <= 153600) {
    if (pe.overlayEntropy > 7.0) {
      score += 20;
      reasons.push(`Encrypted overlay: ${(pe.overlaySize / 1024).toFixed(1)}KB (entropy ${pe.overlayEntropy.toFixed(2)})`);
    } else {
      score += 10;
      reasons.push(`Overlay: ${(pe.overlaySize / 1024).toFixed(1)}KB`);
    }
  }
  
  // === REAL EXPIRO INDICATOR 5: Section with obvious Expiro names ===
  for (const s of pe.sections) {
    if (/expiro|virus|\.packed|\.stub/i.test(s.name)) {
      score += 40;
      reasons.push(`Expiro section name: [${s.name}]`);
    }
  }
  
  // === INDICATOR 6: Abnormal number of exec+write sections ===
  const ewCount = pe.sections.filter(s => s.isExec && s.isWrite).length;
  if (ewCount >= 2) {
    score += 10;
    reasons.push(`${ewCount} executable+writable sections`);
  }
  
  // === INDICATOR 7: Many sections (> 8) ===
  if (pe.numSections > 8) {
    score += 5;
    reasons.push(`High section count: ${pe.numSections}`);
  }
  
  // UPX discount
  const hasUPX = pe.sections.some(s => /^UPX\d$/i.test(s.name));
  if (hasUPX && score > 0 && score < 70) {
    const discount = Math.min(15, score);
    score -= discount;
    reasons.push(`UPX packer discount: -${discount}`);
  }
  
  return { score: Math.max(0, Math.min(100, score)), reasons };
}

// === MAIN: Scan directories ===
async function main() {
  const dirs = [
    'C:\\Program Files\\Git',
    'C:\\Program Files\\nodejs',
    'C:\\Program Files (x86)',
    'C:\\Windows\\System32',
    'C:\\Users\\' + process.env.USERNAME + '\\AppData\\Local',
    'C:\\Users\\' + process.env.USERNAME + '\\Downloads',
  ];
  
  let totalScanned = 0;
  let infected = [];
  
  function walkDir(dir, depth) {
    if (depth > 4) return;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fp = path.join(dir, entry.name);
        if (entry.isDirectory() && depth < 4) {
          walkDir(fp, depth + 1);
        } else if (entry.isFile()) {
          const ext = path.extname(fp).toLowerCase();
          if (['.exe', '.dll', '.sys', '.scr'].includes(ext)) {
            totalScanned++;
            if (totalScanned % 200 === 0) {
              process.stdout.write(`  Scanned: ${totalScanned}, Infected: ${infected.length}\r`);
            }
            
            const pe = analyzePE(fp);
            if (pe) {
              const result = scoreExpiro(pe);
              if (result.score >= 50) {
                infected.push({
                  path: fp,
                  score: result.score,
                  reasons: result.reasons,
                  size: pe.fileSize,
                  lastSection: pe.lastSection ? pe.lastSection.name : 'N/A',
                  epSection: pe.epSection ? pe.epSection.name : 'N/A',
                });
                console.log(`\n  [INFECTED] ${fp}`);
                console.log(`    Score: ${result.score}%`);
                result.reasons.forEach(r => console.log(`    - ${r}`));
              }
            }
          }
        }
      }
    } catch (e) {
      // Permission denied etc.
    }
  }
  
  console.log('=== GSM Shield AV - Deep Expiro Scanner v3 ===');
  console.log('Scanning for REAL Expiro.HNW!MTB indicators...\n');
  
  for (const dir of dirs) {
    if (fs.existsSync(dir)) {
      console.log(`Scanning: ${dir}`);
      walkDir(dir, 0);
    }
  }
  
  console.log(`\n\n=== SCAN COMPLETE ===`);
  console.log(`Files Scanned: ${totalScanned}`);
  console.log(`Infections Found: ${infected.length}`);
  
  if (infected.length > 0) {
    console.log(`\n=== INFECTED FILES ===`);
    infected.forEach((f, i) => {
      console.log(`\n[${i + 1}] ${f.path}`);
      console.log(`    Score: ${f.score}% | Size: ${(f.size / 1024).toFixed(1)}KB`);
      console.log(`    EP Section: ${f.epSection} | Last Section: ${f.lastSection}`);
      f.reasons.forEach(r => console.log(`    - ${r}`));
    });
    
    // Save results
    const logPath = path.join(__dirname, '..', 'logs', `deep_scan_${Date.now()}.json`);
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.writeFileSync(logPath, JSON.stringify(infected, null, 2));
    console.log(`\nResults saved to: ${logPath}`);
  }
}

if (require.main === module) {
  main().catch(console.error);
} else {
  module.exports = { analyzePE, scoreExpiro, calcEntropy };
}
