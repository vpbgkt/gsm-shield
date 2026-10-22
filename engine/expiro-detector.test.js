/**
 * Tests for Expiro detector module v2
 * 
 * Tests cover:
 * - Module exports
 * - Non-PE file handling
 * - Non-existent file handling
 * - Signature constants
 * - UPX false-positive suppression
 * - Mock PE detection (synthetic buffers)
 */

const { detectExpiroInfection, scanFile, scanFiles, EXPIRO_SIGNATURES } = require('./expiro-detector');
const fs = require('fs');
const path = require('path');
const os = require('os');

describe('Expiro Detector v2', () => {
  
  describe('Module Exports', () => {
    test('should export detection function', () => {
      expect(typeof detectExpiroInfection).toBe('function');
    });

    test('should export async scanFile function', () => {
      expect(typeof scanFile).toBe('function');
    });

    test('should export async scanFiles function', () => {
      expect(typeof scanFiles).toBe('function');
    });
  });

  describe('Signature Constants', () => {
    test('should export signature constants', () => {
      expect(EXPIRO_SIGNATURES).toBeDefined();
      expect(EXPIRO_SIGNATURES.suspiciousSections).toBeInstanceOf(Array);
      expect(EXPIRO_SIGNATURES.detectionThreshold).toBe(60);
      expect(EXPIRO_SIGNATURES.certaintyThreshold).toBe(80);
    });

    test('should contain Expiro-specific section names', () => {
      expect(EXPIRO_SIGNATURES.suspiciousSections).toContain('.expiro');
      expect(EXPIRO_SIGNATURES.suspiciousSections).toContain('.virus');
      expect(EXPIRO_SIGNATURES.suspiciousSections).toContain('.packed');
    });

    test('should NOT contain UPX sections in suspicious list (false-positive fix)', () => {
      expect(EXPIRO_SIGNATURES.suspiciousSections).not.toContain('UPX0');
      expect(EXPIRO_SIGNATURES.suspiciousSections).not.toContain('UPX1');
    });

    test('should list UPX as benign packer', () => {
      expect(EXPIRO_SIGNATURES.benignPackerSections).toContain('UPX0');
      expect(EXPIRO_SIGNATURES.benignPackerSections).toContain('UPX1');
    });

    test('should have overlay size thresholds', () => {
      expect(EXPIRO_SIGNATURES.minSizeIncrease).toBe(40 * 1024);
      expect(EXPIRO_SIGNATURES.maxSizeIncrease).toBe(150 * 1024);
    });
  });

  describe('Non-PE File Handling', () => {
    test('should return negative result for non-PE files', () => {
      const result = detectExpiroInfection(__filename);
      expect(result.isInfected).toBe(false);
      expect(result.confidence).toBe(0);
    });

    test('should return negative result for .txt files', () => {
      const result = detectExpiroInfection('C:\\test\\readme.txt');
      expect(result.isInfected).toBe(false);
      expect(result.confidence).toBe(0);
    });

    test('should handle non-existent files gracefully', () => {
      const result = detectExpiroInfection('/nonexistent/file.exe');
      expect(result.isInfected).toBe(false);
    });

    test('async scanFile should handle non-PE gracefully', async () => {
      const result = await scanFile(__filename);
      expect(result.isInfected).toBe(false);
      expect(result.confidence).toBe(0);
    });
  });

  describe('Batch Scanning', () => {
    test('should scan multiple files with progress', async () => {
      const progressCalls = [];
      const results = await scanFiles(
        [__filename, __filename],
        (progress) => progressCalls.push(progress)
      );

      expect(results).toHaveLength(2);
      expect(results[0].isInfected).toBe(false);
      expect(progressCalls.length).toBeGreaterThan(0);
      expect(progressCalls[progressCalls.length - 1].scanned).toBe(2);
    });
  });

  describe('Mock PE Analysis', () => {
    let tempDir;

    beforeAll(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'expiro-test-'));
    });

    afterAll(() => {
      // Clean up temp files
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch (e) {
        // Ignore cleanup errors
      }
    });

    /**
     * Helper: Build a minimal valid PE file buffer with customizable sections
     */
    function buildMinimalPE(options = {}) {
      const {
        sections = [{ name: '.text', characteristics: 0x60000020, rawSize: 512, virtualSize: 512, entropy: 'normal' }],
        entryPointSection = 0,  // index into sections array
      } = options;

      // DOS Header (64 bytes) + PE Signature (4) + COFF Header (20) + Optional Header (96 min for PE32)
      const dosHeaderSize = 64;
      const peSignatureSize = 4;
      const coffHeaderSize = 20;
      const optHeaderSize = 96;  // Minimum for PE32
      const sectionHeaderSize = 40;
      const headersTotalSize = dosHeaderSize + peSignatureSize + coffHeaderSize + optHeaderSize + (sections.length * sectionHeaderSize);

      // Align section data to 512 bytes
      const sectionAlignment = 512;
      let dataOffset = Math.ceil(headersTotalSize / sectionAlignment) * sectionAlignment;

      // Calculate total file size
      let totalSize = dataOffset;
      const sectionMeta = sections.map(s => {
        const rawSize = s.rawSize || 512;
        const meta = { rawOffset: dataOffset, rawSize };
        dataOffset += rawSize;
        totalSize += rawSize;
        return meta;
      });

      if (options.overlayData) {
        totalSize += options.overlayData.length;
      }

      const buf = Buffer.alloc(totalSize, 0);

      // DOS Header: MZ magic
      buf[0] = 0x4D; buf[1] = 0x5A;
      // e_lfanew: PE header offset at position 0x3C
      buf.writeUInt32LE(dosHeaderSize, 0x3C);

      // PE Signature
      const peOff = dosHeaderSize;
      buf[peOff] = 0x50; buf[peOff + 1] = 0x45; buf[peOff + 2] = 0; buf[peOff + 3] = 0;

      // COFF Header
      const coffOff = peOff + 4;
      buf.writeUInt16LE(0x14C, coffOff);  // Machine: i386
      buf.writeUInt16LE(sections.length, coffOff + 2);  // NumberOfSections
      buf.writeUInt32LE(Math.floor(Date.now() / 1000), coffOff + 4);  // TimeDateStamp
      buf.writeUInt16LE(optHeaderSize, coffOff + 16);  // SizeOfOptionalHeader
      buf.writeUInt16LE(0x0102, coffOff + 18);  // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

      // Optional Header
      const optOff = coffOff + 20;
      buf.writeUInt16LE(0x10B, optOff);  // Magic: PE32

      // Entry point RVA — point to the specified section
      const epRVA = 0x1000 + (entryPointSection * 0x1000);
      buf.writeUInt32LE(epRVA, optOff + 16);

      // Image size
      buf.writeUInt32LE(0x10000, optOff + 56);
      // Checksum
      buf.writeUInt32LE(options.checksum || 0, optOff + 64);

      // Section Table
      const sectionTableOff = optOff + optHeaderSize;
      sections.forEach((section, i) => {
        const off = sectionTableOff + (i * 40);
        const nameStr = section.name.padEnd(8, '\0').substring(0, 8);
        buf.write(nameStr, off, 8, 'ascii');

        const virtualSize = section.virtualSize || 512;
        const virtualAddress = 0x1000 + (i * 0x1000);

        buf.writeUInt32LE(virtualSize, off + 8);   // VirtualSize
        buf.writeUInt32LE(virtualAddress, off + 12); // VirtualAddress
        buf.writeUInt32LE(sectionMeta[i].rawSize, off + 16); // SizeOfRawData
        buf.writeUInt32LE(sectionMeta[i].rawOffset, off + 20); // PointerToRawData
        buf.writeUInt32LE(section.characteristics || 0x60000020, off + 36); // Characteristics
      });

      // Fill section data
      sections.forEach((section, i) => {
        const meta = sectionMeta[i];
        if (section.entropy === 'high') {
          // Fill with random-looking data (high entropy)
          for (let j = 0; j < meta.rawSize; j++) {
            buf[meta.rawOffset + j] = (j * 137 + i * 59) & 0xFF;
          }
        } else {
          // Fill with repetitive data (low entropy)
          for (let j = 0; j < meta.rawSize; j++) {
            buf[meta.rawOffset + j] = 0xCC;
          }
        }
      });

      // Add overlay data if specified
      if (options.overlayData) {
        options.overlayData.copy(buf, totalSize - options.overlayData.length);
      }

      return buf;
    }

    test('should detect clean PE file as not infected', () => {
      const peBuf = buildMinimalPE({
        sections: [
          { name: '.text', characteristics: 0x60000020, rawSize: 512, virtualSize: 512 },
          { name: '.data', characteristics: 0xC0000040, rawSize: 512, virtualSize: 512 },
        ],
      });

      const tempFile = path.join(tempDir, 'clean.exe');
      fs.writeFileSync(tempFile, peBuf);

      const result = detectExpiroInfection(tempFile);
      expect(result.isInfected).toBe(false);
      expect(result.confidence).toBeLessThan(EXPIRO_SIGNATURES.detectionThreshold);
    });

    test('should detect .expiro section as infected', () => {
      const peBuf = buildMinimalPE({
        sections: [
          { name: '.text', characteristics: 0x60000020, rawSize: 512, virtualSize: 512 },
          { name: '.expiro', characteristics: 0xE0000060, rawSize: 512, virtualSize: 512, entropy: 'high' },
        ],
      });

      const tempFile = path.join(tempDir, 'infected.exe');
      fs.writeFileSync(tempFile, peBuf);

      const result = detectExpiroInfection(tempFile);
      expect(result.isInfected).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(EXPIRO_SIGNATURES.detectionThreshold);
      expect(result.reasons.some(r => r.includes('.expiro'))).toBe(true);
    });

    test('should NOT flag UPX-packed file as infected (false-positive fix)', () => {
      const peBuf = buildMinimalPE({
        sections: [
          { name: 'UPX0', characteristics: 0xE0000080, rawSize: 512, virtualSize: 4096, entropy: 'high' },
          { name: 'UPX1', characteristics: 0xE0000060, rawSize: 512, virtualSize: 512, entropy: 'high' },
          { name: '.rsrc', characteristics: 0x40000040, rawSize: 512, virtualSize: 512 },
        ],
        entryPointSection: 1,
      });

      const tempFile = path.join(tempDir, 'upx-packed.exe');
      fs.writeFileSync(tempFile, peBuf);

      const result = detectExpiroInfection(tempFile);
      expect(result.isInfected).toBe(false);
      expect(result.reasons.some(r => r.includes('packer discount') || r.includes('benign packer'))).toBe(true);
    });

    test('should NOT flag VMProtect-packed binary as infected (false-positive fix)', () => {
      const peBuf = buildMinimalPE({
        sections: [
          { name: '.text', characteristics: 0x60000020, rawSize: 512, virtualSize: 512 },
          { name: '.data', characteristics: 0xC0000040, rawSize: 512, virtualSize: 512 },
          { name: '.rdata', characteristics: 0x40000040, rawSize: 512, virtualSize: 512 },
          { name: '.vmp0', characteristics: 0x60000020, rawSize: 512, virtualSize: 512, entropy: 'high' },
          { name: '.vmp1', characteristics: 0x60000020, rawSize: 512, virtualSize: 512, entropy: 'high' },
        ],
        entryPointSection: 4, // Entry in .vmp1
      });

      const tempFile = path.join(tempDir, 'vmprotect-binary.dll');
      fs.writeFileSync(tempFile, peBuf);

      const result = detectExpiroInfection(tempFile);
      expect(result.isInfected).toBe(false);
      expect(result.confidence).toBe(0);
    });

    test('v3: real Expiro layout is detected by the structural layer (legacy v2 scores it 0)', () => {
      const { expiroInfected64 } = require('./__tests__/helpers/pe-builder');
      const { detectLegacyHeuristics } = require('./expiro-detector');
      const tempFile = path.join(tempDir, 'real-layout.exe');
      fs.writeFileSync(tempFile, expiroInfected64());

      expect(detectLegacyHeuristics(tempFile).isInfected).toBe(false);
      const result = detectExpiroInfection(tempFile);
      expect(result.isInfected).toBe(true);
      expect(result.detectionLayer).toBe('structural');
      expect(result.threatName).toMatch(/Expiro \(structural\)/);
      expect(result.reasons[0]).toMatch(/^\[structural\]/);
    });

    test('v3: packer discount cannot veto a structural detection', () => {
      const { buildPE, msvcStub64, SEC } = require('./__tests__/helpers/pe-builder');
      const buf = buildPE({
        sections: [
          { name: '.text', characteristics: SEC.CODE, rawSize: 0x2000 },
          { name: '.vmp0', characteristics: SEC.CODE, rawSize: 0x1000 },
          { name: '.reloc', characteristics: SEC.RWX_DATA, rawSize: 0x40000 },
        ],
        relocDir: 'zero',
        dllCharacteristics: 0x8120,
        epBytes: ({ sections, entryRva }) => { const l = sections[2]; return msvcStub64(entryRva, l.virtualAddress + l.rawSize - 0x1000); },
      });
      const tempFile = path.join(tempDir, 'vmp-infected.exe');
      fs.writeFileSync(tempFile, buf);
      const result = detectExpiroInfection(tempFile);
      expect(result.isInfected).toBe(true);
      expect(result.reasons.some((r) => /benign packer verified/i.test(r))).toBe(false);
    });

    test('v3: .tmp files with the Expiro layout are checked (infected Inno Setup _unins.tmp seen in the wild)', () => {
      const { expiroInfected64 } = require('./__tests__/helpers/pe-builder');
      const tempFile = path.join(tempDir, '_unins.tmp');
      fs.writeFileSync(tempFile, expiroInfected64());
      expect(detectExpiroInfection(tempFile).isInfected).toBe(true);
    });

    test('should flag file with many suspicious sections', () => {
      const sections = [];
      for (let i = 0; i < 10; i++) {
        sections.push({
          name: `.sec${i}`,
          characteristics: 0xE0000060, // Exec + Write + Read
          rawSize: 512,
          virtualSize: 512,
          entropy: i > 6 ? 'high' : 'normal',
        });
      }

      const peBuf = buildMinimalPE({
        sections,
        entryPointSection: 8, // Entry in unusual section
      });

      const tempFile = path.join(tempDir, 'multi-section.exe');
      fs.writeFileSync(tempFile, peBuf);

      const result = detectExpiroInfection(tempFile);
      // Should flag due to: high section count + exec+write + entry in unusual section
      expect(result.confidence).toBeGreaterThan(30);
    });
  });
});
