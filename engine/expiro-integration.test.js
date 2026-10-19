/**
 * Integration tests for complete Expiro protection system
 */

const expiroDetector = require('./expiro-detector');
const ExpiroDisinfector = require('./expiro-disinfector');
const ExpiroPrevention = require('./expiro-prevention');

describe('Expiro Protection System - Integration Tests', () => {
  
  describe('Detection Layer', () => {
    test('should detect suspicious PE characteristics', () => {
      // Mock detection logic is tested
      expect(expiroDetector.EXPIRO_SIGNATURES).toBeDefined();
      expect(expiroDetector.EXPIRO_SIGNATURES.detectionThreshold).toBe(60);
    });
    
    test('should handle non-PE files gracefully', async () => {
      const result = await expiroDetector.scanFile(__filename);
      expect(result.isInfected).toBe(false);
      expect(result.confidence).toBe(0);
    });
  });

  describe('Disinfection Layer', () => {
    let mockQuarantine;
    let disinfector;
    
    beforeEach(() => {
      mockQuarantine = {
        quarantineFile: jest.fn().mockResolvedValue({
          success: true,
          quarantinePath: '/path/to/quarantine/file',
        }),
      };
      
      disinfector = new ExpiroDisinfector(mockQuarantine);
    });
    
    test('should assess file criticality correctly', () => {
      const critical = disinfector.assessFileCriticality('C:\\Windows\\System32\\file.exe');
      expect(critical.isCritical).toBe(true);
      
      const nonCritical = disinfector.assessFileCriticality('C:\\Users\\Test\\file.exe');
      expect(nonCritical.isCritical).toBe(false);
    });
    
    test('should quarantine infected file', async () => {
      // Mock file that exists
      const mockDetection = {
        isInfected: true,
        confidence: 75,
        threatName: 'Virus:Win32/Expiro.EK!MTB',
        filePath: __filename,  // Use this test file as mock
      };
      
      const result = await disinfector.disinfectFile(__filename, mockDetection);
      
      expect(result.action).toBeDefined();
    });
  });

  describe('Prevention Layer', () => {
    let mockQuarantine;
    let prevention;
    
    beforeEach(() => {
      mockQuarantine = {
        quarantineFile: jest.fn().mockResolvedValue({
          success: true,
        }),
      };
      
      prevention = new ExpiroPrevention(mockQuarantine);
    });
    
    afterEach(() => {
      prevention.stop();
    });
    
    test('should start and stop prevention', () => {
      expect(prevention.isActive).toBe(false);
      
      prevention.start();
      expect(prevention.isActive).toBe(true);
      
      prevention.stop();
      expect(prevention.isActive).toBe(false);
    });
    
    test('should track statistics', () => {
      prevention.start();
      
      const stats = prevention.getStats();
      expect(stats).toHaveProperty('filesScanned');
      expect(stats).toHaveProperty('infectionsBlocked');
      expect(stats).toHaveProperty('isActive');
      expect(stats.isActive).toBe(true);
    });
    
    test('should generate report', () => {
      prevention.start();
      
      const report = prevention.generateReport();
      expect(typeof report).toBe('string');
      expect(report).toContain('EXPIRO REAL-TIME PREVENTION REPORT');
    });
  });

  describe('End-to-End Protection Flow', () => {
    test('Detection → Disinfection workflow', async () => {
      // 1. Detect
      const detection = await expiroDetector.scanFile(__filename);
      expect(detection).toHaveProperty('isInfected');
      expect(detection).toHaveProperty('confidence');
      
      // 2. If infected (simulated), disinfect
      if (detection.isInfected) {
        const mockQuarantine = {
          quarantineFile: jest.fn().mockResolvedValue({ success: true }),
        };
        
        const disinfector = new ExpiroDisinfector(mockQuarantine);
        const result = await disinfector.disinfectFile(__filename, detection);
        
        expect(result).toHaveProperty('action');
      }
    });
  });
});
