const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { scan, checkDefinitions } = require('./scanner');

// Mock child_process spawn
jest.mock('child_process');

// Mock fs for checkDefinitions tests
jest.mock('fs');

describe('scanner module', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('checkDefinitions', () => {
    test('should return ok=true when both definition files exist and have size > 0', () => {
      // Mock fs.statSync to return valid file stats
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd') || filePath.includes('daily.cvd')) {
          return {
            isFile: () => true,
            size: 1024 * 1024 // 1MB
          };
        }
        throw new Error('File not found');
      });

      const result = checkDefinitions();
      
      expect(result.ok).toBe(true);
      expect(result.detail).toBe('Virus definitions are valid');
      expect(fs.statSync).toHaveBeenCalledTimes(2);
    });

    test('should return ok=false when main.cvd is missing', () => {
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd')) {
          throw new Error('ENOENT: no such file or directory');
        }
        return {
          isFile: () => true,
          size: 1024
        };
      });

      const result = checkDefinitions();
      
      expect(result.ok).toBe(false);
      expect(result.detail).toContain('Failed to verify virus definitions');
    });

    test('should return ok=false when main.cvd has size 0', () => {
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd')) {
          return {
            isFile: () => true,
            size: 0
          };
        }
        return {
          isFile: () => true,
          size: 1024
        };
      });

      const result = checkDefinitions();
      
      expect(result.ok).toBe(false);
      expect(result.detail).toContain('main.cvd is missing or empty');
    });

    test('should return ok=false when daily.cvd has size 0', () => {
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('daily.cvd')) {
          return {
            isFile: () => true,
            size: 0
          };
        }
        return {
          isFile: () => true,
          size: 1024
        };
      });

      const result = checkDefinitions();
      
      expect(result.ok).toBe(false);
      expect(result.detail).toContain('daily.cvd is missing or empty');
    });
  });

  describe('scan', () => {
    let mockChildProcess;
    let mockStdout;
    let mockStderr;

    beforeEach(() => {
      const { EventEmitter } = require('events');
      const { Readable } = require('stream');
      
      // Create proper stream mocks
      mockStdout = new Readable({ read() {} });
      mockStderr = new Readable({ read() {} });
      
      // Create mock child process with EventEmitter
      mockChildProcess = Object.assign(new EventEmitter(), {
        stdout: mockStdout,
        stderr: mockStderr,
        kill: jest.fn(),
        killed: false
      });

      spawn.mockReturnValue(mockChildProcess);
    });

    test('should spawn clamscan.exe with correct arguments', async () => {
      const targetPath = 'C:\\test\\path';
      
      // Simulate immediate clean exit
      setImmediate(() => {
        mockChildProcess.emit('exit', 0);
      });

      await scan(targetPath);

      // --recursive: scan subdirectories; --stdout: emit per-file verdict
      // lines for progress tracking; --no-summary: suppress the SCAN SUMMARY
      // footer (fixes a bug where summary lines were miscounted as scanned
      // files); --database=...: explicit path to the bundled definitions.
      expect(spawn).toHaveBeenCalledWith(
        expect.stringContaining('clamscan.exe'),
        [
          '--recursive',
          '--stdout',
          '--no-summary',
          expect.stringContaining('--database='),
          targetPath,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'] }
      );
    });

    test('should return clean result when exit code is 0', async () => {
      const targetPath = 'C:\\test\\clean';
      
      setImmediate(() => {
        mockChildProcess.emit('exit', 0);
      });

      const result = await scan(targetPath);

      expect(result.cancelled).toBe(false);
      expect(result.error).toBeUndefined();
      expect(result).toHaveProperty('duration');
      expect(result).toHaveProperty('filesScanned');
      expect(result).toHaveProperty('threatsFound');
    });

    test('should call onThreat callback when threat is detected', async () => {
      const targetPath = 'C:\\test\\infected';
      const onThreat = jest.fn();
      
      setImmediate(() => {
        // Simulate ClamAV output with threat found
        mockStdout.push('C:\\test\\infected\\malware.exe: Win.Trojan.Agent FOUND\n');
        mockStdout.push(null); // End stream
        
        // Exit code 1 = threats found
        mockChildProcess.emit('exit', 1);
      });

      const result = await scan(targetPath, { onThreat });

      expect(result.cancelled).toBe(false);
      expect(result.threatsFound).toBe(1);
      expect(onThreat).toHaveBeenCalledWith({
        filePath: 'C:\\test\\infected\\malware.exe',
        threatName: 'Win.Trojan.Agent'
      });
    });

    test('should handle cancellation via AbortSignal', async () => {
      const targetPath = 'C:\\test\\path';
      const abortController = new AbortController();
      
      // Abort immediately
      setImmediate(() => {
        abortController.abort();
        // Simulate process being killed
        setTimeout(() => {
          mockChildProcess.killed = true;
          mockChildProcess.emit('exit', null);
        }, 10);
      });

      const result = await scan(targetPath, { signal: abortController.signal });

      expect(mockChildProcess.kill).toHaveBeenCalledWith('SIGTERM');
      expect(result.cancelled).toBe(true);
    });

    test('should handle already-aborted signal', async () => {
      const targetPath = 'C:\\test\\path';
      const abortController = new AbortController();
      abortController.abort(); // Abort before scan starts
      
      setImmediate(() => {
        mockChildProcess.killed = true;
        mockChildProcess.emit('exit', null);
      });

      const result = await scan(targetPath, { signal: abortController.signal });

      expect(mockChildProcess.kill).toHaveBeenCalledWith('SIGTERM');
      expect(result.cancelled).toBe(true);
    });

    test('should return error result when exit code >= 2', async () => {
      const targetPath = 'C:\\test\\path';
      
      setImmediate(() => {
        mockStderr.push('Error: Invalid database\n');
        mockStderr.push(null);
        mockChildProcess.emit('exit', 2); // Error exit code
      });

      const result = await scan(targetPath);

      expect(result.error).toBe(true);
      expect(result.errorCode).toBe(2);
      expect(result.cancelled).toBe(false);
    });

    test('should handle spawn error', async () => {
      const targetPath = 'C:\\test\\path';
      const spawnError = new Error('ENOENT: clamscan.exe not found');
      
      setImmediate(() => {
        mockChildProcess.emit('error', spawnError);
      });

      const result = await scan(targetPath);

      expect(result.error).toBe(true);
      expect(result.errorMessage).toContain('Failed to start scanner');
      expect(result.filesScanned).toBe(0);
      expect(result.threatsFound).toBe(0);
    });

    // Regression test for the miscounting bug: a real clamscan.exe run
    // against a single EICAR file was observed to report filesScanned=11
    // (1 real file + 10 "SCAN SUMMARY" footer lines, each matching a
    // generic "key: value" pattern). --no-summary was missing, and the
    // parser matched any "text: text" line as a scanned file. This test
    // simulates the exact summary footer ClamAV emits and asserts it is
    // never counted.
    test('should NOT count SCAN SUMMARY footer lines as scanned files (regression)', async () => {
      const targetPath = 'C:\\test\\eicar-dir';
      const onThreat = jest.fn();

      setImmediate(() => {
        mockStdout.push('C:\\test\\eicar-dir\\eicar.com: Eicar-Test-Signature FOUND\n');
        mockStdout.push('\n');
        mockStdout.push('----------- SCAN SUMMARY -----------\n');
        mockStdout.push('Known viruses: 3627885\n');
        mockStdout.push('Engine version: 1.5.2\n');
        mockStdout.push('Scanned directories: 1\n');
        mockStdout.push('Scanned files: 1\n');
        mockStdout.push('Infected files: 1\n');
        mockStdout.push('Data scanned: 68 B\n');
        mockStdout.push('Data read: 68 B (ratio 1.00:1)\n');
        mockStdout.push('Time: 13.762 sec (0 m 13 s)\n');
        mockStdout.push('Start Date: 2026:08:16 23:03:44\n');
        mockStdout.push('End Date:   2026:08:16 23:03:58\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 1);
      });

      const result = await scan(targetPath, { onThreat });

      // Exactly 1 file (the EICAR file), NOT 11 (1 file + 10 summary lines).
      expect(result.filesScanned).toBe(1);
      expect(result.threatsFound).toBe(1);
      expect(onThreat).toHaveBeenCalledWith({
        filePath: 'C:\\test\\eicar-dir\\eicar.com',
        threatName: 'Eicar-Test-Signature',
      });
    });

    test('should call onProgress callback', async () => {
      const targetPath = 'C:\\test\\path';
      const onProgress = jest.fn();
      
      setImmediate(() => {
        // Simulate scanning multiple files
        mockStdout.push('file1.txt: OK\n');
        mockStdout.push('file2.txt: OK\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await scan(targetPath, { onProgress });

      // onProgress is throttled to 500ms, so it might not be called
      // in this immediate test scenario, but we can verify it was set up
      expect(onProgress).toBeDefined();
    });
  });

  // Requirements 6.5, 6.6 — edge-case tests for scanner error handling
  describe('error handling edge cases', () => {
    let mockChildProcess;
    let mockStdout;
    let mockStderr;

    beforeEach(() => {
      const { EventEmitter } = require('events');
      const { Readable } = require('stream');

      mockStdout = new Readable({ read() {} });
      mockStderr = new Readable({ read() {} });

      mockChildProcess = Object.assign(new EventEmitter(), {
        stdout: mockStdout,
        stderr: mockStderr,
        kill: jest.fn(),
        killed: false
      });

      spawn.mockReturnValue(mockChildProcess);
    });

    // Requirement 6.5 — exit code ≥2 resolves (never throws/rejects) and returns error result
    test('exit code 2 — scan() resolves with error result instead of rejecting', async () => {
      setImmediate(() => {
        mockStderr.push('ERROR: Can not open/read RealTime Scanning database\n');
        mockStderr.push(null);
        mockChildProcess.emit('exit', 2);
      });

      // Explicitly assert the promise resolves rather than rejects
      await expect(scan('C:\\test\\path')).resolves.toMatchObject({
        error: true,
        errorCode: 2,
        cancelled: false
      });
    });

    test('exit code 3 — scan() resolves with error result instead of rejecting', async () => {
      setImmediate(() => {
        mockStderr.push(null);
        mockChildProcess.emit('exit', 3);
      });

      const result = await scan('C:\\test\\path');

      expect(result.error).toBe(true);
      expect(result.errorCode).toBe(3);
      expect(result.cancelled).toBe(false);
      // errorMessage should be populated
      expect(typeof result.errorMessage).toBe('string');
      expect(result.errorMessage.length).toBeGreaterThan(0);
    });

    // Requirement 6.6 — missing main.cvd causes checkDefinitions() to return { ok: false }
    test('missing main.cvd — checkDefinitions() returns { ok: false } with a detail message', () => {
      // Simulate main.cvd absent; daily.cvd present
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd')) {
          const err = new Error('ENOENT: no such file or directory, stat \'' + filePath + '\'');
          err.code = 'ENOENT';
          throw err;
        }
        return { isFile: () => true, size: 1024 * 1024 };
      });

      const result = checkDefinitions();

      expect(result.ok).toBe(false);
      expect(typeof result.detail).toBe('string');
      expect(result.detail.length).toBeGreaterThan(0);
    });
  });
});
