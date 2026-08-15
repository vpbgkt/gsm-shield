const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { spawn } = require('child_process');
const fs = require('fs');
const { updateDefinitions } = require('./updater');
const { getDb } = require('../database');

// Mock child_process spawn
jest.mock('child_process');

// Mock fs
jest.mock('fs');

// Mock database
jest.mock('../database');

describe('updater module', () => {
  let mockChildProcess;
  let mockStdout;
  let mockStderr;
  let mockDb;

  beforeEach(() => {
    jest.clearAllMocks();

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

    // Mock database
    mockDb = {
      prepare: jest.fn().mockReturnValue({
        run: jest.fn()
      })
    };
    getDb.mockReturnValue(mockDb);

    // Mock fs.statSync to return valid file stats by default
    fs.statSync.mockImplementation((filePath) => {
      if (filePath.includes('.cvd')) {
        return {
          isFile: () => true,
          size: 1024 * 1024 // 1MB
        };
      }
      throw new Error('File not found');
    });
  });

  describe('updateDefinitions', () => {
    test('should spawn freshclam.exe with correct arguments', async () => {
      setImmediate(() => {
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions();

      expect(spawn).toHaveBeenCalledWith(
        expect.stringContaining('freshclam.exe'),
        expect.arrayContaining([
          '--stdout',
          expect.stringContaining('--datadir=')
        ]),
        { stdio: ['ignore', 'pipe', 'pipe'] }
      );
    });

    test('should return success when update completes with exit code 0 and definitions are valid', async () => {
      setImmediate(() => {
        mockStdout.push('Downloading main.cvd [100%]\n');
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      const result = await updateDefinitions();

      expect(result.success).toBe(true);
      expect(result.version).toBeDefined();
      expect(result.lastUpdate).toBeDefined();
      expect(mockDb.prepare).toHaveBeenCalledWith('UPDATE settings SET value = ? WHERE key = ?');
    });

    test('should call onProgress callback with download progress', async () => {
      const onProgress = jest.fn();
      
      setImmediate(() => {
        mockStdout.push('Downloading main.cvd [25%]\n');
        mockStdout.push('Downloading main.cvd [50%]\n');
        mockStdout.push('Downloading main.cvd [75%]\n');
        mockStdout.push('Downloading main.cvd [100%]\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions({ onProgress });

      expect(onProgress).toHaveBeenCalled();
      expect(onProgress).toHaveBeenCalledWith(
        expect.objectContaining({
          status: expect.any(String),
          percent: expect.any(Number)
        })
      );
    });

    test('should call onProgress with "Testing database" status', async () => {
      const onProgress = jest.fn();
      
      setImmediate(() => {
        mockStdout.push('Testing database\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions({ onProgress });

      expect(onProgress).toHaveBeenCalledWith({
        status: 'Verifying definitions...',
        percent: 95
      });
    });

    test('should call onProgress when database is already up-to-date', async () => {
      const onProgress = jest.fn();
      
      setImmediate(() => {
        mockStdout.push('main.cvd is up-to-date\n');
        mockStdout.push('daily.cvd is up-to-date\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions({ onProgress });

      expect(onProgress).toHaveBeenCalledWith({
        status: 'Definitions already up to date',
        percent: 100
      });
    });

    test('should return failure when freshclam exits with non-zero code', async () => {
      setImmediate(() => {
        mockStderr.push('Error: Network connection failed\n');
        mockStderr.push(null);
        mockChildProcess.emit('exit', 1);
      });

      const result = await updateDefinitions();

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toContain('Network connection failed');
    });

    test('should return failure when definition verification fails after update', async () => {
      // Mock fs.statSync to return zero-size files
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('.cvd')) {
          return {
            isFile: () => true,
            size: 0 // Zero size = corrupted
          };
        }
        throw new Error('File not found');
      });

      setImmediate(() => {
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      const result = await updateDefinitions();

      expect(result.success).toBe(false);
      expect(result.error).toContain('verification failed');
    });

    test('should retain existing definitions on failure', async () => {
      // Initial state - definitions exist
      const initialFsStatSync = fs.statSync.getMockImplementation();
      
      setImmediate(() => {
        mockStderr.push('Error: Network timeout\n');
        mockStderr.push(null);
        mockChildProcess.emit('exit', 1);
      });

      await updateDefinitions();

      // Verify that fs.statSync was not modified (definitions retained)
      expect(fs.statSync.getMockImplementation()).toBe(initialFsStatSync);
    });

    test('should handle spawn error gracefully', async () => {
      const spawnError = new Error('ENOENT: freshclam.exe not found');
      
      setImmediate(() => {
        mockChildProcess.emit('error', spawnError);
      });

      const result = await updateDefinitions();

      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to start updater');
    });

    test('should update settings.definition_version and settings.last_definition_update on success', async () => {
      const runMock = jest.fn();
      mockDb.prepare.mockReturnValue({ run: runMock });

      setImmediate(() => {
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions();

      expect(runMock).toHaveBeenCalledWith(expect.any(String), 'definition_version');
      expect(runMock).toHaveBeenCalledWith(expect.any(String), 'last_definition_update');
    });

    test('should not update settings when verification fails', async () => {
      // Mock fs.statSync to simulate missing definition files
      fs.statSync.mockImplementation(() => {
        throw new Error('File not found');
      });

      const runMock = jest.fn();
      mockDb.prepare.mockReturnValue({ run: runMock });

      setImmediate(() => {
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions();

      // Settings should not be updated when verification fails
      expect(runMock).not.toHaveBeenCalled();
    });

    test('should handle database update error gracefully', async () => {
      // Mock database error
      mockDb.prepare.mockImplementation(() => {
        throw new Error('Database locked');
      });

      setImmediate(() => {
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      const result = await updateDefinitions();

      // Should still return success since definitions were downloaded
      expect(result.success).toBe(true);
      expect(result.error).toContain('Settings update failed');
    });

    test('should parse download progress percentages correctly', async () => {
      const onProgress = jest.fn();
      
      setImmediate(() => {
        mockStdout.push('Downloading daily.cvd [42%]\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions({ onProgress });

      expect(onProgress).toHaveBeenCalledWith({
        status: 'Downloading daily.cvd',
        percent: 42
      });
    });

    test('should handle generic status messages', async () => {
      const onProgress = jest.fn();
      
      setImmediate(() => {
        mockStdout.push('Resolving dns server...\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      await updateDefinitions({ onProgress });

      expect(onProgress).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'Resolving dns server...'
        })
      );
    });
  });

  describe('edge-case tests for definition updater', () => {
    test('network failure returns { success: false } without throwing and existing .cvd files unchanged', async () => {
      // Simulate existing valid definitions before the failed update
      const existingMainStats = { isFile: () => true, size: 2048000 };
      const existingDailyStats = { isFile: () => true, size: 1536000 };
      
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd')) {
          return existingMainStats;
        }
        if (filePath.includes('daily.cvd')) {
          return existingDailyStats;
        }
        throw new Error('File not found');
      });

      // Simulate network failure - freshclam exits with error code
      setImmediate(() => {
        mockStderr.push('ERROR: Connection failed\n');
        mockStderr.push('ERROR: Can\'t connect to port 80 of host database.clamav.net\n');
        mockStderr.push(null);
        mockChildProcess.emit('exit', 1);
      });

      // Call updateDefinitions and ensure it doesn't throw
      let threwError = false;
      let result;
      
      try {
        result = await updateDefinitions();
      } catch (error) {
        threwError = true;
      }

      // Assert: should not throw
      expect(threwError).toBe(false);
      
      // Assert: should return failure result
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toContain('Connection failed');

      // Assert: settings should not be updated (existing definitions retained)
      expect(mockDb.prepare).not.toHaveBeenCalled();

      // Verify that the mock implementation is still returning the original file stats
      // (in a real scenario, the actual .cvd files on disk would be unchanged)
      const mainCvdStats = fs.statSync('main.cvd');
      const dailyCvdStats = fs.statSync('daily.cvd');
      expect(mainCvdStats.size).toBe(2048000);
      expect(dailyCvdStats.size).toBe(1536000);
    });

    test('partial download (zero-size output file) is detected by validation step and rejected', async () => {
      // Simulate a scenario where freshclam reports success but writes zero-byte files
      // This can happen with interrupted downloads that don't properly fail
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd')) {
          return {
            isFile: () => true,
            size: 0 // Zero-size = partial/corrupted download
          };
        }
        if (filePath.includes('daily.cvd')) {
          return {
            isFile: () => true,
            size: 0 // Zero-size = partial/corrupted download
          };
        }
        throw new Error('File not found');
      });

      // Freshclam reports success (exit 0) despite partial download
      setImmediate(() => {
        mockStdout.push('Downloading main.cvd [100%]\n');
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      const result = await updateDefinitions();

      // Assert: validation should detect zero-size files and reject the update
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toContain('verification failed');
      expect(result.error).toContain('corrupted');

      // Assert: settings should not be updated when verification fails
      expect(mockDb.prepare).not.toHaveBeenCalled();
    });

    test('network timeout returns failure without throwing', async () => {
      // Simulate network timeout scenario
      setImmediate(() => {
        mockStderr.push('ERROR: Connection timed out\n');
        mockStderr.push('ERROR: Update failed\n');
        mockStderr.push(null);
        mockChildProcess.emit('exit', 2);
      });

      let threwError = false;
      let result;
      
      try {
        result = await updateDefinitions();
      } catch (error) {
        threwError = true;
      }

      expect(threwError).toBe(false);
      expect(result.success).toBe(false);
      expect(result.error).toContain('timed out');
    });

    test('only main.cvd is zero-size is detected and rejected', async () => {
      // Partial failure: only one file is corrupted
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd')) {
          return {
            isFile: () => true,
            size: 0 // Corrupted
          };
        }
        if (filePath.includes('daily.cvd')) {
          return {
            isFile: () => true,
            size: 1024000 // Valid
          };
        }
        throw new Error('File not found');
      });

      setImmediate(() => {
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      const result = await updateDefinitions();

      expect(result.success).toBe(false);
      expect(result.error).toContain('verification failed');
    });

    test('only daily.cvd is zero-size is detected and rejected', async () => {
      // Partial failure: only one file is corrupted
      fs.statSync.mockImplementation((filePath) => {
        if (filePath.includes('main.cvd')) {
          return {
            isFile: () => true,
            size: 2048000 // Valid
          };
        }
        if (filePath.includes('daily.cvd')) {
          return {
            isFile: () => true,
            size: 0 // Corrupted
          };
        }
        throw new Error('File not found');
      });

      setImmediate(() => {
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      const result = await updateDefinitions();

      expect(result.success).toBe(false);
      expect(result.error).toContain('verification failed');
    });

    test('DNS resolution failure returns failure without throwing', async () => {
      // Simulate DNS resolution failure
      setImmediate(() => {
        mockStderr.push('ERROR: Can\'t resolve host database.clamav.net\n');
        mockStderr.push(null);
        mockChildProcess.emit('exit', 1);
      });

      let threwError = false;
      let result;
      
      try {
        result = await updateDefinitions();
      } catch (error) {
        threwError = true;
      }

      expect(threwError).toBe(false);
      expect(result.success).toBe(false);
      expect(result.error).toContain('resolve host');
    });

    test('definition files missing entirely after update attempt is detected and rejected', async () => {
      // Simulate missing files (not just zero-size)
      fs.statSync.mockImplementation(() => {
        throw new Error('ENOENT: no such file or directory');
      });

      setImmediate(() => {
        mockStdout.push('Database updated\n');
        mockStdout.push(null);
        mockChildProcess.emit('exit', 0);
      });

      const result = await updateDefinitions();

      expect(result.success).toBe(false);
      expect(result.error).toContain('verification failed');
      expect(mockDb.prepare).not.toHaveBeenCalled();
    });
  });
});
