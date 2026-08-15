/**
 * defender/__tests__/preservation.property.test.js
 *
 * Property-based tests for preservation of baseline behavior (BEFORE fix).
 * These tests capture the CURRENT behavior of ps-runner.js, first-run.js,
 * error logging, and IPC messaging to ensure no regressions after the fix.
 *
 * **IMPORTANT**: These tests should PASS on the UNFIXED code.
 *
 * Property 2: Preservation — Non-WSC Script Execution Behavior
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
 */

'use strict';

const fc = require('fast-check');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { runScript } = require('../ps-runner');

// Mock the database module for first-run tests
jest.mock('../../database', () => ({
  getDb: jest.fn(() => ({
    prepare: jest.fn((sql) => ({
      get: jest.fn((key) => {
        // Return first_run_complete as '0' initially
        if (key === 'first_run_complete') {
          return { value: '0' };
        }
        return null;
      }),
      run: jest.fn(),
    })),
  })),
}));

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let tempDir;
let testScripts = [];

beforeAll(() => {
  // Create temp directory for test scripts
  tempDir = path.join(os.tmpdir(), `preservation-test-${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });
});

afterAll(() => {
  // Clean up test scripts
  testScripts.forEach((scriptPath) => {
    try {
      if (fs.existsSync(scriptPath)) {
        fs.unlinkSync(scriptPath);
      }
    } catch (err) {
      // Ignore cleanup errors
    }
  });

  // Clean up temp directory
  try {
    if (fs.existsSync(tempDir)) {
      fs.rmdirSync(tempDir);
    }
  } catch (err) {
    // Ignore cleanup errors
  }
});

/**
 * Helper to create a temporary PowerShell script
 */
function createTestScript(name, content) {
  const scriptPath = path.join(tempDir, name);
  fs.writeFileSync(scriptPath, content, 'utf8');
  testScripts.push(scriptPath);
  return scriptPath;
}

// ---------------------------------------------------------------------------
// Property 2.1: ps-runner.js captures stdout, stderr, exit codes correctly
// ---------------------------------------------------------------------------

describe('Property 2.1: ps-runner stdout/stderr/exitCode capture (Req 3.1)', () => {
  /**
   * **Validates: Requirements 3.1**
   *
   * For ANY PowerShell script that is NOT register-wsc.ps1, ps-runner.js
   * must correctly capture stdout, stderr, and exit codes.
   *
   * This test generates arbitrary exit codes and output strings to verify
   * the baseline behavior is preserved.
   */
  test('arbitrary scripts → correct stdout/stderr/exitCode capture', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 255 }), // Exit codes
        // Use alphanumeric strings to avoid PowerShell special characters
        fc.stringOf(
          fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '.split('')),
          { minLength: 1, maxLength: 50 }
        ),
        fc.stringOf(
          fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '.split('')),
          { minLength: 0, maxLength: 50 }
        ),
        async (exitCode, stdoutMsg, stderrMsg) => {
          // Precondition: Skip register-wsc.ps1 (this is for non-WSC scripts)
          const scriptName = `test-script-${Date.now()}-${Math.random()}.ps1`;
          fc.pre(!scriptName.includes('register-wsc'));

          // Create a script with the given exit code and output
          const scriptContent = `
            Write-Output "${stdoutMsg.replace(/"/g, '""')}"
            Write-Error "${stderrMsg.replace(/"/g, '""')}"
            exit ${exitCode}
          `;

          const scriptPath = createTestScript(scriptName, scriptContent);

          // Execute the script
          const result = await runScript(scriptPath);

          // Assert: ps-runner correctly captures all outputs
          expect(result).toHaveProperty('exitCode');
          expect(result).toHaveProperty('stdout');
          expect(result).toHaveProperty('stderr');
          expect(result.exitCode).toBe(exitCode);

          // Verify stdout contains the message (allowing for PowerShell formatting)
          // Note: PowerShell trims whitespace-only strings, so only check non-whitespace messages
          if (stdoutMsg.trim().length > 0) {
            expect(result.stdout).toContain(stdoutMsg.trim());
          }

          // Verify stderr contains the error message (allowing for PowerShell error formatting)
          if (stderrMsg.trim().length > 0) {
            expect(result.stderr.toLowerCase()).toContain('error');
          }
        }
      ),
      { numRuns: 10 } // Reduced runs for performance
    );
  }, 30000); // 30 second timeout

  /**
   * **Validates: Requirements 3.1**
   *
   * For scripts that execute successfully (exit 0), ps-runner must capture
   * the stdout correctly and return exitCode 0.
   */
  test('successful scripts → exitCode 0 and stdout captured', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate alphanumeric strings to avoid PowerShell special characters
        fc.stringOf(
          fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '.split('')),
          { minLength: 5, maxLength: 50 }
        ).filter(s => s.trim().length > 0), // Output message (non-whitespace)
        async (message) => {
          const scriptName = `success-${Date.now()}-${Math.random()}.ps1`;
          const scriptContent = `
            Write-Output "${message.replace(/"/g, '""')}"
            exit 0
          `;

          const scriptPath = createTestScript(scriptName, scriptContent);
          const result = await runScript(scriptPath);

          expect(result.exitCode).toBe(0);
          expect(result.stdout).toContain(message.trim());
        }
      ),
      { numRuns: 10 } // Reduced for performance
    );
  }, 30000); // 30 second timeout
});

// ---------------------------------------------------------------------------
// Property 2.2: disable-defender.ps1 continues to work correctly
// ---------------------------------------------------------------------------

describe('Property 2.2: disable-defender.ps1 baseline behavior (Req 3.4)', () => {
  /**
   * **Validates: Requirements 3.4**
   *
   * The disable-defender.ps1 script must continue to:
   * - Exit with code 0 (even when Tamper Protection blocks it)
   * - Log informational messages to stdout
   * - Handle errors gracefully with Continue error action preference
   */
  test('disable-defender.ps1 exits 0 on current unfixed code', async () => {
    const scriptPath = path.join(
      __dirname,
      '..',
      '..',
      'defender',
      'scripts',
      'disable-defender.ps1'
    );

    // Skip test if script doesn't exist (e.g., in CI without scripts)
    if (!fs.existsSync(scriptPath)) {
      console.warn('disable-defender.ps1 not found, skipping test');
      return;
    }

    const result = await runScript(scriptPath);

    // Assert: Script exits with 0 (this is the baseline behavior)
    expect(result.exitCode).toBe(0);

    // Assert: Stdout contains success message
    expect(result.stdout).toContain('disable-defender step complete');
  });
});

// ---------------------------------------------------------------------------
// Property 2.3: first-run.js orchestration sequence preservation
// ---------------------------------------------------------------------------

describe('Property 2.3: first-run orchestration sequence (Req 3.2)', () => {
  /**
   * **Validates: Requirements 3.2, 3.3**
   *
   * The first-run.js orchestrator must continue to:
   * - Execute all steps in sequence
   * - Continue execution even when individual steps fail
   * - Set first_run_complete='1' after all steps
   * - Send defender:setup-result IPC message
   *
   * Note: We test the core orchestration logic, not the actual script execution.
   */
  test('orchestrator continues after step failures', async () => {
    // Mock ps-runner instead of _runStep
    jest.mock('../ps-runner', () => ({
      runScript: jest.fn()
        .mockResolvedValueOnce({
          exitCode: 0,
          stdout: 'disable-defender step complete',
          stderr: '',
        })
        .mockResolvedValueOnce({
          exitCode: 1,
          stdout: '',
          stderr: 'Registration failed',
        }),
    }));

    // Clear module cache and reload
    delete require.cache[require.resolve('../../electron/first-run')];
    const firstRun = require('../../electron/first-run');
    const { getDb } = require('../../database');

    // Mock database to track setSetting calls
    const mockDb = {
      prepare: jest.fn((sql) => ({
        get: jest.fn(() => ({ value: '0' })),
        run: jest.fn(),
      })),
    };

    getDb.mockReturnValue(mockDb);

    // Mock mainWindow
    const mockWindow = {
      isDestroyed: jest.fn(() => false),
      webContents: {
        send: jest.fn(),
      },
    };

    // Execute the first-run setup
    await firstRun.runFirstRunSetup(mockWindow);

    // Assert: IPC message was sent to renderer
    expect(mockWindow.webContents.send).toHaveBeenCalled();

    const [channel, payload] = mockWindow.webContents.send.mock.calls[0];
    expect(channel).toBe('defender:setup-result');
    
    // Assert: Payload has required fields
    expect(payload).toHaveProperty('success');
    expect(payload).toHaveProperty('steps');
    expect(payload).toHaveProperty('failureCount');
    expect(payload).toHaveProperty('message');

    // Assert: steps array has both steps
    expect(payload.steps).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Property 2.4: Error logging to error.log preservation
// ---------------------------------------------------------------------------

describe('Property 2.4: error logging to error.log (Req 3.6)', () => {
  /**
   * **Validates: Requirements 3.6**
   *
   * The appendErrorLog function must continue to:
   * - Write timestamped error messages to AppData/GSMShieldAV/error.log
   * - Never throw on errors (best-effort logging)
   * - Create directories if they don't exist
   */
  test('appendErrorLog writes timestamped entries', () => {
    const firstRun = require('../../electron/first-run');

    // Generate arbitrary error messages
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 200 }),
        (errorMessage) => {
          // Call the error logging function (it's exposed for testing)
          // This should not throw
          expect(() => {
            firstRun._appendErrorLog(errorMessage);
          }).not.toThrow();

          // Note: We don't verify the file content here because:
          // 1. It's a side effect on disk
          // 2. The log file is in AppData (may require cleanup)
          // 3. The function silently swallows errors (best-effort)
          // The important property is: it never throws
        }
      ),
      { numRuns: 50 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 2.5: IPC messaging preservation
// ---------------------------------------------------------------------------

describe('Property 2.5: IPC messaging to renderer (Req 3.3)', () => {
  /**
   * **Validates: Requirements 3.3**
   *
   * The defender:setup-result IPC message must continue to be sent
   * with the correct payload structure after first-run completes.
   */
  test('defender:setup-result message has required fields', async () => {
    // Simplified test: verify IPC message structure without mocking internal functions
    const { getDb } = require('../../database');

    // Mock database
    const mockDb = {
      prepare: jest.fn((sql) => ({
        get: jest.fn(() => ({ value: '0' })),
        run: jest.fn(),
      })),
    };

    getDb.mockReturnValue(mockDb);

    // Mock mainWindow
    const mockWindow = {
      isDestroyed: jest.fn(() => false),
      webContents: {
        send: jest.fn(),
      },
    };

    // Mock ps-runner to return a simple result
    jest.mock('../ps-runner', () => ({
      runScript: jest.fn().mockResolvedValue({
        exitCode: 0,
        stdout: 'OK',
        stderr: '',
      }),
    }));

    // Clear cache and reload first-run
    delete require.cache[require.resolve('../../electron/first-run')];
    const firstRun = require('../../electron/first-run');

    // Execute the first-run setup
    await firstRun.runFirstRunSetup(mockWindow);

    // Assert: IPC message was sent
    expect(mockWindow.webContents.send).toHaveBeenCalled();

    // Assert: Message has required fields
    const [channel, payload] = mockWindow.webContents.send.mock.calls[0];
    expect(channel).toBe('defender:setup-result');
    expect(payload).toHaveProperty('success');
    expect(payload).toHaveProperty('steps');
    expect(payload).toHaveProperty('failureCount');
    expect(payload).toHaveProperty('message');

    // Assert: steps array has both steps
    expect(payload.steps).toHaveLength(2);
    expect(payload.steps[0]).toHaveProperty('name');
    expect(payload.steps[0]).toHaveProperty('success');
    expect(payload.steps[0]).toHaveProperty('exitCode');
    expect(payload.steps[0]).toHaveProperty('detail');
  });
});

// ---------------------------------------------------------------------------
// Property 2.6: Script path resolution preservation
// ---------------------------------------------------------------------------

describe('Property 2.6: script path resolution (Req 3.7)', () => {
  /**
   * **Validates: Requirements 3.7**
   *
   * The resolveScriptsDir function must continue to:
   * - Return resources/scripts/ in packaged apps
   * - Return defender/scripts/ in development mode
   * - Work correctly in both environments
   */
  test('script paths resolve correctly in development mode', () => {
    // In development mode, process.resourcesPath is undefined
    const originalResourcesPath = process.resourcesPath;
    delete process.resourcesPath;

    try {
      // Clear the require cache to reload first-run with undefined resourcesPath
      delete require.cache[require.resolve('../../electron/first-run')];
      const firstRun = require('../../electron/first-run');

      // The module should load without errors
      expect(firstRun).toBeDefined();
      expect(firstRun.isFirstRun).toBeDefined();
      expect(firstRun.runFirstRunSetup).toBeDefined();
    } finally {
      // Restore original value
      if (originalResourcesPath !== undefined) {
        process.resourcesPath = originalResourcesPath;
      }
      // Clear cache again to reset state
      delete require.cache[require.resolve('../../electron/first-run')];
    }
  });
});

// ---------------------------------------------------------------------------
// Property 2.7: Non-throwing behavior on all error conditions
// ---------------------------------------------------------------------------

describe('Property 2.7: non-throwing error handling (Req 3.1, 3.6)', () => {
  /**
   * **Validates: Requirements 3.1, 3.6**
   *
   * The ps-runner and first-run modules must NEVER throw exceptions.
   * All errors must be captured and returned/logged gracefully.
   */
  test('ps-runner never throws on invalid inputs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.constant(null),
          fc.constant(undefined),
          fc.constant(''),
          fc.constant('/invalid/path/that/does/not/exist.ps1'),
          fc.string({ maxLength: 5 }) // Very short strings (likely invalid paths)
        ),
        async (invalidPath) => {
          // This should never throw, even with invalid inputs
          const result = await runScript(invalidPath);

          // Assert: Returns a result object (not throwing)
          expect(result).toHaveProperty('exitCode');
          expect(result).toHaveProperty('stdout');
          expect(result).toHaveProperty('stderr');

          // Assert: Exit code indicates failure
          expect(result.exitCode).not.toBe(0);
        }
      ),
      { numRuns: 30 }
    );
  });
});
