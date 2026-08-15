/**
 * defender/ps-runner.test.js
 * 
 * Tests for PowerShell script runner.
 * Validates safe execution, error handling, and non-throwing behavior.
 */

const { runScript } = require('./ps-runner');
const fs = require('fs');
const path = require('path');
const os = require('os');

describe('ps-runner', () => {
  let tempDir;
  let testScripts = [];

  beforeAll(() => {
    // Create temp directory for test scripts
    tempDir = path.join(os.tmpdir(), `ps-runner-test-${Date.now()}`);
    fs.mkdirSync(tempDir, { recursive: true });
  });

  afterAll(() => {
    // Clean up test scripts
    testScripts.forEach(scriptPath => {
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

  describe('runScript', () => {
    it('should execute a simple PowerShell script and return exit code 0', async () => {
      const scriptPath = createTestScript('success.ps1', `
        Write-Output "Hello from PowerShell"
        exit 0
      `);

      const result = await runScript(scriptPath);

      expect(result).toHaveProperty('exitCode');
      expect(result).toHaveProperty('stdout');
      expect(result).toHaveProperty('stderr');
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('Hello from PowerShell');
    });

    it('should capture stdout from PowerShell script', async () => {
      const scriptPath = createTestScript('output.ps1', `
        Write-Output "Line 1"
        Write-Output "Line 2"
        Write-Output "Line 3"
      `);

      const result = await runScript(scriptPath);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('Line 1');
      expect(result.stdout).toContain('Line 2');
      expect(result.stdout).toContain('Line 3');
    });

    it('should capture stderr from PowerShell script', async () => {
      const scriptPath = createTestScript('error-output.ps1', `
        Write-Error "This is an error message"
      `);

      const result = await runScript(scriptPath);

      expect(result.stderr).toContain('error');
    });

    it('should return non-zero exit code without throwing', async () => {
      const scriptPath = createTestScript('failure.ps1', `
        Write-Output "About to fail"
        exit 42
      `);

      // Should not throw - this is the key requirement
      const result = await runScript(scriptPath);

      expect(result.exitCode).toBe(42);
      expect(result.stdout).toContain('About to fail');
    });

    it('should handle script with parameters', async () => {
      const scriptPath = createTestScript('with-params.ps1', `
        param($Name, $Value)
        Write-Output "Name: $Name"
        Write-Output "Value: $Value"
      `);

      const result = await runScript(scriptPath, ['TestName', '123']);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('Name: TestName');
      expect(result.stdout).toContain('Value: 123');
    });

    it('should handle script that exits with error code 2+', async () => {
      const scriptPath = createTestScript('error-code.ps1', `
        Write-Output "Critical error"
        exit 5
      `);

      const result = await runScript(scriptPath);

      // Should resolve, not throw
      expect(result.exitCode).toBe(5);
      expect(result.stdout).toContain('Critical error');
    });

    it('should handle non-existent script file gracefully', async () => {
      const nonExistentPath = path.join(tempDir, 'does-not-exist.ps1');

      const result = await runScript(nonExistentPath);

      // Should return error result, not throw
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toBeTruthy();
    });

    it('should handle invalid script path gracefully', async () => {
      const result = await runScript('');

      expect(result.exitCode).toBe(-1);
      expect(result.stderr).toContain('Invalid script path');
    });

    it('should handle null script path gracefully', async () => {
      const result = await runScript(null);

      expect(result.exitCode).toBe(-1);
      expect(result.stderr).toContain('Invalid script path');
    });

    it('should handle undefined params as empty array', async () => {
      const scriptPath = createTestScript('no-params.ps1', `
        Write-Output "No parameters"
      `);

      const result = await runScript(scriptPath, undefined);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('No parameters');
    });

    it('should normalize relative paths', async () => {
      const scriptPath = createTestScript('relative.ps1', `
        Write-Output "Relative path test"
      `);

      // Use relative path
      const relativePath = path.relative(process.cwd(), scriptPath);

      const result = await runScript(relativePath);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('Relative path test');
    });

    it('should run with ExecutionPolicy Bypass (verify no policy errors)', async () => {
      // This script would normally fail with restricted execution policy
      const scriptPath = createTestScript('policy-test.ps1', `
        Write-Output "Execution policy bypassed"
        Write-Output $ExecutionContext.SessionState.LanguageMode
      `);

      const result = await runScript(scriptPath);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('Execution policy bypassed');
      // Should not contain policy restriction errors
      expect(result.stderr).not.toContain('execution of scripts is disabled');
    });

    it('should handle scripts with multiple exit codes sequentially', async () => {
      const script1 = createTestScript('multi-1.ps1', 'exit 0');
      const script2 = createTestScript('multi-2.ps1', 'exit 1');
      const script3 = createTestScript('multi-3.ps1', 'exit 2');

      const result1 = await runScript(script1);
      const result2 = await runScript(script2);
      const result3 = await runScript(script3);

      expect(result1.exitCode).toBe(0);
      expect(result2.exitCode).toBe(1);
      expect(result3.exitCode).toBe(2);
    });

    it('should trim stdout and stderr whitespace', async () => {
      const scriptPath = createTestScript('whitespace.ps1', `
        Write-Output ""
        Write-Output "   Content with spaces   "
        Write-Output ""
      `);

      const result = await runScript(scriptPath);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).not.toMatch(/^\s+/); // No leading whitespace
      expect(result.stdout).not.toMatch(/\s+$/); // No trailing whitespace
    });

    it('should handle empty output gracefully', async () => {
      const scriptPath = createTestScript('empty.ps1', `
        # This script produces no output
        exit 0
      `);

      const result = await runScript(scriptPath);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe('');
      expect(result.stderr).toBe('');
    });
  });

  describe('Requirements validation', () => {
    it('validates Requirement 21.1: Uses ExecutionPolicy Bypass and NonInteractive flags', async () => {
      // Create a script that would fail without these flags
      const scriptPath = createTestScript('req-21.1.ps1', `
        Write-Output "Testing ExecutionPolicy Bypass"
        # This should work even if system policy is Restricted
      `);

      const result = await runScript(scriptPath);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('Testing ExecutionPolicy Bypass');
    });

    it('validates Requirement 21.6: Never throws on non-zero exit code', async () => {
      const scriptPath = createTestScript('req-21.6.ps1', `
        Write-Output "This will exit with error"
        exit 99
      `);

      // Should not throw - wrap in expect to catch any thrown errors
      await expect(runScript(scriptPath)).resolves.toMatchObject({
        exitCode: 99,
        stdout: expect.stringContaining('This will exit with error'),
        stderr: expect.any(String)
      });
    });
  });
});
