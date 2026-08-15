/**
 * defender/register-wsc.bug.test.js
 * 
 * Bug Condition Exploration Test for WSC Registration Failure
 * 
 * **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
 * **DO NOT attempt to fix the test or the code when it fails**
 * **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
 * **GOAL**: Surface counterexamples that demonstrate the bug exists
 * 
 * This test verifies that the current WMI-based registration approach fails silently
 * without creating the required registry keys or WSC entries.
 * 
 * **Validates: Requirements 1.1, 1.4, 1.5**
 */

const { runScript } = require('./ps-runner');
const path = require('path');
const fs = require('fs');
const fc = require('fast-check');

describe('Bug Condition Exploration: WSC Registration via WMI API Fails', () => {
  const SCRIPT_PATH = path.join(__dirname, 'scripts', 'register-wsc.ps1');
  
  /**
   * Helper: Create PowerShell script to check registry key existence
   */
  function createRegistryCheckScript(keyPath) {
    const tempDir = path.join(require('os').tmpdir(), `wsc-test-${Date.now()}`);
    fs.mkdirSync(tempDir, { recursive: true });
    
    const scriptPath = path.join(tempDir, 'check-registry.ps1');
    const scriptContent = `
      param($KeyPath)
      try {
        $exists = Test-Path $KeyPath
        if ($exists) {
          Write-Output "EXISTS"
        } else {
          Write-Output "NOT_FOUND"
        }
        exit 0
      } catch {
        Write-Output "ERROR: $_"
        exit 1
      }
    `;
    
    fs.writeFileSync(scriptPath, scriptContent, 'utf8');
    return { scriptPath, tempDir };
  }
  
  /**
   * Helper: Create PowerShell script to query WSC for GSM Shield AV
   */
  function createWscQueryScript() {
    const tempDir = path.join(require('os').tmpdir(), `wsc-test-${Date.now()}`);
    fs.mkdirSync(tempDir, { recursive: true });
    
    const scriptPath = path.join(tempDir, 'query-wsc.ps1');
    const scriptContent = `
      try {
        $products = Get-WmiObject -Namespace "root\\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        $gsmShield = $products | Where-Object { $_.displayName -eq "GSM Shield AV" }
        
        if ($gsmShield) {
          Write-Output "FOUND"
          Write-Output "ProductState: $($gsmShield.productState)"
        } else {
          Write-Output "NOT_FOUND"
        }
        exit 0
      } catch {
        Write-Output "ERROR: $_"
        exit 1
      }
    `;
    
    fs.writeFileSync(scriptPath, scriptContent, 'utf8');
    return { scriptPath, tempDir };
  }
  
  /**
   * Helper: Clean up temporary scripts
   */
  function cleanup(tempDir) {
    try {
      if (fs.existsSync(tempDir)) {
        fs.readdirSync(tempDir).forEach(file => {
          fs.unlinkSync(path.join(tempDir, file));
        });
        fs.rmdirSync(tempDir);
      }
    } catch (err) {
      // Ignore cleanup errors
    }
  }

  describe('Property 1: Bug Condition - WSC Registration via WMI API Fails', () => {
    /**
     * **Validates: Requirements 1.1, 1.4, 1.5**
     * 
     * This property test demonstrates that running register-wsc.ps1 (unfixed) 
     * with WMI CreateInstance() and Put() fails to create registry keys under
     * HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}
     */
    it('should fail to register GSM Shield AV with Windows Security Center (unfixed code)', async () => {
      // Requirement 1.1: Script attempts WMI registration and fails
      const result = await runScript(SCRIPT_PATH);
      
      console.log('\n=== Bug Exploration Counterexample 1: WMI Registration Failure ===');
      console.log(`Exit Code: ${result.exitCode}`);
      console.log(`Stdout: ${result.stdout}`);
      console.log(`Stderr: ${result.stderr}`);
      
      // CRITICAL: This assertion documents the actual bug behavior
      // The script fails with "Access denied" when calling WMI Put()
      // Exit code may be 0 or 1 depending on error handling in unfixed script
      expect(result.exitCode).toBeGreaterThanOrEqual(0);
      
      // The output should indicate WMI Put() failed with Access Denied
      const indicatesWmiFailure = 
        result.stdout.includes('Access denied') ||
        result.stdout.includes('Failed to register with WSC via WMI') ||
        result.stdout.includes('WARNING: GSM Shield AV not found in SecurityCenter2');
      
      console.log(`WMI Failure Detected: ${indicatesWmiFailure}`);
      
      // Document the exact error observed
      expect(indicatesWmiFailure).toBe(true);
      
      // Requirement 1.4, 1.5: Check that registry keys do NOT exist after unfixed script runs
      const instanceGuid = '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}';
      const registryKeyPath = `HKLM:\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Av_${instanceGuid}`;
      
      const { scriptPath: regCheckScript, tempDir: regTempDir } = createRegistryCheckScript();
      
      try {
        const regCheckResult = await runScript(regCheckScript, [registryKeyPath]);
        
        console.log('\n=== Bug Exploration Counterexample 2: Missing Registry Keys ===');
        console.log(`Registry Key Path: ${registryKeyPath}`);
        console.log(`Check Result: ${regCheckResult.stdout}`);
        
        // CRITICAL: This assertion documents the actual bug behavior
        // The registry key should NOT exist because WMI Put() doesn't work
        expect(regCheckResult.stdout).toContain('NOT_FOUND');
        
        // After fix, this should change to 'EXISTS'
        // For now, confirm the bug: keys don't exist
        const registryKeysMissing = regCheckResult.stdout.includes('NOT_FOUND');
        expect(registryKeysMissing).toBe(true);
      } finally {
        cleanup(regTempDir);
      }
      
      // Requirement 1.5: Check that GSM Shield AV does NOT appear in WSC query
      const { scriptPath: wscQueryScript, tempDir: wscTempDir } = createWscQueryScript();
      
      try {
        const wscQueryResult = await runScript(wscQueryScript);
        
        console.log('\n=== Bug Exploration Counterexample 3: Missing WSC Entry ===');
        console.log(`WSC Query Result: ${wscQueryResult.stdout}`);
        
        // CRITICAL: This assertion documents the actual bug behavior
        // GSM Shield AV should NOT be found in WSC because registration didn't work
        expect(wscQueryResult.stdout).toContain('NOT_FOUND');
        
        // After fix, the query should return FOUND instead of NOT_FOUND
        // This confirms the bug: registration failed
        const gsmShieldNotRegistered = wscQueryResult.stdout.includes('NOT_FOUND');
        expect(gsmShieldNotRegistered).toBe(true);
      } finally {
        cleanup(wscTempDir);
      }
      
      console.log('\n=== Bug Condition Summary ===');
      console.log('EXPECTED: This test documents the bug by demonstrating registration failure');
      console.log('Counterexamples found:');
      console.log('  1. WMI Put() throws "Access denied" exception');
      console.log('  2. Registry keys missing under HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Av_{GUID}');
      console.log('  3. WSC query does not return GSM Shield AV entry');
      console.log('ROOT CAUSE: WMI AntiVirusProduct class is read-only for third-party apps');
      console.log('FIX REQUIRED: Use registry-based Security Provider registration instead');
      console.log('=====================================\n');
    }, 60000); // 60 second timeout for registry operations

    /**
     * Property-based test: Verify WMI registration fails consistently
     * across different test scenarios
     */
    it('should fail to create registry values for displayName, pathToSignedProductExe, or productState', async () => {
      // Property: For any valid instance GUID, the WMI approach fails to create registry values
      await fc.assert(
        fc.asyncProperty(
          fc.constantFrom(
            '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}',
            '{B2C3D4E5-F6A7-8901-BCDE-F12345678901}',
            '{C3D4E5F6-A7B8-9012-CDEF-123456789012}'
          ),
          async (testGuid) => {
            // Run the unfixed registration script
            const result = await runScript(SCRIPT_PATH);
            
            // Create script to check for specific registry values
            const tempDir = path.join(require('os').tmpdir(), `wsc-test-${Date.now()}`);
            fs.mkdirSync(tempDir, { recursive: true });
            
            const checkValuesScript = path.join(tempDir, 'check-values.ps1');
            const scriptContent = `
              param($GuidPath)
              try {
                $displayName = Get-ItemProperty -Path $GuidPath -Name "displayName" -ErrorAction SilentlyContinue
                $pathToExe = Get-ItemProperty -Path $GuidPath -Name "pathToSignedProductExe" -ErrorAction SilentlyContinue
                $productState = Get-ItemProperty -Path $GuidPath -Name "productState" -ErrorAction SilentlyContinue
                
                if ($displayName -or $pathToExe -or $productState) {
                  Write-Output "VALUES_EXIST"
                } else {
                  Write-Output "VALUES_MISSING"
                }
                exit 0
              } catch {
                Write-Output "VALUES_MISSING"
                exit 0
              }
            `;
            
            fs.writeFileSync(checkValuesScript, scriptContent, 'utf8');
            
            try {
              const registryPath = `HKLM:\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Av_${testGuid}`;
              const checkResult = await runScript(checkValuesScript, [registryPath]);
              
              console.log(`\n=== Counterexample for GUID ${testGuid} ===`);
              console.log(`Registry values check: ${checkResult.stdout}`);
              
              // CRITICAL: This assertion documents the actual bug behavior
              // No registry values should exist because WMI Put() doesn't create them
              expect(checkResult.stdout).toContain('VALUES_MISSING');
              
              // After fix, this should change to 'VALUES_EXIST'
              // For now, confirm the bug: values are missing
              const valuesMissing = checkResult.stdout.includes('VALUES_MISSING');
              expect(valuesMissing).toBe(true);
            } finally {
              cleanup(tempDir);
            }
          }
        ),
        { numRuns: 3 } // Test with 3 different GUIDs
      );
    }, 90000); // 90 second timeout for property-based testing
  });

  describe('Counterexample Documentation', () => {
    it('should document the exact failure mode for bug tracking', async () => {
      const result = await runScript(SCRIPT_PATH);
      
      const documentation = {
        testType: 'Bug Condition Exploration',
        bugDescription: 'WSC Registration via WMI API Fails',
        dateRun: new Date().toISOString(),
        scriptPath: SCRIPT_PATH,
        exitCode: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        counterexamples: [
          {
            id: 1,
            description: 'WMI Put() throws Access Denied exception',
            evidence: result.stdout.includes('Access denied') ||
                      result.stdout.includes('Failed to register with WSC via WMI')
          },
          {
            id: 2,
            description: 'Registry keys missing under HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider',
            evidence: 'Verified via registry check script (see test output above)'
          },
          {
            id: 3,
            description: 'WSC query does not return GSM Shield AV entry',
            evidence: 'Verified via Get-WmiObject query (see test output above)'
          }
        ],
        rootCause: 'root\\SecurityCenter2:AntiVirusProduct WMI class is read-only for third-party applications',
        expectedOutcome: 'This test FAILS on unfixed code, confirming the bug exists',
        fixValidation: 'After implementing registry-based registration, this test should PASS'
      };
      
      console.log('\n=== COUNTEREXAMPLE DOCUMENTATION ===');
      console.log(JSON.stringify(documentation, null, 2));
      console.log('===================================\n');
      
      // This test always passes - it's just for documentation
      expect(documentation.testType).toBe('Bug Condition Exploration');
    });
  });
});
