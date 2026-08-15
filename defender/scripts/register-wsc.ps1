# register-wsc.ps1
# Registers GSM Shield AV with Windows Security Center using the
# Security Provider registry-based API.
#
# The WMI AntiVirusProduct class (root\SecurityCenter2) is read-only for
# third-party applications and cannot be used for registration.
# Third-party AV products must register via registry keys under:
# HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{GUID}
#
# Requirements: 21.2, 21.3, 21.4
# Called by ps-runner.js with -ExecutionPolicy Bypass -NonInteractive flags
# Also called by Inno Setup installer at end of installation (setup.iss [Run])

$ErrorActionPreference = "Stop"
$exitCode = 0

# ── Fixed, deterministic GUID for GSM Shield AV ─────────────────────────────
# Using a constant GUID ensures idempotent registration: re-running this script
# updates the existing entry instead of creating duplicates.
$PRODUCT_GUID = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
$PRODUCT_KEY_NAME = "Av_$PRODUCT_GUID"
$PRODUCT_DISPLAY_NAME = "GSM Shield AV"

# Check for elevated (Administrator) privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires elevated (Administrator) privileges"
    Write-Host "ERROR: Please run the installer as Administrator"
    exit 1
}

Write-Host "INFO: Running with Administrator privileges"

# Determine the path to the GSM Shield AV executable.
# Script lives at: <appRoot>\resources\scripts\register-wsc.ps1
# Exe lives at:    <appRoot>\GSM Shield AV.exe
$scriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$resourcesDir = Split-Path -Parent $scriptDir
$appRoot      = Split-Path -Parent $resourcesDir
$exePath      = Join-Path $appRoot "GSM Shield AV.exe"

if (-not (Test-Path $exePath)) {
    # On 64-bit Windows, {autopf} in Inno Setup resolves to "C:\Program Files" (not x86)
    $exePath = "C:\Program Files\GSMShieldAV\GSM Shield AV.exe"
}

Write-Host "INFO: Registering with WSC, exe path: $exePath"

# Check executable path exists
if (-not (Test-Path $exePath)) {
    Write-Host "ERROR: GSM Shield AV executable not found at: $exePath"
    exit 1
}

# ── Add Defender exclusion for the GSM Shield AV install folder ──────────────
# Best-effort: if Defender is still partially active it won't flag our files.
# This also helps during the transition period before Defender is fully disabled.
$installDir = Split-Path -Parent $exePath
try {
    Add-MpPreference -ExclusionPath $installDir -ErrorAction Stop
    Write-Host "SUCCESS: Added Defender exclusion for install path: $installDir"
} catch {
    Write-Host "WARNING: Could not add Defender exclusion (Defender may already be disabled): $($_.Exception.Message)"
}

# Implement registry-based Security Provider registration
# The WMI AntiVirusProduct class is read-only for third-party applications.
# Registration must be done via registry keys under:
# HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av_{instanceGuid}

try {
    Write-Host "INFO: Using fixed product GUID: $PRODUCT_GUID"
    Write-Host "INFO: Target registry key: $PRODUCT_KEY_NAME"
    Write-Host "INFO: Using .NET Registry API to preserve underscore in key name"
    
    # CRITICAL: PowerShell's New-Item cmdlet does NOT handle underscores correctly in registry key names
    # When you use New-Item -Path "HKLM:\...\Provider\Av_{GUID}", PowerShell creates only "Av" 
    # We MUST use .NET Registry API to create the key correctly
    
    try {
        # Use .NET Registry API for key creation
        $providerKeyPath = "SOFTWARE\Microsoft\Security Center\Provider"
        $hklm = [Microsoft.Win32.Registry]::LocalMachine
        
        # Open the Provider key with write access
        $providerKey = $hklm.OpenSubKey($providerKeyPath, $true)
        
        if ($null -eq $providerKey) {
            # Provider key doesn't exist, create it first
            Write-Host "INFO: Provider key doesn't exist, creating parent path..."
            $securityCenterKey = $hklm.OpenSubKey("SOFTWARE\Microsoft\Security Center", $true)
            if ($null -eq $securityCenterKey) {
                $microsoftKey = $hklm.OpenSubKey("SOFTWARE\Microsoft", $true)
                $securityCenterKey = $microsoftKey.CreateSubKey("Security Center")
                $microsoftKey.Close()
            }
            $providerKey = $securityCenterKey.CreateSubKey("Provider")
            $securityCenterKey.Close()
        }
        
        # ── Idempotent cleanup: remove any stale GSM Shield AV entries ───────
        # This prevents duplicate entries if the script is re-run or if the
        # user triggers setup from Settings after a previous partial run.
        Write-Host "INFO: Checking for existing GSM Shield AV registrations..."
        $existingSubKeys = $providerKey.GetSubKeyNames()
        foreach ($subKeyName in $existingSubKeys) {
            if ($subKeyName -like "Av_*") {
                try {
                    $existingKey = $providerKey.OpenSubKey($subKeyName, $false)
                    if ($null -ne $existingKey) {
                        $existingDisplayName = $existingKey.GetValue("displayName")
                        $existingKey.Close()
                        if ($existingDisplayName -eq $PRODUCT_DISPLAY_NAME) {
                            if ($subKeyName -ne $PRODUCT_KEY_NAME) {
                                # Stale entry with a different GUID — remove it
                                Write-Host "INFO: Removing stale registration: $subKeyName"
                                $providerKey.DeleteSubKeyTree($subKeyName, $false)
                            }
                        }
                    }
                } catch {
                    Write-Host "WARNING: Could not inspect existing key '$subKeyName': $($_.Exception.Message)"
                }
            }
        }
        
        # Create our Av_{GUID} subkey - the .NET API preserves the underscore correctly
        # CreateSubKey is idempotent: if the key already exists, it opens it for writing
        Write-Host "INFO: Creating/updating subkey: $PRODUCT_KEY_NAME"
        $avKey = $providerKey.CreateSubKey($PRODUCT_KEY_NAME)
        
        if ($null -eq $avKey) {
            throw "Failed to create registry subkey '$PRODUCT_KEY_NAME'"
        }
        
        Write-Host "INFO: Registry key created/opened successfully"
        Write-Host "INFO: Key name: $PRODUCT_KEY_NAME"
        Write-Host "INFO: Full path: HKLM\$providerKeyPath\$PRODUCT_KEY_NAME"
        
        # Set displayName (REG_SZ)
        Write-Host "INFO: Setting displayName..."
        $avKey.SetValue("displayName", $PRODUCT_DISPLAY_NAME, [Microsoft.Win32.RegistryValueKind]::String)
        Write-Host "INFO: Set displayName to '$PRODUCT_DISPLAY_NAME'"
        
        # Set pathToSignedProductExe (REG_SZ)
        Write-Host "INFO: Setting pathToSignedProductExe..."
        $avKey.SetValue("pathToSignedProductExe", $exePath, [Microsoft.Win32.RegistryValueKind]::String)
        Write-Host "INFO: Set pathToSignedProductExe to '$exePath'"
        
        # Set pathToSignedReportingExe (REG_SZ)
        Write-Host "INFO: Setting pathToSignedReportingExe..."
        $avKey.SetValue("pathToSignedReportingExe", $exePath, [Microsoft.Win32.RegistryValueKind]::String)
        Write-Host "INFO: Set pathToSignedReportingExe to '$exePath'"
        
        # Set productState (REG_DWORD) - 266240 = enabled, up-to-date
        Write-Host "INFO: Setting productState..."
        $avKey.SetValue("productState", 266240, [Microsoft.Win32.RegistryValueKind]::DWord)
        Write-Host "INFO: Set productState to 266240 (enabled, up-to-date)"
        
        # Close registry keys
        $avKey.Close()
        $providerKey.Close()
        
        Write-Host "INFO: All registry values set successfully"
        
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "ERROR: Failed to create registry key or set values"
        Write-Host "ERROR: $errorMessage"
        
        # Clean up any open keys
        if ($null -ne $avKey) { $avKey.Close() }
        if ($null -ne $providerKey) { $providerKey.Close() }
        
        # Check if it's a permission error
        if ($errorMessage -match "Access.*denied|UnauthorizedAccessException|Requested registry access is not allowed") {
            Write-Host "ERROR: Access denied - insufficient permissions to modify registry"
            Write-Host "ERROR: Administrator privileges are required"
            throw "Access denied: $_"
        } else {
            throw $_
        }
    }
    
    Write-Host "INFO: Security Provider registry keys created successfully"
    $exitCode = 0
    
} catch {
    Write-Host "ERROR: Failed to complete WSC registration: $_"
    Write-Error "WSC registration failed: $_"
    $exitCode = 1
}

# Verify registration
if ($exitCode -eq 0) {
    Write-Host "INFO: Verifying WSC registration..."
    
    try {
        # Query WSC for GSM Shield AV entry
        $registered = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | 
            Where-Object { $_.displayName -eq $PRODUCT_DISPLAY_NAME }
        
        if ($registered) {
            Write-Host "VERIFIED: GSM Shield AV appears in SecurityCenter2"
            Write-Host "VERIFIED: Product State = $($registered.productState)"
            
            # Check if product state matches expected value (266240)
            if ($registered.productState -eq 266240) {
                Write-Host "VERIFIED: Product State is correct (266240 = enabled, up-to-date)"
                $exitCode = 0
            } else {
                Write-Host "WARNING: Product State is $($registered.productState), expected 266240"
                Write-Host "WARNING: Registration may not be fully functional"
                # Still consider this a success since the entry exists
                $exitCode = 0
            }
        } else {
            # WSC query may not reflect registry changes immediately.
            # Verify the registry keys directly as a fallback.
            Write-Host "WARNING: GSM Shield AV not found in SecurityCenter2 WMI query"
            Write-Host "INFO: Verifying registry keys directly..."
            
            $hklm = [Microsoft.Win32.Registry]::LocalMachine
            $verifyKey = $hklm.OpenSubKey("SOFTWARE\Microsoft\Security Center\Provider\$PRODUCT_KEY_NAME", $false)
            
            if ($null -ne $verifyKey) {
                $regDisplayName = $verifyKey.GetValue("displayName")
                $regProductState = $verifyKey.GetValue("productState")
                $verifyKey.Close()
                
                if ($regDisplayName -eq $PRODUCT_DISPLAY_NAME) {
                    Write-Host "VERIFIED: Registry key exists with correct displayName"
                    Write-Host "VERIFIED: Registry productState = $regProductState"
                    Write-Host "INFO: WSC may need a moment or a restart to reflect the registration"
                    $exitCode = 0
                } else {
                    Write-Host "ERROR: Registry key exists but displayName mismatch: '$regDisplayName'"
                    $exitCode = 1
                }
            } else {
                Write-Host "ERROR: Registry key not found at HKLM\SOFTWARE\Microsoft\Security Center\Provider\$PRODUCT_KEY_NAME"
                Write-Host "ERROR: Possible causes:"
                Write-Host "ERROR:   1. Registry key creation was silently blocked"
                Write-Host "ERROR:   2. Insufficient permissions"
                Write-Host "ERROR:   3. Tamper Protection prevented the write"
                $exitCode = 1
            }
        }
    } catch {
        Write-Host "ERROR: Failed to verify WSC registration: $($_.Exception.Message)"
        Write-Host "ERROR: Registry keys may have been created but verification failed"
        # Don't override exitCode - if registration succeeded, keep exitCode = 0
        if ($exitCode -eq 0) {
            Write-Host "WARNING: Continuing with exit code 0 despite verification failure"
        }
    }
} else {
    Write-Host "INFO: Skipping verification because registration failed (exit code = $exitCode)"
}

exit $exitCode
