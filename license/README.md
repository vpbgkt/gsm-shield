# License Module

This module handles all licensing functionality for GSM Shield AV, including machine fingerprinting, Keygen.sh API integration, and encrypted license storage.

## Components

### machine-id.js
Generates a unique, consistent hardware fingerprint for the machine using CPU ID, disk serial, and MAC address.

```javascript
const { getMachineFingerprint } = require('./license/machine-id');

const fingerprint = await getMachineFingerprint();
// Returns: "a1b2c3d4e5f6..." (64-char SHA-256 hex string)
```

### keygen-client.js
Handles all communication with the Keygen.sh licensing API.

**Configuration**: Set these environment variables before running:
- `KEYGEN_ACCOUNT_ID`: Your Keygen.sh account ID
- `KEYGEN_VALIDATION_TOKEN`: A validation-scoped token (never use admin token!)

**Functions**:

#### activateLicense(key, fingerprint)
Activates a license key for this machine.

```javascript
const { activateLicense } = require('./license/keygen-client');

const result = await activateLicense('TEST-KEY-123', fingerprint);
if (result.success) {
  console.log('Activated:', result.token, result.expiresAt);
} else {
  console.error('Failed:', result.error, result.message);
}
```

#### validateLicense(token)
Validates a stored license token.

```javascript
const { validateLicense } = require('./license/keygen-client');

const result = await validateLicense(token);
if (result.success && result.valid) {
  console.log('License valid until:', result.expiresAt);
} else if (result.success && !result.valid) {
  console.log('License invalid:', result.error);
} else {
  console.log('Network error:', result.message);
}
```

#### deactivateLicense(token, fingerprint)
Deactivates a license for this machine.

```javascript
const { deactivateLicense } = require('./license/keygen-client');

const result = await deactivateLicense(token, fingerprint);
if (result.success) {
  console.log('License deactivated successfully');
} else {
  console.error('Deactivation failed:', result.error, result.message);
}
```

### license-store.js
Handles encrypted storage of license data in AppData.

**Storage location**: `%APPDATA%\GSMShieldAV\license.enc`

**Encryption**: AES-256-GCM with key derived from machine fingerprint

**Functions**:

```javascript
const { storeLicense, loadLicense, clearLicense } = require('./license/license-store');

// Store encrypted license
storeLicense({
  token: 'validation-token',
  expiresAt: '2025-12-31T23:59:59.000Z',
  storedAt: new Date().toISOString()
}, fingerprint);

// Load encrypted license
const licenseData = loadLicense(fingerprint);
if (licenseData) {
  console.log('Token:', licenseData.token);
}

// Clear stored license
clearLicense();
```

## Complete Workflow Example

```javascript
const license = require('./license');

async function activateAndStore(licenseKey) {
  // 1. Get machine fingerprint
  const fingerprint = await license.getMachineFingerprint();
  
  // 2. Activate with Keygen.sh
  const activationResult = await license.activateLicense(licenseKey, fingerprint);
  
  if (!activationResult.success) {
    throw new Error(`Activation failed: ${activationResult.message}`);
  }
  
  // 3. Store encrypted license
  license.storeLicense({
    token: activationResult.token,
    expiresAt: activationResult.expiresAt,
    storedAt: new Date().toISOString()
  }, fingerprint);
  
  return activationResult;
}

async function validateStored() {
  // 1. Get machine fingerprint
  const fingerprint = await license.getMachineFingerprint();
  
  // 2. Load stored license
  const stored = license.loadLicense(fingerprint);
  
  if (!stored) {
    return { valid: false, reason: 'NO_STORED_LICENSE' };
  }
  
  // 3. Check grace period (7 days)
  const storedDate = new Date(stored.storedAt);
  const daysSinceStored = (Date.now() - storedDate.getTime()) / (1000 * 60 * 60 * 24);
  
  // 4. Validate with Keygen.sh
  const validationResult = await license.validateLicense(stored.token);
  
  if (!validationResult.success && daysSinceStored < 7) {
    // Network error within grace period - allow
    return { valid: true, reason: 'GRACE_PERIOD', expiresAt: stored.expiresAt };
  }
  
  if (!validationResult.success) {
    // Network error after grace period - deny
    return { valid: false, reason: 'NETWORK_ERROR_EXPIRED' };
  }
  
  // Return validation result
  return {
    valid: validationResult.valid,
    expiresAt: validationResult.expiresAt,
    reason: validationResult.valid ? 'VALID' : validationResult.error
  };
}
```

## Error Handling

All functions return structured results instead of throwing errors. This ensures the application never crashes due to network issues.

**Success response**:
```javascript
{
  success: true,
  // ... function-specific data
}
```

**Error response**:
```javascript
{
  success: false,
  error: 'ERROR_CODE',
  message: 'Human-readable error message',
  details: '...' // Optional additional details
}
```

## Requirements Satisfied

- **Requirement 19.3**: License activation with key and machine fingerprint via Keygen.sh API
- **Requirement 20.1**: Silent license validation at application startup
- **Requirement 20.4**: No admin token embedded; validation-scoped token only
- **Requirement 25.2**: Network errors return structured results (never throw)

## Testing

Run all license module tests:
```bash
npm test -- license/
```

Run specific test files:
```bash
npm test -- license/keygen-client.test.js
npm test -- license/__tests__/keygen-client.integration.test.js
npm test -- license/machine-id.test.js
npm test -- license/license-store.test.js
```
