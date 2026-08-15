# License IPC Handlers

## Overview

The license IPC handlers module (`electron/ipc/license-handlers.js`) provides the bridge between the renderer process and the license subsystem. It implements three main IPC channels for managing software licensing through Keygen.sh.

## Requirements Satisfied

- **Requirement 19.2**: License page displays status, expiry date, and machine fingerprint
- **Requirement 19.3**: License activation with key and machine fingerprint sent to Keygen.sh
- **Requirement 19.4**: Store encrypted license token (AES-256) and update gates immediately
- **Requirement 19.5**: License deactivation removes machine from license and clears stored token
- **Requirement 20.1**: Silent license validation at application startup
- **Requirement 20.2**: 7-day grace period when API unreachable
- **Requirement 20.3**: Feature gates applied when license inactive
- **Requirement 20.5**: Feature gates removed immediately on activation (no restart required)

## IPC Channels

### `license:status`

**Direction**: Invoke (renderer → main)

**Parameters**: None

**Returns**:
```javascript
{
  status: 'active' | 'inactive' | 'grace',
  expiresAt: string | null,        // ISO 8601 date
  fingerprint: string,              // 64-char hex SHA-256
  gates: {
    scanLimit: boolean,             // true = limited to 50 results/1 folder
    whitelistCap: boolean,          // true = limited to 10 user entries
    realtimeDisabled: boolean       // true = real-time protection disabled
  }
}
```

**Description**: Returns the current license status, expiry date, machine fingerprint, and feature gate state. This is used by the License page to display license information to the user.

---

### `license:activate`

**Direction**: Invoke (renderer → main)

**Parameters**:
```javascript
{
  key: string  // License key entered by user
}
```

**Returns**:
```javascript
{
  success: boolean,
  status?: 'active',
  expiresAt?: string,
  error?: string,
  message?: string
}
```

**Description**: Activates a license key with Keygen.sh by:
1. Getting the machine fingerprint
2. Calling Keygen.sh activation API with key and fingerprint
3. Storing the encrypted license token in `AppData/GSMShieldAV/license.enc`
4. Clearing all feature gates immediately (no restart required)
5. Pushing `license:updated` event to renderer

**Side Effects**:
- Creates encrypted license file in AppData
- Updates feature gates
- Sends `license:updated` push event to renderer

---

### `license:deactivate`

**Direction**: Invoke (renderer → main)

**Parameters**: None

**Returns**:
```javascript
{
  success: boolean,
  message?: string,
  warning?: string  // If API call failed but local clear succeeded
}
```

**Description**: Deactivates the current license by:
1. Getting the machine fingerprint
2. Loading the stored license token
3. Calling Keygen.sh deactivation API
4. Clearing the stored license file (even if API call fails)
5. Re-applying all feature gates
6. Pushing `license:updated` event to renderer

**Side Effects**:
- Deletes encrypted license file from AppData
- Re-applies feature gates
- Sends `license:updated` push event to renderer

---

## Push Events

### `license:updated`

**Direction**: Push (main → renderer)

**Payload**:
```javascript
{
  status: 'active' | 'inactive' | 'grace',
  gates: {
    scanLimit: boolean,
    whitelistCap: boolean,
    realtimeDisabled: boolean
  }
}
```

**Description**: Sent from main to renderer whenever the license status changes (activation, deactivation, or validation). The renderer should update the UI to reflect the new license state and feature gate restrictions.

---

## Feature Gates

When a license is **inactive**, the following restrictions are applied:

1. **scanLimit**: Scanning is limited to 1 folder with a maximum of 50 results
2. **whitelistCap**: User-added whitelist entries are capped at 10
3. **realtimeDisabled**: Real-time file system protection is disabled

When a license is **active** or in **grace period**, all gates are set to `false` (no restrictions).

### Grace Period

When the Keygen.sh API is unreachable and a valid license token was stored within the last 7 days, the license enters "grace" status. During grace period, all feature gates are cleared, allowing full operation without network connectivity.

After 7 days without successful API validation, the license transitions to "inactive" and feature gates are applied.

---

## Module Integration

### Registration in main.js

```javascript
const licenseHandlers = require('./ipc/license-handlers');

licenseHandlers.register(ipcMain, {
  getMainWindow: () => mainWindow
});
```

### Exports for Other Modules

The module exports two functions for use by other parts of the application:

1. **`getFeatureGates()`**: Returns current feature gate state for use by scanner, whitelist, and monitor modules
2. **`refreshLicenseState(fingerprint)`**: Validates stored license and updates state (used by main.js on startup)

### Usage Example

```javascript
const { getFeatureGates } = require('./electron/ipc/license-handlers');

// In scanner module
const gates = getFeatureGates();
if (gates.scanLimit) {
  // Apply scan result limit
}

// In whitelist module
const gates = getFeatureGates();
if (gates.whitelistCap) {
  // Check user entry count
}
```

---

## Dependencies

- `license/machine-id.js`: Machine fingerprint generation (SHA-256 of hardware ID)
- `license/keygen-client.js`: Keygen.sh API calls (activate, validate, deactivate)
- `license/license-store.js`: AES-256-GCM encrypted license storage

---

## Testing

The module has comprehensive test coverage:

- **Unit tests** (`__tests__/license-handlers.test.js`): 13 tests covering all IPC channels with mocked dependencies
- **Integration tests** (`__tests__/license-handlers.integration.test.js`): 12 tests with real license modules

All 25 tests pass successfully.

### Running Tests

```bash
npm test -- electron/ipc/__tests__/license-handlers
```

---

## Error Handling

All IPC handlers are wrapped in try-catch blocks. Errors are logged and returned as structured error responses:

```javascript
{
  success: false,
  error: 'ERROR_CODE',
  message: 'Human-readable error message'
}
```

Network errors during activation/deactivation do not throw exceptions — they return structured error results that the renderer can display to the user.

---

## Security Considerations

1. **No admin token**: The application only uses validation-scoped Keygen.sh tokens, never admin tokens
2. **Encrypted storage**: License tokens are encrypted using AES-256-GCM with key derived from machine fingerprint
3. **Machine-bound**: Licenses are tied to specific hardware via SHA-256 fingerprint
4. **Grace period**: Prevents complete lockout during temporary network issues

---

## Future Enhancements

- Automatic license renewal notifications when approaching expiry
- License transfer workflow (deactivate old machine, activate new machine)
- Offline license activation via manual token entry
- Multi-seat license support with seat count display
