const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Non-secret constant salt (part of key derivation, not the scrypt salt)
const APP_SALT = 'gsm-shield-av-2024';

// License storage path
function getLicenseStorePath() {
  const appDataDir = path.join(os.homedir(), 'AppData', 'Roaming', 'GSMShieldAV');
  
  // Ensure directory exists
  if (!fs.existsSync(appDataDir)) {
    fs.mkdirSync(appDataDir, { recursive: true });
  }
  
  return path.join(appDataDir, 'license.enc');
}

/**
 * Derive encryption key from machine fingerprint
 * @param {string} machineFingerprint - Machine fingerprint from machine-id.js
 * @returns {Buffer} 32-byte AES-256 key
 */
function deriveKey(machineFingerprint) {
  const material = machineFingerprint + APP_SALT;
  // Use scryptSync with fixed salt for deterministic key derivation
  return crypto.scryptSync(material, 'gsm-shield-salt', 32);
}

/**
 * Store encrypted license data
 * @param {Object} licenseData - License data to store
 * @param {string} licenseData.token - Keygen.sh validation token
 * @param {string} licenseData.expiresAt - ISO 8601 expiry date
 * @param {string} licenseData.storedAt - ISO 8601 storage timestamp
 * @param {string} machineFingerprint - Machine fingerprint for key derivation
 * @throws {Error} If encryption or file write fails
 */
function storeLicense(licenseData, machineFingerprint) {
  try {
    // Validate input
    if (!licenseData || !licenseData.token || !licenseData.expiresAt || !licenseData.storedAt) {
      throw new Error('Invalid license data: missing required fields');
    }
    
    if (!machineFingerprint) {
      throw new Error('Machine fingerprint is required');
    }
    
    // Derive encryption key
    const key = deriveKey(machineFingerprint);
    
    // Generate random 12-byte IV for GCM
    const iv = crypto.randomBytes(12);
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // Encrypt license data as JSON
    const plaintext = JSON.stringify(licenseData);
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // Get auth tag
    const authTag = cipher.getAuthTag();
    
    // Prepend IV (12 bytes), then auth tag (16 bytes), then ciphertext
    const combined = Buffer.concat([iv, authTag, encrypted]);
    
    // Encode as base64 and write to file
    const base64Data = combined.toString('base64');
    const storePath = getLicenseStorePath();
    
    fs.writeFileSync(storePath, base64Data, 'utf8');
    
  } catch (error) {
    throw new Error(`Failed to store license: ${error.message}`);
  }
}

/**
 * Load and decrypt license data
 * @param {string} machineFingerprint - Machine fingerprint for key derivation
 * @returns {Object|null} License data or null on any error
 * @returns {string} return.token - Keygen.sh validation token
 * @returns {string} return.expiresAt - ISO 8601 expiry date
 * @returns {string} return.storedAt - ISO 8601 storage timestamp
 */
function loadLicense(machineFingerprint) {
  try {
    const storePath = getLicenseStorePath();
    
    // Check if file exists
    if (!fs.existsSync(storePath)) {
      return null;
    }
    
    if (!machineFingerprint) {
      return null;
    }
    
    // Read and decode base64
    const base64Data = fs.readFileSync(storePath, 'utf8');
    const combined = Buffer.from(base64Data, 'base64');
    
    // Extract IV (first 12 bytes), auth tag (next 16 bytes), and ciphertext
    if (combined.length < 28) {
      // Invalid format: too short to contain IV + auth tag
      return null;
    }
    
    const iv = combined.slice(0, 12);
    const authTag = combined.slice(12, 28);
    const encrypted = combined.slice(28);
    
    // Derive decryption key
    const key = deriveKey(machineFingerprint);
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    // Parse JSON
    const licenseData = JSON.parse(decrypted.toString('utf8'));
    
    // Validate structure
    if (!licenseData.token || !licenseData.expiresAt || !licenseData.storedAt) {
      return null;
    }
    
    return licenseData;
    
  } catch (error) {
    // Return null on any error (corrupt file, wrong key, invalid JSON, etc.)
    return null;
  }
}

/**
 * Clear stored license by deleting the encrypted file
 */
function clearLicense() {
  try {
    const storePath = getLicenseStorePath();
    
    if (fs.existsSync(storePath)) {
      fs.unlinkSync(storePath);
    }
  } catch (error) {
    // Silently fail - file might already be deleted or inaccessible
  }
}

module.exports = {
  storeLicense,
  loadLicense,
  clearLicense,
  // Export for testing
  _deriveKey: deriveKey,
  _getLicenseStorePath: getLicenseStorePath
};
