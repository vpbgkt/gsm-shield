/**
 * license/index.js
 * 
 * Main export file for the license subsystem.
 * Aggregates all license-related functionality.
 */

const { getMachineFingerprint } = require('./machine-id');
const { activateLicense, validateLicense, deactivateLicense } = require('./keygen-client');
const { storeLicense, loadLicense, clearLicense } = require('./license-store');

module.exports = {
  // Machine fingerprinting
  getMachineFingerprint,
  
  // Keygen.sh API calls
  activateLicense,
  validateLicense,
  deactivateLicense,
  
  // License storage
  storeLicense,
  loadLicense,
  clearLicense
};
