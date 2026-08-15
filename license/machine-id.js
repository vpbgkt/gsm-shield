/**
 * license/machine-id.js
 * 
 * Hardware fingerprint derivation for license binding.
 * Generates a consistent machine fingerprint by hashing the hardware ID.
 */

const { machineId } = require('node-machine-id');
const crypto = require('crypto');

/**
 * Get a unique hardware fingerprint for this machine.
 * 
 * Uses node-machine-id to retrieve the hardware ID (CPU ID, disk serial, MAC address),
 * then SHA-256 hashes the result to produce a consistent 64-character hex string.
 * 
 * @returns {Promise<string>} 64-character hexadecimal string (SHA-256 hash)
 */
async function getMachineFingerprint() {
  try {
    // Get hardware ID from node-machine-id
    const hwId = await machineId();
    
    // Hash the hardware ID using SHA-256
    const hash = crypto.createHash('sha256')
      .update(hwId)
      .digest('hex');
    
    return hash;
  } catch (error) {
    // If we fail to get machine ID, throw a descriptive error
    throw new Error(`Failed to generate machine fingerprint: ${error.message}`);
  }
}

module.exports = {
  getMachineFingerprint
};
