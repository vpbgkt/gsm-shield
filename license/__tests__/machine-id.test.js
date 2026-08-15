/**
 * Tests for license/machine-id.js
 */

const { getMachineFingerprint } = require('../machine-id');
const crypto = require('crypto');

describe('machine-id', () => {
  describe('getMachineFingerprint', () => {
    test('returns a 64-character hex string', async () => {
      const fingerprint = await getMachineFingerprint();
      
      // Should be exactly 64 characters (SHA-256 produces 32 bytes = 64 hex chars)
      expect(fingerprint).toHaveLength(64);
      
      // Should be valid hexadecimal
      expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
    });

    test('returns consistent fingerprint on multiple calls', async () => {
      const fingerprint1 = await getMachineFingerprint();
      const fingerprint2 = await getMachineFingerprint();
      
      // Same machine should always produce the same fingerprint
      expect(fingerprint1).toBe(fingerprint2);
    });

    test('fingerprint is a valid SHA-256 hash', async () => {
      const fingerprint = await getMachineFingerprint();
      
      // Should be lowercase
      expect(fingerprint).toBe(fingerprint.toLowerCase());
      
      // Should be exactly the length of SHA-256 output
      const hashBuffer = Buffer.from(fingerprint, 'hex');
      expect(hashBuffer.length).toBe(32); // 32 bytes = 256 bits
    });

    test('fingerprint is deterministic', async () => {
      // Call multiple times in sequence
      const fingerprints = await Promise.all([
        getMachineFingerprint(),
        getMachineFingerprint(),
        getMachineFingerprint(),
        getMachineFingerprint(),
        getMachineFingerprint()
      ]);
      
      // All should be identical
      const uniqueFingerprints = new Set(fingerprints);
      expect(uniqueFingerprints.size).toBe(1);
    });

    test('fingerprint is not empty', async () => {
      const fingerprint = await getMachineFingerprint();
      
      expect(fingerprint).not.toBe('');
      expect(fingerprint).not.toBe('0'.repeat(64));
    });

    test('validates SHA-256 hashing of hardware ID', async () => {
      // We can't mock node-machine-id's machineId directly, but we can verify
      // that the output is a proper SHA-256 hash by checking its characteristics
      const fingerprint = await getMachineFingerprint();
      
      // Verify it's a valid hex string that could be a SHA-256 hash
      expect(() => {
        Buffer.from(fingerprint, 'hex');
      }).not.toThrow();
      
      // Verify the hash entropy is reasonable (not all zeros, not all same char)
      const chars = new Set(fingerprint.split(''));
      expect(chars.size).toBeGreaterThan(4); // Should have variety in characters
    });
  });
});
