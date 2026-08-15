'use strict';

const crypto = require('crypto');
const fs = require('fs');

/**
 * Streams a file through SHA-256 and returns the hex digest.
 *
 * @param {string} filePath - Absolute or relative path to the file.
 * @returns {Promise<string>} Resolves with the lowercase hex SHA-256 hash.
 */
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);

    stream.on('error', (err) => {
      if (err.code === 'ENOENT') {
        reject(new Error(`File not found: ${filePath}`));
      } else if (err.code === 'EACCES') {
        reject(new Error(`Permission denied: ${filePath}`));
      } else {
        reject(err);
      }
    });

    stream.on('data', (chunk) => hash.update(chunk));

    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Synchronously hashes an in-memory buffer with SHA-256.
 *
 * @param {Buffer|string} buffer - Data to hash.
 * @returns {string} Lowercase hex SHA-256 digest.
 */
function hashBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

module.exports = { hashFile, hashBuffer };
