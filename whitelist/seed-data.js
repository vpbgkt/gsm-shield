'use strict';

/**
 * whitelist/seed-data.js
 *
 * Pre-built GSM tool whitelist entries bundled with GSM Shield AV.
 *
 * IMPORTANT — PLACEHOLDER HASHES:
 * The `hash` values below are placeholder zero-hashes. They are intentionally
 * unique (index padded into the first characters) so they satisfy the PRIMARY
 * KEY uniqueness constraint in SQLite, but they are NOT real SHA-256 digests.
 *
 * Populating real hashes is a MANUAL DATA-COLLECTION STEP that requires the
 * team to physically obtain each tool's installer/executable and run
 * `hashFile()` (whitelist/hasher.js) against it. Replace each placeholder
 * with the corresponding real value before shipping.
 *
 * Format of each entry:
 *   hash     {string}  64-char hex SHA-256 (placeholder until manually collected)
 *   name     {string}  Human-readable tool name
 *   vendor   {string}  Vendor / publisher name
 *   verified {number}  1 — pre-built/bundled, treated as verified by GSM Shield
 *   source   {string}  'bundled' — identifies this as a shipped whitelist entry
 */

/**
 * Generates a unique placeholder hash for a given index.
 * The index is zero-padded and placed at the start of the 64-character string
 * so every entry has a distinct primary key value.
 *
 * @param {number} index  Zero-based position in the seed array (0–19)
 * @returns {string} 64-character placeholder hex string
 */
function placeholderHash(index) {
  // Format index as 2 hex digits, then pad the rest with zeros
  const prefix = index.toString(16).padStart(2, '0');
  return prefix + '0'.repeat(62);
}

/** @type {Array<{ hash: string, name: string, vendor: string, verified: number, source: string }>} */
const SEED_ENTRIES = [
  {
    hash: placeholderHash(0),
    name: 'Odin3',
    vendor: 'Samsung',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(1),
    name: 'SP Flash Tool',
    vendor: 'MediaTek',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(2),
    name: 'Miracle Box',
    vendor: 'Miracle Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(3),
    name: 'UFI Box',
    vendor: 'UFI Soft',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(4),
    name: 'NCK Box',
    vendor: 'NCK Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(5),
    name: 'Z3X Pro',
    vendor: 'Z3X Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(6),
    name: 'Infinity CM2',
    vendor: 'Infinity-Box Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(7),
    name: 'Chimera Tool',
    vendor: 'Chimera Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(8),
    name: 'MRT Dongle',
    vendor: 'MRT Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(9),
    name: 'EFT Pro Dongle',
    vendor: 'EFT Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(10),
    name: 'Hydra Tool',
    vendor: 'Hydra Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(11),
    name: 'Pandora Box',
    vendor: 'Pandora Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(12),
    name: 'Volcano Box',
    vendor: 'Volcano Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(13),
    name: 'GPG Dragon',
    vendor: 'GPG Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(14),
    name: 'Sigma Box',
    vendor: 'Sigma Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(15),
    name: 'Furious Gold',
    vendor: 'Furious Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(16),
    name: 'ATF Box',
    vendor: 'ATF Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(17),
    name: 'Easy JTAG',
    vendor: 'Z3X Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(18),
    name: 'Riff Box',
    vendor: 'RIFF Team',
    verified: 1,
    source: 'bundled',
  },
  {
    hash: placeholderHash(19),
    name: 'Falcon Box',
    vendor: 'Falcon Team',
    verified: 1,
    source: 'bundled',
  },
];

module.exports = SEED_ENTRIES;
