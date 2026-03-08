'use strict';

/**
 * Minimal BN254 point helpers.
 * Points are passed as hex strings to/from the Rust native addon.
 */

function pointToHex(point) {
  if (typeof point === 'string') return point;
  if (Buffer.isBuffer(point)) return point.toString('hex');
  if (typeof point === 'object') return Buffer.from(JSON.stringify(point)).toString('hex');
  return String(point);
}

function hexToPoint(hex) {
  if (typeof hex !== 'string') return hex;
  try {
    return JSON.parse(Buffer.from(hex, 'hex').toString());
  } catch {
    return hex;
  }
}

module.exports = { pointToHex, hexToPoint };
