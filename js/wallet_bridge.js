/**
 * wallet_bridge.js
 *
 * JavaScript bridge between wallet.js and the Rust native addon.
 *
 * Usage:
 *   const bridge = require('./wallet_bridge');
 *   bridge.init();
 *
 *   const { pkXHex, pkYsHex, skXHex, skYsHex } = bridge.psKeygen(5);
 *   const sig = bridge.psSign(['Priya', '26', 'India', '850000', 'Kolkata'], skXHex, skYsHex);
 *
 *   bridge.storePSCredential('govt_id', {
 *     attributes:      { name: 'Priya', age: '26', country: 'India', income: '850000', city: 'Kolkata' },
 *     attribute_order: ['name', 'age', 'country', 'income', 'city'],
 *     sigma1_hex:      sig.sigma1Hex,
 *     sigma2_hex:      sig.sigma2Hex,
 *     pk_x_hex:        pkXHex,
 *     pk_ys_hex:       pkYsHex,
 *   });
 *
 *   const { proof, proofId } = bridge.generateNIZKProof('govt_id', ['country'], 'bank', challenge);
 *   const result = bridge.verifyNIZKProof(proof, challenge, pkXHex, pkYsHex);
 *
 * Build instructions (run once):
 *   cd wallet_rs
 *   npm install
 *   npm run build          # debug
 *   npm run build-release  # production (faster)
 */

'use strict';

// ─── Load the native Rust addon ───────────────────────────────────────────────
// After `npm run build`, neon places the .node file at:
//   wallet_rs/index.node

let native;
try {
  native = require('./wallet_rs/index.node');
} catch (e) {
  throw new Error(
    '[wallet_bridge] Failed to load Rust addon.\n' +
    'Run:  cd wallet_rs && npm install && npm run build\n' +
    'Original error: ' + e.message
  );
}

// ─── Bridge API ───────────────────────────────────────────────────────────────

/**
 * Initialise the Rust wallet. Call once at startup.
 */
function init() {
  return native.walletInit();
}

/**
 * Generate a PS keypair for `l` attributes.
 * Returns { pkXHex, pkYsHex, skXHex, skYsHex, l }
 *
 * pkXHex, pkYsHex  → share with verifiers (issuer public key)
 * skXHex, skYsHex  → issuer keeps these secret to sign credentials
 */
function psKeygen(l) {
  const result = native.psKeygen(l);
  return {
    pkXHex  : result.pkX,
    pkYsHex : Array.from({ length: l }, (_, i) => result.pkYs[i]),
    skXHex  : result.skX,
    skYsHex : Array.from({ length: l }, (_, i) => result.skYs[i]),
    l,
  };
}

/**
 * Sign attribute values with the issuer's PS secret key.
 * messages[] must be in the SAME ORDER as attributeOrder.
 * Values are passed as strings — Rust hashes them to field scalars.
 *
 * Returns { sigma1Hex, sigma2Hex }
 */
function psSign(messages, skXHex, skYsHex) {
  return native.psSign(messages, skXHex, skYsHex);
}

/**
 * Store a PS-signed credential in the Rust wallet.
 *
 * @param {string} credentialId
 * @param {object} credential
 *   {
 *     attributes:      { [key]: string },   ← ALL values must be strings
 *     attribute_order: string[],
 *     sigma1_hex:      string,
 *     sigma2_hex:      string,
 *     pk_x_hex:        string,
 *     pk_ys_hex:       string[],
 *   }
 *
 * Rust computes C_i = m_i*G + r_i*H per attribute and stores them.
 */
function storePSCredential(credentialId, credential) {
  // Ensure all attribute values are strings
  const sanitised = { ...credential };
  sanitised.attributes = Object.fromEntries(
    Object.entries(credential.attributes).map(([k, v]) => [k, String(v)])
  );
  return native.storePSCredential(credentialId, JSON.stringify(sanitised));
}

/**
 * Retrieve stored per-attribute Pedersen commitments.
 * Returns { [attributeKey]: hexCommitment }
 * Safe to share with verifiers.
 */
function getAttributeCommitments(credentialId) {
  return native.getAttributeCommitments(credentialId);
}

/**
 * Generate a NIZK sigma proof for a PS credential with selective disclosure.
 *
 * REVEALED attributes → plaintext in proof
 * HIDDEN attributes   → C_i + NIZK Σ-proof of knowledge of (m_i, r_i)
 *
 * @param {string}   credentialId
 * @param {string[]} revealAttributes  - attribute keys to disclose
 * @param {string}   verifierId
 * @param {string}   challenge         - verifier's nonce
 *
 * @returns {{ proof: object, proofId: string }}
 */
function generateNIZKProof(credentialId, revealAttributes, verifierId, challenge) {
  const { proofJson, proofId } = native.generateNIZKProof(
    credentialId, revealAttributes, verifierId, challenge
  );
  return { proof: JSON.parse(proofJson), proofId };
}

/**
 * Verify a NIZK proof.
 * Stateless — call this on the verifier side.
 *
 * @param {object} proof            - from generateNIZKProof()
 * @param {string} originalChallenge
 * @param {string} pkXHex           - issuer public key X point
 * @param {string[]} pkYsHex        - issuer public key Y points
 *
 * @returns {{ valid, errors, disclosed, hiddenKeys, trustLevel, sessionId }}
 */
function verifyNIZKProof(proof, originalChallenge, pkXHex, pkYsHex) {
  const proofJson = typeof proof === 'string' ? proof : JSON.stringify(proof);
  const { resultJson, valid } = native.verifyNIZKProof(
    proofJson, originalChallenge, pkXHex, pkYsHex
  );
  return JSON.parse(resultJson);
}

/**
 * List all stored credentials (metadata only, no raw values).
 */
function listCredentials() {
  return JSON.parse(native.listCredentials());
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  init,
  psKeygen,
  psSign,
  storePSCredential,
  getAttributeCommitments,
  generateNIZKProof,
  verifyNIZKProof,
  listCredentials,
};
