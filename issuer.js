/**
 * ZKP Credential Issuer
 * 
 * Trusted authority (e.g. government, bank) that:
 *   1. Receives user's attribute commitments
 *   2. Verifies them (KYC/offline check)
 *   3. Signs the commitments
 *   4. Returns a signed credential to the wallet
 * 
 * The issuer NEVER learns the blinding factors, so they
 * cannot re-derive the raw attribute values from commitments.
 */

const { commit, hmac, sha256, randomBytes } = require('./wallet');

class Issuer {
  constructor(name) {
    this.name = name;
    // In production: this would be an elliptic curve private key (BLS12-381)
    this.privateKey = sha256({ secret: randomBytes(), name });
    this.publicKey  = sha256({ publicOf: this.privateKey }); // simulated pub key
    console.log(`[Issuer:${name}] Created with publicKey=${this.publicKey.slice(0,16)}...`);
  }

  /**
   * Issue a credential to a user.
   * 
   * @param {object} attributes - raw attribute key-values the user wants certified
   * @returns {object} credential ready to store in the ZKP Wallet
   */
  issueCredential(attributes) {
    // 1. Generate per-attribute blinding factors
    const blindings = {};
    const commitments = {};

    for (const [key, value] of Object.entries(attributes)) {
      blindings[key]    = randomBytes();
      commitments[key]  = commit(value, blindings[key]);
    }

    // 2. Sign the commitments (not the raw values)
    const issuerSignature = hmac(this.publicKey, { commitments });

    const credential = {
      attributes,          // stored in wallet only — never sent to verifier
      blindings,           // stored in wallet only — never sent to verifier
      commitments,         // public: committed form of attributes
      issuerSignature,     // proves issuer certified these commitments
      issuerPublicKey: this.publicKey,
      issuedAt: Date.now(),
      issuerName: this.name,
    };

    console.log(`[Issuer:${this.name}] ✅ Issued credential for attributes: [${Object.keys(attributes).join(', ')}]`);
    return credential;
  }
}

module.exports = { Issuer };
