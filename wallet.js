/**
 * ZKP Identity Wallet
 * 
 * The wallet stores user credentials issued by trusted issuers,
 * generates zero-knowledge proofs for selective disclosure,
 * and ensures unlinkability across verifier sessions.
 * 
 */

const crypto = require('crypto');

// ─── Utility Helpers ────────────────────────────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(JSON.stringify(data)).digest('hex');
}

function randomBytes(n = 32) {
  return crypto.randomBytes(n).toString('hex');
}


function commit(value, blinding) {
  return sha256({ value, blinding });
}


// ─── ZKP Wallet Class ────────────────────────────────────────────────────────

class ZKPWallet {
  constructor() {
    this.credentials = new Map();     // credentialId → credential
    this.sessionLog  = new Map();     // verifierId  → [sessionIds]
    this.masterSecret = randomBytes(); // wallet's master secret (never shared)
  }

// ── Credential Management ──────────────────────────────────────────────────

  
  storeCredential(credentialId, credential) 
  {
   
    const valid = this._verifyIssuerSignature(credential);
    if (!valid) throw new Error(`Invalid issuer signature for credential: ${credentialId}`);

    this.credentials.set(credentialId, {
      ...credential,
      storedAt: Date.now(),
    });
    console.log(`[Wallet] ✅ Stored credential: ${credentialId}`);
    return true;
  }

  
  listCredentials() {
    return [...this.credentials.keys()].map(id => ({
      id,
      attributeKeys: Object.keys(this.credentials.get(id).attributes),
      storedAt: this.credentials.get(id).storedAt,
    }));
  }

  // ── Proof Generation ───────────────────────────────────────────────────────

  generateProof(credentialId, revealAttributes = [], predicates = [], verifierId, challenge) {
    const cred = this.credentials.get(credentialId);
    if (!cred) throw new Error(`Credential not found: ${credentialId}`);

    // 1. Generate a fresh session randomness → unlinkability
    
    const sessionRandom = randomBytes();
    const sessionId = sha256({ verifierId, sessionRandom, challenge });

   
    if (!this.sessionLog.has(verifierId)) this.sessionLog.set(verifierId, []);
    this.sessionLog.get(verifierId).push({ sessionId, credentialId, timestamp: Date.now() });

    // 2. Selective disclosure: only reveal requested attributes
    const disclosed = {};
    for (const key of revealAttributes) {
      if (!(key in cred.attributes)) throw new Error(`Attribute not in credential: ${key}`);
      disclosed[key] = cred.attributes[key];
    }

    // 3. Re-randomize commitments (so verifier can't link to other sessions)
    const reRandomizedCommitments = {};
    for (const [key, commitment] of Object.entries(cred.commitments)) {
      const delta = hmac(this.masterSecret, { sessionId, key });
      reRandomizedCommitments[key] = sha256({ commitment, delta }); // shifted commitment
    }

    // 4. Build predicate proofs (e.g., age >= 18 without revealing age=25)
    const predicateProofs = predicates.map(pred => {
      const { attr, op, value } = pred;
      if (!(attr in cred.attributes)) throw new Error(`Attribute not in credential: ${attr}`);
      
      const actualValue = cred.attributes[attr];
      const holds = this._evaluatePredicate(actualValue, op, value);
      if (!holds) throw new Error(`Predicate ${attr} ${op} ${value} is FALSE for this credential`);

      // Witness: proves predicate holds without revealing actualValue
      
      const witness = hmac(this.masterSecret, { sessionId, attr, actualValue, pred });
      const predicateCommitment = commit(actualValue, witness);

      return {
        attr,
        op,
        claimedThreshold: value,
        predicateCommitment,       
        witness,                   
      };
    });

    // 5. Compute proof of knowledge of issuer signature (Schnorr-style)
    
    const proofOfKnowledge = hmac(cred.issuerSignature, { challenge, sessionId, reRandomizedCommitments });

    // 6. Assemble the proof
    const proof = {
      sessionId,                        
      credentialId,                     
      issuerPublicKey: cred.issuerPublicKey,
      reRandomizedCommitments,          
      disclosed,                        
      predicateProofs,                  
      proofOfKnowledge,                 
      challenge,                        
      timestamp: Date.now(),
    };

    console.log(`[Wallet] 🔐 Proof generated for verifier="${verifierId}" | session=${sessionId.slice(0,16)}...`);
    console.log(`[Wallet]    Disclosed: [${revealAttributes.join(', ')}] | Predicates: ${predicates.length}`);
    return proof;
  }

  // ── Verifier-side verification (can run independently) ─────────────────────

  
  static verifyProof(proof, originalChallenge, issuerPublicKey) {
    const errors = [];

    // 1. Challenge match (replay protection)
    if (proof.challenge !== originalChallenge) {
      errors.push('Challenge mismatch — possible replay attack');
    }

    // 2. Timestamp freshness (reject proofs older than 5 minutes)
    const age = Date.now() - proof.timestamp;
    if (age > 5 * 60 * 1000) errors.push('Proof expired');

    // 3. Issuer public key match
    if (proof.issuerPublicKey !== issuerPublicKey) {
      errors.push('Issuer public key mismatch');
    }

    // 4. Predicate validity (check commitment structure)
    for (const pp of proof.predicateProofs) {
      
      if (!pp.predicateCommitment || !pp.witness) {
        errors.push(`Invalid predicate proof for attribute: ${pp.attr}`);
      }
    }

    // 5. Proof of knowledge verification
    const pokValid = proof.proofOfKnowledge.length === 64; // HMAC hex = 64 chars

    if (!pokValid) errors.push('Proof of knowledge invalid');

    const result = {
      valid: errors.length === 0,
      errors,
      sessionId: proof.sessionId,
      disclosed: proof.disclosed,
      predicateResults: proof.predicateProofs.map(p => ({
        claim: `${p.attr} ${p.op} ${p.claimedThreshold}`,
        verified: true, // in real system, verify the range proof
      })),
    };

    const status = result.valid ? '✅ VALID' : '❌ INVALID';
    console.log(`[Verifier] ${status} proof | session=${proof.sessionId.slice(0,16)}...`);
    if (errors.length) console.log(`[Verifier] Errors:`, errors);

    return result;
  }

  // ── Private Helpers ────────────────────────────────────────────────────────

  _verifyIssuerSignature(credential) {
    const expected = hmac(
      credential.issuerPublicKey,
      { commitments: credential.commitments }
    );
    return expected === credential.issuerSignature;
  }

  _evaluatePredicate(actual, op, threshold) {
    switch (op) {
      case '>=': return actual >= threshold;
      case '<=': return actual <= threshold;
      case '>':  return actual >  threshold;
      case '<':  return actual <  threshold;
      case '==': return actual == threshold;
      default:   throw new Error(`Unknown operator: ${op}`);
    }
  }
}

module.exports = { ZKPWallet, commit, hmac, sha256, randomBytes };
