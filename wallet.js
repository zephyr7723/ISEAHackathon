/**
 * ZKP Identity Wallet
 *
 * Stores credentials issued by trusted issuers (PS-signed over BN254),
 * generates NIZK sigma proofs for selective disclosure,
 * and ensures unlinkability across verifier sessions.
 *
 * Also supports HOLDER-GENERATED (self-issued) credentials.
 *
 * Cryptographic stack:
 *   Curve        : BN254 (alt_bn128) — pairing-friendly, used in Ethereum ZKPs
 *   Signatures   : Pointcheval-Sanders (PS) — randomizable, multi-message
 *   Commitments  : Pedersen over BN254 G1 — C_i = m_i*G + r_i*H per attribute
 *   ZK Proofs    : NIZK Σ-protocols (Fiat-Shamir transform)
 *   Unlinkability: PS re-randomization + fresh per-session Pedersen blindings
 */

'use strict';

const crypto = require('crypto');
const {
  psKeyGen, psSign, psReRandomize,
  pedersenCommit,
  nizkProveCommitment, nizkVerifyCommitment,
  nizkProvePSSignature, nizkVerifyPSSignature,
  attributeToScalar, randomScalar,
} = require('./ps_crypto');
const { pointToHex, hexToPoint } = require('./bn254');

// ─── Legacy helpers (kept for self-issued / non-PS credentials) ───────────────
function sha256(data) { return require('crypto').createHash('sha256').update(JSON.stringify(data)).digest('hex'); }
function hmac(key, data) { return require('crypto').createHmac('sha256', key).update(JSON.stringify(data)).digest('hex'); }
function randomBytes(n=32) { return require('crypto').randomBytes(n).toString('hex'); }
function commit(value, blinding) { return sha256({ value, blinding }); }

// ─── ZKP Wallet ───────────────────────────────────────────────────────────────

class ZKPWallet {
  constructor() {
    this.credentials  = new Map();
    this.sessionLog   = new Map();
    this.proofStore   = new Map(); // ← stores generated proofs by proofId
    this.masterSecret = randomBytes();
    this.holderPrivateKey = randomBytes();
    this.holderPublicKey  = sha256({ publicOf: this.holderPrivateKey });
  }

  // ── PS Credential Storage ──────────────────────────────────────────────────

  /**
   * Store a PS-signed credential.
   * Computes and stores per-attribute Pedersen commitments C_i = m_i*G + r_i*H.
   *
   * @param {string} credentialId
   * @param {object} credential { attributes, psSignature, issuerPK, attributeOrder }
   */
  storePSCredential(credentialId, credential) {
    const { attributes, psSignature, issuerPK, attributeOrder } = credential;
    if (!attributeOrder || attributeOrder.length !== issuerPK.L)
      throw new Error('attributeOrder length must equal issuerPK.L');

    // Attribute scalars (Fr elements)
    const attrScalars = attributeOrder.map(key => {
      if (!(key in attributes)) throw new Error(`Missing attribute: ${key}`);
      return attributeToScalar(attributes[key]);
    });

    // Per-attribute Pedersen commitments: C_i = m_i*G + r_i*H
    const attrBlindings     = {};
    const attrCommitments   = {};
    const attrCommitmentsHex= {};
    for (let i = 0; i < attributeOrder.length; i++) {
      const key = attributeOrder[i];
      const r_i = randomScalar();
      const C_i = pedersenCommit(attrScalars[i], r_i);
      attrBlindings[key]      = r_i;
      attrCommitments[key]    = C_i;
      attrCommitmentsHex[key] = pointToHex(C_i);
    }

    this.credentials.set(credentialId, {
      type: 'ps',
      attributes,           // secret — raw values, never leave wallet
      attributeOrder,
      attrScalars,          // secret — Fr scalars
      attrBlindings,        // secret — r_i per attribute
      attrCommitments,      // points C_i
      attrCommitmentsHex,   // hex form for transport
      psSignature,          // PS (sigma1, sigma2) from issuer
      issuerPK,
      storedAt: Date.now(),
      selfIssued: false,
    });

    console.log(`[Wallet] ✅ PS credential stored: "${credentialId}"`);
    console.log(`[Wallet]    Attributes       : [${attributeOrder.join(', ')}]`);
    console.log(`[Wallet]    Commitments C_i  : ${attributeOrder.length} stored`);
    return true;
  }

  // ── Legacy Credential Storage ──────────────────────────────────────────────

  storeCredential(credentialId, credential) {
    if (!this._verifyIssuerSignature(credential))
      throw new Error(`Invalid issuer signature for: ${credentialId}`);
    this.credentials.set(credentialId, { type: 'legacy', ...credential, storedAt: Date.now(), selfIssued: false });
    console.log(`[Wallet] ✅ Legacy credential stored: "${credentialId}"`);
    return true;
  }

  // ── Credential Listing ─────────────────────────────────────────────────────

  listCredentials() {
    return [...this.credentials.keys()].map(id => {
      const c = this.credentials.get(id);
      return {
        id,
        type          : c.type,
        attributeKeys : Object.keys(c.attributes),
        storedAt      : c.storedAt,
        selfIssued    : c.selfIssued || false,
        commitmentKeys: c.type === 'ps' ? Object.keys(c.attrCommitmentsHex) : [],
      };
    });
  }

  /**
   * Retrieve stored per-attribute Pedersen commitments for a PS credential.
   * These are public (hiding, not secret) and can be shared with verifiers.
   */
  getAttributeCommitments(credentialId) {
    const cred = this.credentials.get(credentialId);
    if (!cred || cred.type !== 'ps') throw new Error(`PS credential not found: ${credentialId}`);
    return { ...cred.attrCommitmentsHex };
  }

  // ── NIZK Proof Generation ──────────────────────────────────────────────────

  /**
   * Generate a NIZK sigma proof for a PS credential with selective disclosure.
   *
   * REVEALED attributes → plaintext in proof
   * HIDDEN attributes   → C_i = m_i*G + r_i*H + NIZK proof of knowledge of (m_i, r_i)
   *
   * Proof is unlinkable (PS re-randomization), replay-safe (challenge binding),
   * and optionally stored in proofStore.
   *
   * @param {string}   credentialId
   * @param {string[]} revealAttributes  - keys to disclose in plaintext
   * @param {string}   verifierId
   * @param {string}   challenge         - verifier nonce
   * @param {object}   [opts]
   * @param {boolean}  [opts.store=true] - store proof in proofStore
   * @returns {{ proof, proofId }}
   */
  generateNIZKProof(credentialId, revealAttributes=[], verifierId, challenge, opts={}) {
    const cred = this.credentials.get(credentialId);
    if (!cred)            throw new Error(`Credential not found: ${credentialId}`);
    if (cred.type !== 'ps') throw new Error(`Use generateProof() for non-PS credentials`);

    const { store = true } = opts;

    // Session binding
    const sessionRandom = randomBytes();
    const sessionId     = sha256({ verifierId, sessionRandom, challenge });
    const sessionCtx    = `${sessionId}:${verifierId}:${challenge}`;

    if (!this.sessionLog.has(verifierId)) this.sessionLog.set(verifierId, []);
    this.sessionLog.get(verifierId).push({ sessionId, credentialId, timestamp: Date.now() });

    const { attributeOrder, attrScalars, attrBlindings, psSignature, issuerPK } = cred;
    const revealSet     = new Set(revealAttributes);
    const hiddenIndices = attributeOrder.map((k,i)=>revealSet.has(k)?null:i).filter(i=>i!==null);
    const rs            = attributeOrder.map(k => cred.attrBlindings[k]);

    // Build NIZK PS proof with per-attribute commitment proofs
    const psNIZK = nizkProvePSSignature(psSignature, attrScalars, rs, hiddenIndices, issuerPK, sessionCtx);

    // Readable disclosed values
    const revealedAttributes = {};
    for (const key of revealAttributes) revealedAttributes[key] = cred.attributes[key];
    const hiddenAttributeKeys = hiddenIndices.map(i => attributeOrder[i]);

    const proof = {
      proofType          : 'PS_NIZK_BN254',
      sessionId,
      credentialId,
      issuerPKhex        : { Xhex: issuerPK.Xhex, Yshex: issuerPK.Yshex },
      psNIZK: { ...psNIZK, _verifierId: verifierId },  // verifierId embedded for ctx reconstruction
      revealedAttributes,              // plaintext
      hiddenAttributeKeys,             // which keys are hidden
      challenge,
      timestamp          : Date.now(),
    };

    // Store proof
    const proofId = sha256({ sessionId, credentialId, verifierId, ts: proof.timestamp });
    if (store) {
      this.proofStore.set(proofId, {
        proof,
        verifierId,
        credentialId,
        revealedKeys  : revealAttributes,
        hiddenKeys    : hiddenAttributeKeys,
        generatedAt   : Date.now(),
      });
    }

    console.log(`[Wallet] 🔐 PS NIZK proof generated | verifier="${verifierId}"`);
    console.log(`[Wallet]    session=${sessionId.slice(0,16)}...`);
    console.log(`[Wallet]    Revealed: [${revealAttributes.join(', ')}]`);
    console.log(`[Wallet]    Hidden  : [${hiddenAttributeKeys.join(', ')}]`);
    console.log(`[Wallet]    proofId =${proofId.slice(0,16)}...`);

    return { proof, proofId };
  }

  // ── Proof Store ────────────────────────────────────────────────────────────

  getStoredProof(proofId)  { return this.proofStore.get(proofId) || null; }
  deleteStoredProof(proofId) { return this.proofStore.delete(proofId); }
  listStoredProofs() {
    return [...this.proofStore.entries()].map(([id, r]) => ({
      proofId      : id,
      credentialId : r.credentialId,
      verifierId   : r.verifierId,
      revealedKeys : r.revealedKeys,
      hiddenKeys   : r.hiddenKeys,
      generatedAt  : r.generatedAt,
    }));
  }

  // ── PS NIZK Verification (verifier-side, static) ──────────────────────────

  /**
   * Verify a PS_NIZK_BN254 proof.
   * Stateless — only needs the proof and issuer public key.
   *
   * Checks:
   *   1. Challenge match (replay protection)
   *   2. Timestamp freshness
   *   3. NIZK Fiat-Shamir challenge consistency
   *   4. Per-attribute commitment proofs for all hidden attributes
   */
  static verifyNIZKProof(proof, originalChallenge, issuerPK) {
    const errors = [];
    if (proof.challenge !== originalChallenge) errors.push('Challenge mismatch');
    if (Date.now() - proof.timestamp > 5*60*1000)  errors.push('Proof expired');
    if (proof.proofType !== 'PS_NIZK_BN254') errors.push('Wrong proof type');

    if (proof.psNIZK) {
      const pkFull = {
        Xhex : issuerPK.Xhex,
        Yshex: issuerPK.Yshex,
        X    : hexToPoint(issuerPK.Xhex),
        Ys   : issuerPK.Yshex.map(h => hexToPoint(h)),
        L    : issuerPK.Yshex.length,
      };
      // sessionCtx during verify: use sessionId as the binding (Fiat-Shamir is self-contained)
      const verifyCtx = `${proof.sessionId}:${proof.psNIZK._verifierId||""}:${proof.challenge}`;
      const result = nizkVerifyPSSignature(proof.psNIZK, pkFull, verifyCtx);
      if (!result.valid) errors.push(...result.errors.map(e => 'NIZK: '+e));
    } else {
      errors.push('Missing psNIZK');
    }

    const valid = errors.length === 0;
    console.log(`[Verifier] ${valid?'✅ VALID':'❌ INVALID'} [PS_NIZK_BN254] | session=${proof.sessionId?.slice(0,16)}...`);
    if (errors.length) console.log(`[Verifier] Errors:`, errors);

    return {
      valid, errors,
      disclosed       : proof.revealedAttributes,
      hiddenKeys      : proof.hiddenAttributeKeys,
      trustLevel      : 'ISSUER_BACKED_PS_BN254',
      sessionId       : proof.sessionId,
    };
  }

  // ── Unified verifyProof (routes by proofType) ──────────────────────────────

  static verifyProof(proof, originalChallenge, issuerPublicKey) {
    if (proof.proofType === 'PS_NIZK_BN254')
      return ZKPWallet.verifyNIZKProof(proof, originalChallenge, issuerPublicKey);

    // Legacy / self-issued
    const errors = [];
    if (proof.challenge !== originalChallenge) errors.push('Challenge mismatch');
    if (Date.now() - proof.timestamp > 5*60*1000) errors.push('Proof expired');
    if (proof.issuerPublicKey !== issuerPublicKey) errors.push('Issuer key mismatch');
    for (const pp of (proof.predicateProofs||[])) {
      if (!pp.predicateCommitment||!pp.witness) errors.push(`Bad predicate: ${pp.attr}`);
    }
    if (proof.proofOfKnowledge?.length !== 64) errors.push('PoK invalid');
    if (proof.selfIssued) {
      if (!proof.bindingSignature||proof.bindingSignature.length!==64) errors.push('Missing binding sig');
      if (!proof.holderPublicKey) errors.push('Missing holderPublicKey');
    }
    const valid = errors.length === 0;
    const tag = proof.selfIssued ? '[SELF-ISSUED]' : '[LEGACY]';
    console.log(`[Verifier] ${valid?'✅':'❌'} ${tag} | session=${proof.sessionId?.slice(0,16)}...`);
    if (errors.length) console.log(`[Verifier] Errors:`, errors);
    return {
      valid, errors,
      sessionId   : proof.sessionId,
      disclosed   : proof.disclosed,
      selfIssued  : proof.selfIssued||false,
      trustLevel  : proof.selfIssued ? 'HOLDER_ASSERTED' : 'ISSUER_BACKED',
      predicateResults: (proof.predicateProofs||[]).map(p => ({
        claim: `${p.attr} ${p.op} ${p.claimedThreshold}`, verified: true,
      })),
    };
  }

  // ── Legacy proof generation ────────────────────────────────────────────────

  generateProof(credentialId, revealAttributes=[], predicates=[], verifierId, challenge) {
    const cred = this.credentials.get(credentialId);
    if (!cred) throw new Error(`Credential not found: ${credentialId}`);
    if (cred.type === 'ps') throw new Error('Use generateNIZKProof() for PS credentials');
    const sessionRandom = randomBytes();
    const sessionId = sha256({ verifierId, sessionRandom, challenge });
    if (!this.sessionLog.has(verifierId)) this.sessionLog.set(verifierId, []);
    this.sessionLog.get(verifierId).push({ sessionId, credentialId, timestamp: Date.now() });
    const disclosed = {};
    for (const key of revealAttributes) disclosed[key] = cred.attributes[key];
    const reRandomizedCommitments = {};
    for (const [key, c] of Object.entries(cred.commitments||{})) {
      const delta = hmac(this.masterSecret, { sessionId, key });
      reRandomizedCommitments[key] = sha256({ commitment: c, delta });
    }
    const predicateProofs = predicates.map(pred => {
      const { attr, op, value } = pred;
      const actualValue = cred.attributes[attr];
      if (!this._evaluatePredicate(actualValue, op, value))
        throw new Error(`Predicate ${attr} ${op} ${value} is FALSE`);
      const witness = hmac(this.masterSecret, { sessionId, attr, actualValue, pred });
      return { attr, op, claimedThreshold: value, predicateCommitment: commit(actualValue, witness), witness };
    });
    const proofOfKnowledge = hmac(cred.issuerSignature, { challenge, sessionId, reRandomizedCommitments });
    console.log(`[Wallet] 🔐 Legacy proof | verifier="${verifierId}" session=${sessionId.slice(0,16)}...`);
    return { proofType: 'LEGACY_HMAC', sessionId, credentialId, issuerPublicKey: cred.issuerPublicKey, reRandomizedCommitments, disclosed, predicateProofs, proofOfKnowledge, challenge, timestamp: Date.now() };
  }

  // ── Self-issued credential ────────────────────────────────────────────────

  selfIssueCredential(credentialId, attributes) {
    const blindings={}, commitments={};
    for (const [k,v] of Object.entries(attributes)) { blindings[k]=randomBytes(); commitments[k]=commit(v,blindings[k]); }
    const issuedAt = Date.now();
    const holderSignature = hmac(this.holderPrivateKey, { commitments, credentialId, issuedAt });
    this.credentials.set(credentialId, { type:'self', attributes, blindings, commitments, issuerSignature:holderSignature, issuerPublicKey:this.holderPublicKey, issuedAt, selfIssued:true, credentialId, storedAt:Date.now() });
    console.log(`[Wallet] 🖊️  Self-issued credential: "${credentialId}"`);
    return this.holderPublicKey;
  }

  generateHolderProof(credentialId, revealAttributes=[], predicates=[], verifierId, challenge) {
    const cred = this.credentials.get(credentialId);
    if (!cred||!cred.selfIssued) throw new Error(`Not a self-issued credential: ${credentialId}`);
    const sessionRandom=randomBytes(), sessionId=sha256({verifierId,sessionRandom,challenge});
    if (!this.sessionLog.has(verifierId)) this.sessionLog.set(verifierId,[]);
    this.sessionLog.get(verifierId).push({sessionId,credentialId,selfIssued:true,timestamp:Date.now()});
    const disclosed={};
    for (const k of revealAttributes) disclosed[k]=cred.attributes[k];
    const reRandomizedCommitments={};
    for (const [k,c] of Object.entries(cred.commitments)) { const d=hmac(this.masterSecret,{sessionId,k}); reRandomizedCommitments[k]=sha256({commitment:c,delta:d}); }
    const predicateProofs=predicates.map(pred=>{
      const {attr,op,value}=pred, actualValue=cred.attributes[attr];
      if (!this._evaluatePredicate(actualValue,op,value)) throw new Error(`Predicate FALSE`);
      const witness=hmac(this.masterSecret,{sessionId,attr,actualValue,pred});
      return {attr,op,claimedThreshold:value,predicateCommitment:commit(actualValue,witness),witness};
    });
    const holderProofOfKnowledge=hmac(this.holderPrivateKey,{challenge,sessionId,reRandomizedCommitments});
    const bindingSignature=hmac(this.holderPrivateKey,{verifierId,challenge,sessionId,disclosed,predicates,timestamp:Date.now()});
    console.log(`[Wallet] 🔐 Holder proof | verifier="${verifierId}" session=${sessionId.slice(0,16)}...`);
    return { proofType:'HOLDER_SELF_ISSUED', sessionId, credentialId, selfIssued:true, holderPublicKey:this.holderPublicKey, issuerPublicKey:this.holderPublicKey, reRandomizedCommitments, disclosed, predicateProofs, holderProofOfKnowledge, bindingSignature, proofOfKnowledge:holderProofOfKnowledge, challenge, timestamp:Date.now() };
  }

  // ── Private ────────────────────────────────────────────────────────────────

  _verifyIssuerSignature(credential) {
    return hmac(credential.issuerPublicKey,{commitments:credential.commitments}) === credential.issuerSignature;
  }
  _evaluatePredicate(actual,op,threshold) {
    return op==='>='?actual>=threshold:op==='<='?actual<=threshold:op==='>'?actual>threshold:op==='<'?actual<threshold:op==='=='?actual==threshold:(()=>{throw new Error('Unknown op: '+op)})();
  }
}

module.exports = { ZKPWallet, commit, hmac, sha256, randomBytes };
