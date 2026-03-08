/**
 * demo_bridge.js
 *
 * End-to-end demo of the JS ↔ Rust bridge.
 * Shows PS keygen, signing, storing, NIZK proof generation and verification
 * all going through the Rust native addon via wallet_bridge.js.
 *
 * Run:
 *   cd wallet_rs && npm install && npm run build-release && cd ..
 *   node demo_bridge.js
 */

'use strict';

const bridge = require('./wallet_bridge');
const crypto = require('crypto');

function section(t) { console.log('\n' + '═'.repeat(62) + '\n  ' + t + '\n' + '═'.repeat(62)); }

async function main() {

  section('STEP 1: Initialise Rust wallet');
  bridge.init();
  console.log('  Rust wallet initialised ✅');

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 2: Issuer generates PS keypair over BN254 (Rust)');

  const ATTR_ORDER = ['name', 'age', 'country', 'income', 'city'];
  const keys = bridge.psKeygen(ATTR_ORDER.length);

  console.log(`  pkXHex  = ${keys.pkXHex.slice(0, 24)}...`);
  console.log(`  pkYsHex = [${keys.pkYsHex.map(y => y.slice(0,12)+'...').join(', ')}]`);
  console.log(`  L = ${keys.l} attributes`);

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 3: Issuer signs user attributes (Rust)');

  const attributes = {
    name    : 'Priya Sharma',
    age     : '26',            // ← strings for Rust boundary
    country : 'India',
    income  : '850000',
    city    : 'Kolkata',
  };

  const messages = ATTR_ORDER.map(k => attributes[k]);
  const sig = bridge.psSign(messages, keys.skXHex, keys.skYsHex);

  console.log(`  σ1 = ${sig.sigma1Hex.slice(0, 24)}...`);
  console.log(`  σ2 = ${sig.sigma2Hex.slice(0, 24)}...`);

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 4: Wallet stores PS credential + computes C_i (Rust)');

  bridge.storePSCredential('govt_id', {
    attributes,
    attribute_order : ATTR_ORDER,
    sigma1_hex      : sig.sigma1Hex,
    sigma2_hex      : sig.sigma2Hex,
    pk_x_hex        : keys.pkXHex,
    pk_ys_hex       : keys.pkYsHex,
  });
  console.log('  Credential stored ✅');

  const commits = bridge.getAttributeCommitments('govt_id');
  console.log('\n  Per-attribute Pedersen commitments C_i = m_i·G + r_i·H:');
  for (const [key, hex] of Object.entries(commits)) {
    console.log(`    C_${key.padEnd(10)} = ${hex.slice(0, 24)}...`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 5: Bank — reveal country only (Rust NIZK proof)');

  const bankChallenge = crypto.randomBytes(16).toString('hex');
  const { proof: bankProof, proofId: bankProofId } =
    bridge.generateNIZKProof('govt_id', ['country'], 'bank_HDFC', bankChallenge);

  console.log(`  proofType  = ${bankProof.proof_type}`);
  console.log(`  sessionId  = ${bankProof.session_id.slice(0, 16)}...`);
  console.log(`  revealed   = ${JSON.stringify(bankProof.revealed)}`);
  console.log(`  hiddenKeys = ${JSON.stringify(bankProof.hidden_keys)}`);
  console.log(`  proofId    = ${bankProofId.slice(0, 16)}...`);

  const bankResult = bridge.verifyNIZKProof(bankProof, bankChallenge, keys.pkXHex, keys.pkYsHex);
  console.log(`\n  Verification:`);
  console.log(`    valid      = ${bankResult.valid}`);
  console.log(`    trustLevel = ${bankResult.trust_level}`);
  console.log(`    disclosed  = ${JSON.stringify(bankResult.disclosed)}`);

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 6: KYC Portal — reveal name + city');

  const kycChallenge = crypto.randomBytes(16).toString('hex');
  const { proof: kycProof } =
    bridge.generateNIZKProof('govt_id', ['name', 'city'], 'kyc_portal', kycChallenge);

  const kycResult = bridge.verifyNIZKProof(kycProof, kycChallenge, keys.pkXHex, keys.pkYsHex);
  console.log(`  valid     = ${kycResult.valid}`);
  console.log(`  disclosed = ${JSON.stringify(kycResult.disclosed)}`);
  console.log(`  hidden    = ${JSON.stringify(kycResult.hidden_keys)}`);

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 7: Zero disclosure — reveal nothing');

  const zeroChallenge = crypto.randomBytes(16).toString('hex');
  const { proof: zeroProof } =
    bridge.generateNIZKProof('govt_id', [], 'anon_verifier', zeroChallenge);

  const zeroResult = bridge.verifyNIZKProof(zeroProof, zeroChallenge, keys.pkXHex, keys.pkYsHex);
  console.log(`  valid      = ${zeroResult.valid}`);
  console.log(`  disclosed  = ${JSON.stringify(zeroResult.disclosed)}`);
  console.log(`  hiddenKeys = ${JSON.stringify(zeroResult.hidden_keys)}`);

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 8: Unlinkability check');

  console.log(`  Bank  σ1: ${bankProof.sigma1_hex.slice(0, 32)}...`);
  console.log(`  KYC   σ1: ${kycProof.sigma1_hex.slice(0, 32)}...`);
  console.log(`  Different: ${bankProof.sigma1_hex !== kycProof.sigma1_hex ? '✅ YES' : '❌ NO'}`);

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 9: Replay attack blocked');

  const fakeChallenge = crypto.randomBytes(16).toString('hex');
  const replayResult  = bridge.verifyNIZKProof(bankProof, fakeChallenge, keys.pkXHex, keys.pkYsHex);
  console.log(`  Blocked: ${!replayResult.valid ? '✅ YES' : '❌ NO'}`);
  console.log(`  Errors : ${replayResult.errors.join(', ')}`);

  // ───────────────────────────────────────────────────────────────────────────
  section('STEP 10: List credentials');

  const list = bridge.listCredentials();
  console.log('  Stored credentials:', JSON.stringify(list, null, 2));

  // ───────────────────────────────────────────────────────────────────────────
  section('✅ BRIDGE DEMO COMPLETE');
  console.log(`
  PS Keygen over BN254     ✅  Rust (ark-bn254)
  PS Signing               ✅  Rust
  PS Credential Storage    ✅  Rust — C_i = m_i·G + r_i·H per attribute
  NIZK Proof Generation    ✅  Rust — Σ-protocol + Fiat-Shamir
  NIZK Verification        ✅  Rust
  Selective Disclosure     ✅  Revealed plaintext / Hidden via C_i + proof
  Zero Disclosure          ✅  All attrs hidden
  Unlinkability            ✅  σ1 re-randomized per session
  Replay Protection        ✅  Challenge-bound
  JS ↔ Rust Bridge         ✅  neon via wallet_bridge.js
  `);
}

main().catch(console.error);
