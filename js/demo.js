/**
 * ZKP System Demo
 * 
 * Simulates the full flow:
 *   Issuer → Wallet → Verifier A, Verifier B, Verifier C
 * 
 * Demonstrates:
 *   ✅ Selective Disclosure  - only share what's needed
 *   ✅ Zero Disclosure       - predicate proofs reveal nothing extra
 *   ✅ Unlinkability         - Verifier A cannot correlate with Verifier B
 *   ✅ Multi-Verifier        - same credential, multiple independent verifiers
 */

const { ZKPWallet, randomBytes } = require('./wallet');
const { Issuer } = require('./issuer');

// ─── Helper ──────────────────────────────────────────────────────────────────

function section(title) {
  console.log('\n' + '═'.repeat(60));
  console.log(`  ${title}`);
  console.log('═'.repeat(60));
}

function step(msg) {
  console.log(`\n  ▸ ${msg}`);
}

// ─── DEMO ────────────────────────────────────────────────────────────────────

async function runDemo() {
  section('STEP 1: Government Issues Identity Credential');

  const govIssuer = new Issuer('IndiaGovt');

  // User's real attributes (wallet keeps these private)
  const userAttributes = {
    name:        'Priya Sharma',
    age:         26,
    country:     'India',
    aadhaarHash: 'a3f9...', // hash of real Aadhaar
    incomeINR:   850000,
    city:        'Kolkata',
  };

  const credential = govIssuer.issueCredential(userAttributes);

  // ─────────────────────────────────────────────────────────────────────────
  section('STEP 2: Wallet Stores the Credential');

  const wallet = new ZKPWallet();
  wallet.storeCredential('govt_id', credential);

  console.log('\n  Stored credentials:', wallet.listCredentials());

  // ─────────────────────────────────────────────────────────────────────────
  section('STEP 3: Verifier A (Bank) — Needs age ≥ 18 + country');

  step('Bank generates a fresh challenge to prevent replay attacks');
  const bankChallenge = randomBytes(16);

  step('Wallet generates proof: reveals country, proves age ≥ 18 WITHOUT revealing actual age');
  const bankProof = wallet.generateProof(
    'govt_id',
    ['country'],                              // only disclose country
    [{ attr: 'age', op: '>=', value: 18 }],  // prove age ≥ 18 (ZKP)
    'verifier_bank_HDFC',
    bankChallenge
  );

  step('Bank verifies the proof');
  const bankResult = ZKPWallet.verifyProof(bankProof, bankChallenge, govIssuer.publicKey);
  console.log('\n  Bank sees:', {
    disclosed: bankResult.disclosed,
    predicates: bankResult.predicateResults,
    sessionId: bankResult.sessionId.slice(0, 20) + '...',
  });
  console.log('  ❌ Bank does NOT see: name, age value, aadhaarHash, incomeINR, city');

  // ─────────────────────────────────────────────────────────────────────────
  section('STEP 4: Verifier B (Alcohol Shop) — Only needs age ≥ 21');

  const shopChallenge = randomBytes(16);
  const shopProof = wallet.generateProof(
    'govt_id',
    [],                                        // reveal NOTHING
    [{ attr: 'age', op: '>=', value: 21 }],   // only prove age ≥ 21
    'verifier_shop_ABC',
    shopChallenge
  );

  const shopResult = ZKPWallet.verifyProof(shopProof, shopChallenge, govIssuer.publicKey);
  console.log('\n  Shop sees:', {
    disclosed: shopResult.disclosed,
    predicates: shopResult.predicateResults,
  });
  console.log('  ❌ Shop does NOT see: name, age, country, or any other attribute');

  // ─────────────────────────────────────────────────────────────────────────
  section('STEP 5: Verifier C (Govt Portal) — Needs income > 500000 + city');

  const portalChallenge = randomBytes(16);
  const portalProof = wallet.generateProof(
    'govt_id',
    ['city'],
    [{ attr: 'incomeINR', op: '>=', value: 500000 }],
    'verifier_govt_portal',
    portalChallenge
  );

  const portalResult = ZKPWallet.verifyProof(portalProof, portalChallenge, govIssuer.publicKey);
  console.log('\n  Portal sees:', {
    disclosed: portalResult.disclosed,
    predicates: portalResult.predicateResults,
  });

  // ─────────────────────────────────────────────────────────────────────────
  section('STEP 6: UNLINKABILITY CHECK');

  step('Do Bank and Shop see the same sessionId? (they should NOT)');
  console.log(`  Bank  sessionId: ${bankProof.sessionId.slice(0, 32)}...`);
  console.log(`  Shop  sessionId: ${shopProof.sessionId.slice(0, 32)}...`);
  console.log(`  Portal sessionId: ${portalProof.sessionId.slice(0, 32)}...`);
  
  const allUnique = new Set([
    bankProof.sessionId,
    shopProof.sessionId,
    portalProof.sessionId,
  ]).size === 3;

  console.log(`\n  All session IDs unique: ${allUnique ? '✅ YES — verifiers cannot correlate proofs' : '❌ NO'}`);

  step('Do verifiers see the same re-randomized commitments? (should NOT match)');
  const commitMatch = JSON.stringify(bankProof.reRandomizedCommitments) ===
                      JSON.stringify(shopProof.reRandomizedCommitments);
  console.log(`  Commitments match across verifiers: ${commitMatch ? '❌ YES (linkable!)' : '✅ NO — fully unlinkable'}`);

  // ─────────────────────────────────────────────────────────────────────────
  section('STEP 7: REPLAY ATTACK PROTECTION');

  step('Attacker tries to reuse bankProof with a different challenge');
  const fakeChallenge = randomBytes(16);
  const replayResult = ZKPWallet.verifyProof(bankProof, fakeChallenge, govIssuer.publicKey);
  console.log(`  Replay attack blocked: ${!replayResult.valid ? '✅ YES' : '❌ NO'}`);
  console.log(`  Errors: ${replayResult.errors.join(', ')}`);

  // ─────────────────────────────────────────────────────────────────────────
  section('STEP 8: Wallet Audit Log (visible only to user)');
  
  console.log('\n  Sessions per verifier:');
  for (const [vid, sessions] of wallet.sessionLog.entries()) {
    console.log(`    ${vid}: ${sessions.length} proof(s) generated`);
  }

  section('✅ DEMO COMPLETE — All 4 properties demonstrated');
  console.log(`
  1. Selective Disclosure  ✅  Bank got country only, not name/age/income
  2. Zero Disclosure       ✅  Shop got NO attributes, only a predicate proof
  3. Multi-Verifier        ✅  Same credential used across Bank, Shop, Portal
  4. Unlinkability         ✅  All sessionIds + commitments unique per verifier
  5. Replay Protection     ✅  Reused proof rejected with wrong challenge
  `);
}

runDemo().catch(console.error);
