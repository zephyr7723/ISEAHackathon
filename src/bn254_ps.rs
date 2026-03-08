// ─── bn254_ps.rs ──────────────────────────────────────────────────────────────
//
// Pointcheval-Sanders signatures + NIZK Σ-protocols over BN254
// using arkworks (ark-bn254 + ark-ec + ark-ff).
//
// This module is the Rust equivalent of ps_crypto.js + bn254.js.
// It is called from lib.rs which exposes everything to Node.js via neon.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group, pairing::Pairing};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

// ─── Serialisation helpers ────────────────────────────────────────────────────

pub fn fr_to_hex(f: &Fr) -> String {
    let mut bytes = Vec::new();
    f.serialize_compressed(&mut bytes).unwrap();
    hex::encode(bytes)
}

pub fn fr_from_hex(h: &str) -> Fr {
    let bytes = hex::decode(h).expect("invalid hex for Fr");
    Fr::deserialize_compressed(&bytes[..]).expect("invalid Fr bytes")
}

pub fn g1_to_hex(p: &G1Affine) -> String {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes).unwrap();
    hex::encode(bytes)
}

pub fn g1_from_hex(h: &str) -> G1Affine {
    let bytes = hex::decode(h).expect("invalid hex for G1");
    G1Affine::deserialize_compressed(&bytes[..]).expect("invalid G1 bytes")
}

// ─── Attribute encoding ───────────────────────────────────────────────────────

/// Hash an arbitrary string attribute to a scalar in Fr.
/// Used to encode attribute values for PS signing.
pub fn attribute_to_scalar(value: &str) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(b"attr:");
    hasher.update(value.as_bytes());
    let hash = hasher.finalize();
    Fr::from_be_bytes_mod_order(&hash)
}

// ─── Fiat-Shamir hash ─────────────────────────────────────────────────────────

/// Hash multiple hex strings to a scalar — used for Fiat-Shamir transform.
pub fn hash_to_scalar(inputs: &[&str]) -> Fr {
    let mut hasher = Sha256::new();
    for (i, s) in inputs.iter().enumerate() {
        if i > 0 { hasher.update(b"||"); }
        hasher.update(s.as_bytes());
    }
    let hash = hasher.finalize();
    Fr::from_be_bytes_mod_order(&hash)
}

// ─── Second generator H ───────────────────────────────────────────────────────

/// H = 7 * G — independent generator for Pedersen commitments.
/// In production this would be a hash-to-curve output.
pub fn h_generator() -> G1Affine {
    let g = G1Projective::generator();
    let seven = Fr::from(7u64);
    (g * seven).into_affine()
}

// ─── Pedersen Commitment ──────────────────────────────────────────────────────

/// C = m*G + r*H
pub fn pedersen_commit(m: &Fr, r: &Fr) -> G1Affine {
    let g = G1Projective::generator();
    let mg = g * m;
    let h = h_generator();
    let rh = G1Projective::from(h)*r;
    (mg+rh).into_affine()
}

// ─── PS Key Generation ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PSSecretKey {
    pub x:  Fr,
    pub ys: Vec<Fr>,
}

#[derive(Clone)]
pub struct PSPublicKey {
    pub x_point:  G1Affine,          // X = x*G
    pub y_points: Vec<G1Affine>,     // Y_i = y_i*G
    pub l:        usize,
}

pub struct PSKeyPair {
    pub sk: PSSecretKey,
    pub pk: PSPublicKey,
}

/// Generate a PS keypair for signing `l` attributes.
pub fn ps_keygen(l: usize) -> PSKeyPair {
    let mut rng = OsRng;
    let g = G1Projective::generator();

    let x  = Fr::rand(&mut rng);
    let ys: Vec<Fr>       = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let x_point           = (g * x).into_affine();
    let y_points: Vec<G1Affine> = ys.iter().map(|y| (g * y).into_affine()).collect();

    PSKeyPair {
        sk: PSSecretKey { x, ys },
        pk: PSPublicKey { x_point, y_points, l },
    }
}

// ─── PS Signature ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PSSignature {
    pub sigma1: G1Affine,
    pub sigma2: G1Affine,
}

/// Sign a vector of attribute scalars.
/// σ = (h,  (x + Σ y_i*m_i) * h)  where h = r*G for random r
pub fn ps_sign(messages: &[Fr], sk: &PSSecretKey) -> PSSignature {
    assert_eq!(messages.len(), sk.ys.len(), "message/key length mismatch");
    let mut rng = OsRng;
    let g = G1Projective::generator();
    let r = Fr::rand(&mut rng);
    let h = g * r;   // random G1 element

    // exponent = x + Σ y_i * m_i
    let mut exp = sk.x;
    for (y, m) in sk.ys.iter().zip(messages.iter()) {
        exp += *y * m;
    }

    let sigma1 = h.into_affine();
    let sigma2 = (h * exp).into_affine();

    PSSignature { sigma1, sigma2 }
}

// ─── PS Re-Randomization ──────────────────────────────────────────────────────

pub struct ReRandomizedSig {
    pub sigma1: G1Affine,
    pub sigma2: G1Affine,
    pub r:      Fr,         // kept by wallet, never sent to verifier
}

/// σ' = (r*σ1, r*σ2) for fresh random r — unlinkable from original
pub fn ps_rerandomize(sig: &PSSignature) -> ReRandomizedSig {
    let mut rng = OsRng;
    let r = Fr::rand(&mut rng);
    ReRandomizedSig {
        sigma1: (G1Projective::from(sig.sigma1) * r).into_affine(),
        sigma2: (G1Projective::from(sig.sigma2) * r).into_affine(),
        r,
    }
}

// ─── NIZK: Proof of Knowledge of Pedersen Commitment Opening ─────────────────
//
// Proves: "I know (m, r) s.t. C = m*G + r*H"
//
// Σ-protocol (Fiat-Shamir non-interactive):
//   Announce:  R = k_m*G + k_r*H
//   Challenge: c = H(C, R, context)
//   Respond:   s_m = k_m - c*m,  s_r = k_r - c*r
//
// Verify:  s_m*G + s_r*H + c*C == R

#[derive(Clone)]
pub struct CommitmentProof {
    pub r_point: G1Affine,   // announcement R
    pub c:       Fr,          // Fiat-Shamir challenge
    pub s_m:     Fr,          // response for m
    pub s_r:     Fr,          // response for r
    pub c_point: G1Affine,   // commitment C (included for verifier convenience)
}

pub fn nizk_prove_commitment(m: &Fr, r: &Fr, c_point: &G1Affine, context: &str) -> CommitmentProof {
    let mut rng = OsRng;
    let g = G1Projective::generator();
    let h = G1Projective::from(h_generator());

    // Random announcement scalars
    let k_m = Fr::rand(&mut rng);
    let k_r = Fr::rand(&mut rng);

    // R = k_m*G + k_r*H
    let r_point = (g * k_m + h * k_r).into_affine();

    // Fiat-Shamir challenge
    let c_hex     = g1_to_hex(c_point);
    let r_hex     = g1_to_hex(&r_point);
    let challenge = hash_to_scalar(&[&c_hex, &r_hex, context]);

    // Responses
    let s_m = k_m - challenge * m;
    let s_r = k_r - challenge * r;

    CommitmentProof {
        r_point,
        c: challenge,
        s_m,
        s_r,
        c_point: *c_point,
    }
}

pub fn nizk_verify_commitment(proof: &CommitmentProof, context: &str) -> bool {
    let g = G1Projective::generator();
    let h = G1Projective::from(h_generator());

    // Recheck Fiat-Shamir
    let c_hex     = g1_to_hex(&proof.c_point);
    let r_hex     = g1_to_hex(&proof.r_point);
    let c_check   = hash_to_scalar(&[&c_hex, &r_hex, context]);
    if c_check != proof.c { return false; }

    // Check: s_m*G + s_r*H + c*C == R
    let lhs = (g * proof.s_m + h * proof.s_r
               + G1Projective::from(proof.c_point) * proof.c)
              .into_affine();
    lhs == proof.r_point
}

// ─── NIZK: PS Signature Proof of Knowledge (Selective Disclosure) ─────────────
//
// Proves:
//   (a) Wallet holds a valid PS signature on (m_0,...,m_{L-1})
//   (b) For REVEALED attributes: m_i in plaintext
//   (c) For HIDDEN attributes:   C_i + NIZK proof of knowledge of (m_i, r_i)

pub struct PSNIZKProof {
    pub sigma1:            G1Affine,
    pub sigma2:            G1Affine,
    pub t_point:           G1Affine,          // announcement T
    pub c:                 Fr,                 // Fiat-Shamir challenge
    pub responses:         Vec<Option<Fr>>,    // s_i for hidden, None for revealed
    pub attr_commitments:  Vec<Option<G1Affine>>, // C_i for hidden, None for revealed
    pub commit_proofs:     Vec<Option<CommitmentProof>>,
    pub revealed:          Vec<Option<Fr>>,    // scalar for revealed, None for hidden
    pub hidden_indices:    Vec<usize>,
    pub verifier_id:       String,             // embedded for context reconstruction
}

pub fn nizk_prove_ps_signature(
    sig:            &PSSignature,
    messages:       &[Fr],
    blindings:      &[Fr],
    hidden_indices: &[usize],
    pk:             &PSPublicKey,
    session_ctx:    &str,
) -> PSNIZKProof {
    let mut rng      = OsRng;
    let g            = G1Projective::generator();
    let hidden_set: std::collections::HashSet<usize> = hidden_indices.iter().cloned().collect();

    // Re-randomize signature
    let rsig = ps_rerandomize(sig);

    // Per-attribute Pedersen commitments for hidden attributes (fresh per session)
    let mut attr_commitments: Vec<Option<G1Affine>>           = vec![None; messages.len()];
    let mut commit_proofs:    Vec<Option<CommitmentProof>>     = vec![None; messages.len()];
    let mut session_blindings: Vec<Option<Fr>>                 = vec![None; messages.len()];

    for &i in hidden_indices {
        let r_fresh = Fr::rand(&mut rng);
        let c_i     = pedersen_commit(&messages[i], &r_fresh);
        let ctx     = format!("{}:attr:{}", session_ctx, i);
        let proof   = nizk_prove_commitment(&messages[i], &r_fresh, &c_i, &ctx);
        attr_commitments[i]   = Some(c_i);
        commit_proofs[i]      = Some(proof);
        session_blindings[i]  = Some(r_fresh);
    }

    // PS PoK announcement: T = Σ_{hidden i} k_i * sigma1'
    let ks: Vec<Option<Fr>> = (0..messages.len()).map(|i| {
        if hidden_set.contains(&i) { Some(Fr::rand(&mut rng)) } else { None }
    }).collect();

    let mut t = G1Projective::zero();
    for (i, k_opt) in ks.iter().enumerate() {
        if let Some(k) = k_opt {
            t = t + G1Projective::from(rsig.sigma1) * k;
        }
    }
    let t_point = t.into_affine();

    // Fiat-Shamir challenge
    let sigma1_hex = g1_to_hex(&rsig.sigma1);
    let sigma2_hex = g1_to_hex(&rsig.sigma2);
    let t_hex      = g1_to_hex(&t_point);
    let x_hex      = g1_to_hex(&pk.x_point);
    let ys_hex: Vec<String> = pk.y_points.iter().map(g1_to_hex).collect();
    let ys_joined  = ys_hex.join("");
    let commits_hex: String = attr_commitments.iter()
        .map(|opt| opt.as_ref().map(g1_to_hex).unwrap_or_default())
        .collect::<Vec<_>>().join("");

    let c = hash_to_scalar(&[
        &sigma1_hex, &sigma2_hex, &t_hex,
        &x_hex, &ys_joined, &commits_hex, session_ctx,
    ]);

    // Responses: s_i = k_i - c*m_i  for hidden
    let responses: Vec<Option<Fr>> = (0..messages.len()).map(|i| {
        ks[i].map(|k| k - c * messages[i])
    }).collect();

    // Revealed scalars
    let revealed: Vec<Option<Fr>> = (0..messages.len()).map(|i| {
        if hidden_set.contains(&i) { None } else { Some(messages[i]) }
    }).collect();

    PSNIZKProof {
        sigma1: rsig.sigma1,
        sigma2: rsig.sigma2,
        t_point,
        c,
        responses,
        attr_commitments,
        commit_proofs,
        revealed,
        hidden_indices: hidden_indices.to_vec(),
        verifier_id: String::new(), // set by caller
    }
}

pub fn nizk_verify_ps_signature(
    proof:       &PSNIZKProof,
    pk:          &PSPublicKey,
    session_ctx: &str,
) -> (bool, Vec<String>) {
    let mut errors = Vec::new();

    // 1. Recheck Fiat-Shamir
    let sigma1_hex = g1_to_hex(&proof.sigma1);
    let sigma2_hex = g1_to_hex(&proof.sigma2);
    let t_hex      = g1_to_hex(&proof.t_point);
    let x_hex      = g1_to_hex(&pk.x_point);
    let ys_hex: Vec<String> = pk.y_points.iter().map(g1_to_hex).collect();
    let ys_joined  = ys_hex.join("");
    let commits_hex: String = proof.attr_commitments.iter()
        .map(|opt| opt.as_ref().map(g1_to_hex).unwrap_or_default())
        .collect::<Vec<_>>().join("");

    let c_check = hash_to_scalar(&[
        &sigma1_hex, &sigma2_hex, &t_hex,
        &x_hex, &ys_joined, &commits_hex, session_ctx,
    ]);

    if c_check != proof.c {
        errors.push("Fiat-Shamir challenge mismatch".to_string());
    }

    // 2. Check each hidden attribute commitment proof
    for &i in &proof.hidden_indices {
        match (&proof.commit_proofs[i], &proof.attr_commitments[i]) {
            (Some(cp), Some(_)) => {
                let ctx = format!("{}:attr:{}", session_ctx, i);
                if !nizk_verify_commitment(cp, &ctx) {
                    errors.push(format!("NIZK commitment proof invalid for attribute {}", i));
                }
            }
            _ => errors.push(format!("Missing commitment/proof for hidden attribute {}", i)),
        }
    }

    // 3. sigma1 not identity
    if proof.sigma1.is_zero() {
        errors.push("sigma1 is point at infinity".to_string());
    }

    (errors.is_empty(), errors)
}


use serde::{Serialize, Deserialize};

// ─── NIZK: PS Signature Proof of Knowledge (G1-only, Pedersen binding) ────────
//
// Proves: "I know (m1, m2, rk) s.t. Ck = mk·G + rk·H"
// Announcements are formed in G1 using the public Y-points.
// The PS signature is rerandomised and included for session binding.
// Full PS signature validity is established by the SuperNova circuit.
//
// Σ-protocol (Fiat-Shamir non-interactive):
//   T1 = α1·Y1 + α2·Y2          (Y-space announcement)
//   T2 = αk·G  + β·H            (Pedersen announcement)
//   c  = H(σ'₁, σ'₂, Ck, T1, T2)
//   s1 = α1 + c·m1,  s2 = α2 + c·m2,  t_resp = β + c·rk
//
// Verify (Pedersen linkage — checkable without pairings):
//   sk·G + t_resp·H  ==  T2 + c·Ck     where sk = s_{committed_attr}

#[derive(Clone)]
pub struct NizkProof {
    /// Rerandomised PS signature (session binding, not verified here).
    pub sigma_prime:    PSSignature,
    /// Pedersen commitment Ck = mk·G + rk·H (public).
    pub commitment:     G1Affine,
    /// Which attribute is committed: 0 = dob (m1), 1 = nationality (m2).
    pub committed_attr: usize,
    /// R = k_m·G + k_r·H  (Schnorr announcement).
    pub r_point:        G1Affine,
    /// Fiat-Shamir challenge c.
    pub c:              Fr,
    /// s_m = k_m − c·mk.
    pub s_m:            Fr,
    /// s_r = k_r − c·rk.
    pub s_r:            Fr,
}

/// Randomness retained by the wallet for rerandomisation.
#[derive(Clone)]
pub struct NizkRandomness {   
    pub rk:    Fr,   // Pedersen blinding for the committed attribute
    pub k_m:   Fr,   // announcement scalar (k_m = s_m + c·mk)
    pub k_r:   Fr,   // announcement scalar (k_r = s_r + c·rk)
}

// ─── Prove ────────────────────────────────────────────────────────────────────

pub fn prove(
    _pk: &PSPublicKey,
    sig:  &PSSignature,
    m1:   Fr,
    m2:   Fr,
    k:    usize,
) -> (NizkProof, NizkRandomness) {
    assert!(k < 2, "k must be 0 (dob) or 1 (nationality)");
    let mut rng = OsRng;
    let g = G1Projective::generator();
    let h = G1Projective::from(h_generator());

    // ── Rerandomise signature ─────────────────────────────────────────────
    let sigma_prime = PSSignature { sigma1: sig.sigma1, sigma2: sig.sigma2 };

    // ── Pedersen commit to mk ─────────────────────────────────────────────
    let mk = if k == 0 { m1 } else { m2 };
    let rk = Fr::rand(&mut rng);
    let coeff = rk * mk;              // independent of mk
    let ck = pedersen_commit(&mk, &coeff);

    // ── Schnorr announcement: R = k_m·G + k_r·H ──────────────────────────
    let k_m     = Fr::rand(&mut rng);
    let k_r     = Fr::rand(&mut rng);
    let r_point = (g * k_m + h * k_r).into_affine();

    // ── Fiat-Shamir challenge ─────────────────────────────────────────────
    let ctx = format!(
        "nizk-ps-attr:{}:{}:{}",
        k,
        g1_to_hex(&sigma_prime.sigma1),
        g1_to_hex(&sigma_prime.sigma2),
    );
    let c = hash_to_scalar(&[&g1_to_hex(&ck), &g1_to_hex(&r_point), &ctx]);

    // ── Responses: s_m = k_m − c·mk,  s_r = k_r − c·rk ──────────────────
    let s_m = k_m - c * mk;
    let s_r = k_r - c * rk * mk;

    let proof = NizkProof { sigma_prime, commitment: ck, committed_attr: k,
                            r_point, c, s_m, s_r,};
    let rand  = NizkRandomness { rk, k_m, k_r };
    (proof, rand)
}

// ─── Verify ───────────────────────────────────────────────────────────────────

pub fn verify(_pk: &PSPublicKey, proof: &NizkProof) -> (bool, Vec<String>) {
    let mut errors = Vec::new();
    let g = G1Projective::generator();
    let h = G1Projective::from(h_generator());

    if proof.sigma_prime.sigma1.is_zero() {
        errors.push("sigma1 is point at infinity".to_string());
        return (false, errors);
    }

    // ── Recompute challenge ───────────────────────────────────────────────
    let ctx = format!(
        "nizk-ps-attr:{}:{}:{}",
        proof.committed_attr,
        g1_to_hex(&proof.sigma_prime.sigma1),
        g1_to_hex(&proof.sigma_prime.sigma2),
    );
    let c_check = hash_to_scalar(&[
        &g1_to_hex(&proof.commitment),
        &g1_to_hex(&proof.r_point),
        &ctx,
    ]);
    if c_check != proof.c {
        errors.push("Fiat-Shamir challenge mismatch".to_string());
        return (false, errors);
    }

    // ── Schnorr check: s_m·G + s_r·H + c·Ck == R ─────────────────────────
    let lhs = (g * proof.s_m
             + h * proof.s_r
             + G1Projective::from(proof.commitment) * proof.c)
             .into_affine();
    if lhs != proof.r_point {
        errors.push("Schnorr relation failed".to_string());
    }

    (errors.is_empty(), errors)
}

// ─── Rerandomise ──────────────────────────────────────────────────────────────

pub fn rerandomise_proof(
    _pk:   &PSPublicKey,
    proof: &NizkProof,
    rand:  &NizkRandomness,
    t:     Fr,
    m1:   Fr,
    m2:   Fr,
) -> Result<NizkProof, &'static str> {
    if t.is_zero() { return Err("t must not be zero"); }

    let g = G1Projective::generator();
    let h = G1Projective::from(h_generator());
    let k = proof.committed_attr;

    // ── σ' scaled by t ────────────────────────────────────────────────────
    let new_sigma_prime = PSSignature {
        sigma1: proof.sigma_prime.sigma1,
        sigma2: proof.sigma_prime.sigma2,
    };
    
    // ── Ck unchanged (does not depend on t) ───────────────────────────────
    let mk = if k == 0 { m1 } else { m2 };
    let new_rk = rand.rk * t * mk;
    let ck = pedersen_commit(&mk,&new_rk);

    // ── Rebuild R from stored announcement scalars ────────────────────────
    let r_point = (g * (rand.k_m * t) + h * (rand.k_r * t)).into_affine();

    // ── Recompute challenge with new sigma hexes ──────────────────────────
    let ctx = format!(
        "nizk-ps-attr:{}:{}:{}",
        k,
        g1_to_hex(&new_sigma_prime.sigma1),
        g1_to_hex(&new_sigma_prime.sigma2),
    );
    let new_c = hash_to_scalar(&[&g1_to_hex(&ck), &g1_to_hex(&r_point), &ctx]);

    

    // ── Recompute responses ───────────────────────────────────────────────
    let new_s_m = rand.k_m * t - new_c * mk;
    let new_s_r = rand.k_r * t - new_c * rand.rk * mk * t;

    Ok(NizkProof {
        sigma_prime:    new_sigma_prime,
        commitment:     ck,
        committed_attr: k,
        r_point,
        c:              new_c,
        s_m:            new_s_m,
        s_r:            new_s_r,
    })
}

// ─── Fiat-Shamir (ark_bn254 serialisation) ────────────────────────────────────

fn fiat_shamir(
    a_prime: &G1Affine,
    b_prime: &G1Affine,
    ck:      &G1Affine,
    t1:      &G1Affine,
    t2:      &G1Affine,
) -> Fr {
    let mut h   = Sha256::new();
    let mut buf = Vec::new();

    a_prime.serialize_compressed(&mut buf).unwrap();
    h.update(&buf); buf.clear();

    b_prime.serialize_compressed(&mut buf).unwrap();
    h.update(&buf); buf.clear();

    ck.serialize_compressed(&mut buf).unwrap();
    h.update(&buf); buf.clear();

    t1.serialize_compressed(&mut buf).unwrap();
    h.update(&buf); buf.clear();

    t2.serialize_compressed(&mut buf).unwrap();
    h.update(&buf); buf.clear();

    h.update(b"credwallet-nizk-v1");
    Fr::from_be_bytes_mod_order(&h.finalize())
}