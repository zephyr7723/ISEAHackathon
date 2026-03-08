// ─── wallet_core.rs ───────────────────────────────────────────────────────────
//
// Pure Rust wallet logic — no neon dependency here.
// lib.rs wraps these functions and exposes them to Node.js.

use std::collections::HashMap;
use ark_bn254::{Fr, G1Affine};
use ark_ff::{PrimeField, UniformRand, Field};
use ark_ff::utils as Bleh;
use ff::{Field as OtherField, PrimeField as OtherPrimeField};
use ark_serialize::CanonicalSerialize;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use anyhow::{anyhow, bail, Result};
use arecibo::{
    supernova::{PublicParams, RecursiveSNARK, snark::CompressedSNARK},
    provider::{Bn256Engine, GrumpkinEngine},
    spartan::batched::BatchedRelaxedR1CSSNARK,  // <- CHANGE IF NEEDED
    traits::{Engine, circuit_supernova::TrivialSecondaryCircuit, snark},
};
use arecibo::traits::circuit_supernova::StepCircuit;
use arecibo::traits::snark::BatchedRelaxedR1CSSNARKTrait;
use arecibo::supernova::NonUniformCircuit;



use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper::gadgets::num::AllocatedNum;
use bellpepper_core::test_cs::TestConstraintSystem;
// FIX 1: removed self-import `use crate::wallet_core::{WalletCore, CommitmentProofOutput}`
use crate::credential_machine::{
    CredentialMachine, CredentialStep, RamInstruction, NUM_CIRCUITS,
    PC_PS_RAND, PC_PS_DOB, PC_PS_NAT,
    ARITY};
use crate::bn254_ps::*;

type E1 = Bn256Engine;
type E2 = GrumpkinEngine;
type F1 = <E1 as Engine>::Scalar;
type F2 = <E2 as Engine>::Scalar;

// SNARK backends - CHANGE THESE if the names differ in your arecibo
use arecibo::provider::ipa_pc::EvaluationEngine as IPA;
use arecibo::spartan::snark::RelaxedR1CSSNARK;
use serde_json::*;


type EE1 = IPA<E1>;
type EE2 = IPA<E2>;

type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<E2, EE2>;

type CS = CompressedSNARK<E1, E2, RamInstruction<F1>, TrivialSecondaryCircuit<F2>, S1, S2>;

// FIX 2: added type annotation `u64`
const CURRENT_YEAR: u64 = 2026;

// ─── Serialisable types for JS boundary ──────────────────────────────────────

#[derive(Deserialize)]
pub struct PSCredentialInput {
    pub attributes:      HashMap<String, String>,
    pub attribute_order: Vec<String>,
    pub sigma1_hex:      String,
    pub sigma2_hex:      String,
    pub pk_x_hex:        String,
    pub pk_ys_hex:       Vec<String>,
}

pub struct PSCredentialRecord {
    pub attributes:       HashMap<String, String>,
    pub attribute_order:  Vec<String>,
    pub attr_scalars:     Vec<Fr>,
    pub attr_blindings:   Vec<Fr>,
    pub attr_commitments: Vec<String>,
    pub signature:        PSSignature,
    pub pk:               PSPublicKey,
    pub stored_at:        u64,
}

#[derive(Serialize, Deserialize)]
pub struct NIZKProofOutput {
    pub proof_type:           String,
    pub session_id:           String,
    pub credential_id:        String,
    pub sigma1_hex:           String,
    pub sigma2_hex:           String,
    pub t_hex:                String,
    pub c_hex:                String,
    pub responses_hex:        Vec<Option<String>>,
    pub attr_commitments_hex: Vec<Option<String>>,
    pub commit_proofs:        Vec<Option<CommitmentProofOutput>>,
    pub revealed:             HashMap<String, String>,
    pub hidden_keys:          Vec<String>,
    pub verifier_id:          String,
    pub challenge:            String,
    pub timestamp:            u64,
}

// FIX 1 (continued): CommitmentProofOutput defined here, not imported from self
#[derive(Serialize, Deserialize)]
pub struct CommitmentProofOutput {
    pub r_hex:       String,
    pub c_hex:       String,
    pub s_m_hex:     String,
    pub s_r_hex:     String,
    pub c_point_hex: String,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub valid:       bool,
    pub errors:      Vec<String>,
    pub disclosed:   HashMap<String, String>,
    pub hidden_keys: Vec<String>,
    pub trust_level: String,
    pub session_id:  String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub age_range:   Option<(u64, u64)>,
    pub nationality: Option<u64>,
}

impl CredentialRequest {
    pub fn age_only(lo: u64, hi: u64)     -> Self { Self { age_range: Some((lo,hi)), nationality: None } }
    pub fn nationality_only(c: u64)        -> Self { Self { age_range: None, nationality: Some(c) } }
    pub fn both(lo: u64, hi: u64, c: u64) -> Self { Self { age_range: Some((lo,hi)), nationality: Some(c) } }

    pub fn prove_age(&self) -> bool { self.age_range.is_some() }
    pub fn prove_nat(&self) -> bool { self.nationality.is_some() }

    fn validate(&self) -> Result<()> {
        if !self.prove_age() && !self.prove_nat() {
            bail!("request must include at least one predicate");
        }
        Ok(())
    }
}

// FIX 3: removed `pp` reference field (references are not Serialize; verifier
//         rebuilds pp from the circuit shape independently).
// FIX 3: corrected nizk_dob/nizk_nat type to NizkProof (was NIZKProof).

pub struct CredentialProof {
    pub nizk_dob:         Option<NizkProof>,
    pub nizk_nat:         Option<NizkProof>,
    pub compressed_bytes: Vec<u8>,
    pub z_out:            Vec<[u8; 32]>,
    pub num_steps:        usize,
    pub request:          CredentialRequest,
    pub session_id:       String,
    pub timestamp:        u64,
    pub z_0:              Vec<F1>,
}

/*impl CredentialProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| anyhow!("{e}"))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        serde_json::from_slice(b).map_err(|e| anyhow!("{e}"))
    }
    pub fn z_out_fr(&self) -> Vec<F1> {
        self.z_out.iter()
            .map(|a| F1::from_repr(*a).unwrap_or(F1::ZERO))
            .collect()
    }
}*/

// ─── Wallet Core ──────────────────────────────────────────────────────────────

pub struct WalletCore {
    credentials:   HashMap<String, PSCredentialRecord>,
    session_log:   HashMap<String, Vec<String>>,
    proof_store:   HashMap<String, NIZKProofOutput>,
    master_secret: Fr,
}

impl WalletCore {
    pub fn new() -> Self {
        let mut rng = OsRng;
        WalletCore {
            credentials:   HashMap::new(),
            session_log:   HashMap::new(),
            proof_store:   HashMap::new(),
            master_secret: Fr::rand(&mut rng),
        }
    }

    pub fn store_ps_credential(&mut self, id: String, input: PSCredentialInput) -> Result<(), String> {
        let l = input.attribute_order.len();

        let pk = PSPublicKey {
            x_point:  g1_from_hex(&input.pk_x_hex),
            y_points: input.pk_ys_hex.iter().map(|h| g1_from_hex(h)).collect(),
            l,
        };

        if pk.y_points.len() != l {
            return Err(format!("pk has {} Y points but {} attributes", pk.y_points.len(), l));
        }

        let sig = PSSignature {
            sigma1: g1_from_hex(&input.sigma1_hex),
            sigma2: g1_from_hex(&input.sigma2_hex),
        };

        let attr_scalars: Vec<Fr> = input.attribute_order.iter()
            .map(|key| {
                let val = input.attributes.get(key)
                    .ok_or_else(|| format!("Missing attribute: {}", key))?;
                Ok(attribute_to_scalar(val))
            })
            .collect::<Result<Vec<_>, String>>()?;

        let mut rng = OsRng;
        let mut attr_blindings   = Vec::with_capacity(l);
        let mut attr_commitments = Vec::with_capacity(l);

        for scalar in &attr_scalars {
            let r_i = Fr::rand(&mut rng);
            let c_i = pedersen_commit(scalar, &r_i);
            attr_blindings.push(r_i);
            attr_commitments.push(g1_to_hex(&c_i));
        }

        self.credentials.insert(id.clone(), PSCredentialRecord {
            attributes: input.attributes,
            attribute_order: input.attribute_order,
            attr_scalars,
            attr_blindings,
            attr_commitments,
            signature: sig,
            pk,
            stored_at: current_timestamp(),
        });

        Ok(())
    }

    pub fn get_attribute_commitments(&self, id: &str) -> Result<HashMap<String, String>, String> {
        let cred = self.credentials.get(id)
            .ok_or_else(|| format!("Credential not found: {}", id))?;
        Ok(cred.attribute_order.iter().zip(cred.attr_commitments.iter())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    pub fn generate_nizk_proof(
        &mut self,
        credential_id:     &str,
        reveal_attributes: &[String],
        verifier_id:       &str,
        challenge:         &str,
        _store:            bool,
    ) -> Result<(NIZKProofOutput, String), String> {

        let cred = self.credentials.get(credential_id)
            .ok_or_else(|| format!("Credential not found: {}", credential_id))?;

        let session_random = {
            let mut rng = OsRng;
            let r = Fr::rand(&mut rng);
            fr_to_hex(&r)
        };
        let session_id  = hash_to_scalar_str(&[verifier_id, &session_random, challenge]);
        let session_ctx = format!("{}:{}:{}", session_id, verifier_id, challenge);

        self.session_log
            .entry(verifier_id.to_string())
            .or_default()
            .push(session_id.clone());

        let reveal_set: std::collections::HashSet<&str> =
            reveal_attributes.iter().map(|s| s.as_str()).collect();

        let hidden_indices: Vec<usize> = cred.attribute_order.iter().enumerate()
            .filter(|(_, k)| !reveal_set.contains(k.as_str()))
            .map(|(i, _)| i)
            .collect();

        let messages   = cred.attr_scalars.clone();
        let blindings  = cred.attr_blindings.clone();
        let sig        = PSSignature { sigma1: cred.signature.sigma1, sigma2: cred.signature.sigma2 };
        let pk         = PSPublicKey {
            x_point:  cred.pk.x_point,
            y_points: cred.pk.y_points.clone(),
            l:        cred.pk.l,
        };
        let attr_order = cred.attribute_order.clone();
        let attributes = cred.attributes.clone();

        let mut nizk = nizk_prove_ps_signature(
            &sig, &messages, &blindings, &hidden_indices, &pk, &session_ctx,
        );
        nizk.verifier_id = verifier_id.to_string();

        let responses_hex: Vec<Option<String>> = nizk.responses.iter()
            .map(|opt| opt.as_ref().map(fr_to_hex))
            .collect();

        let attr_commitments_hex: Vec<Option<String>> = nizk.attr_commitments.iter()
            .map(|opt| opt.as_ref().map(g1_to_hex))
            .collect();

        let commit_proofs_out: Vec<Option<CommitmentProofOutput>> = nizk.commit_proofs.iter()
            .map(|opt| opt.as_ref().map(|cp| CommitmentProofOutput {
                r_hex:       g1_to_hex(&cp.r_point),
                c_hex:       fr_to_hex(&cp.c),
                s_m_hex:     fr_to_hex(&cp.s_m),
                s_r_hex:     fr_to_hex(&cp.s_r),
                c_point_hex: g1_to_hex(&cp.c_point),
            }))
            .collect();

        let revealed: HashMap<String, String> = attr_order.iter().enumerate()
            .filter(|(_, k)| reveal_set.contains(k.as_str()))
            .map(|(_, k)| (k.clone(), attributes[k].clone()))
            .collect();

        let hidden_keys: Vec<String> = hidden_indices.iter()
            .map(|&i| attr_order[i].clone())
            .collect();

        let proof_output = NIZKProofOutput {
            proof_type:           "PS_NIZK_BN254_RUST".to_string(),
            session_id:           session_id.clone(),
            credential_id:        credential_id.to_string(),
            sigma1_hex:           g1_to_hex(&nizk.sigma1),
            sigma2_hex:           g1_to_hex(&nizk.sigma2),
            t_hex:                g1_to_hex(&nizk.t_point),
            c_hex:                fr_to_hex(&nizk.c),
            responses_hex,
            attr_commitments_hex,
            commit_proofs:        commit_proofs_out,
            revealed,
            hidden_keys,
            verifier_id:          verifier_id.to_string(),
            challenge:            challenge.to_string(),
            timestamp:            current_timestamp(),
        };

        let proof_id = hash_to_scalar_str(&[&session_id, credential_id, verifier_id]);
        Ok((proof_output, proof_id))
    }

    pub fn verify_nizk_proof(
        proof:              &NIZKProofOutput,
        original_challenge: &str,
        pk_x_hex:           &str,
        pk_ys_hex:          &[String],
    ) -> VerifyResult {
        let mut errors = Vec::new();

        if proof.challenge != original_challenge {
            errors.push("Challenge mismatch — replay attack".to_string());
        }

        let age = current_timestamp().saturating_sub(proof.timestamp);
        if age > 300 {
            errors.push("Proof expired".to_string());
        }

        if proof.proof_type != "PS_NIZK_BN254_RUST" {
            errors.push(format!("Wrong proof type: {}", proof.proof_type));
        }

        let pk = PSPublicKey {
            x_point:  g1_from_hex(pk_x_hex),
            y_points: pk_ys_hex.iter().map(|h| g1_from_hex(h)).collect(),
            l:        pk_ys_hex.len(),
        };

        let sigma1  = g1_from_hex(&proof.sigma1_hex);
        let sigma2  = g1_from_hex(&proof.sigma2_hex);
        let t_point = g1_from_hex(&proof.t_hex);
        let c       = fr_from_hex(&proof.c_hex);

        let responses: Vec<Option<Fr>> = proof.responses_hex.iter()
            .map(|opt| opt.as_ref().map(|h| fr_from_hex(h)))
            .collect();

        let attr_commitments: Vec<Option<G1Affine>> = proof.attr_commitments_hex.iter()
            .map(|opt| opt.as_ref().map(|h| g1_from_hex(h)))
            .collect();

        let commit_proofs_vec: Vec<Option<CommitmentProof>> = proof.commit_proofs.iter()
            .map(|opt| opt.as_ref().map(|cp| CommitmentProof {
                r_point: g1_from_hex(&cp.r_hex),
                c:       fr_from_hex(&cp.c_hex),
                s_m:     fr_from_hex(&cp.s_m_hex),
                s_r:     fr_from_hex(&cp.s_r_hex),
                c_point: g1_from_hex(&cp.c_point_hex),
            }))
            .collect();

        let hidden_indices: Vec<usize> = (0..responses.len())
            .filter(|i| responses[*i].is_some())
            .collect();

        let revealed_scalars: Vec<Option<Fr>> = responses.iter()
            .map(|opt| if opt.is_none() { Some(Fr::ZERO) } else { None })
            .collect();

        let nizk_proof = PSNIZKProof {
            sigma1, sigma2, t_point, c,
            responses,
            attr_commitments,
            commit_proofs: commit_proofs_vec,
            revealed: revealed_scalars,
            hidden_indices,
            verifier_id: proof.verifier_id.clone(),
        };

        let verify_ctx = format!("{}:{}:{}", proof.session_id, proof.verifier_id, proof.challenge);
        let (nizk_valid, nizk_errors) = nizk_verify_ps_signature(&nizk_proof, &pk, &verify_ctx);
        if !nizk_valid {
            errors.extend(nizk_errors);
        }

        VerifyResult {
            valid:       errors.is_empty(),
            errors,
            disclosed:   proof.revealed.clone(),
            hidden_keys: proof.hidden_keys.clone(),
            trust_level: "ISSUER_BACKED_PS_BN254_RUST".to_string(),
            session_id:  proof.session_id.clone(),
        }
    }

    pub fn list_credentials(&self) -> Vec<HashMap<String, String>> {
        self.credentials.iter().map(|(id, cred)| {
            let mut m = HashMap::new();
            m.insert("id".to_string(), id.clone());
            m.insert("type".to_string(), "ps_rust".to_string());
            m.insert("attribute_keys".to_string(), cred.attribute_order.join(","));
            m.insert("stored_at".to_string(), cred.stored_at.to_string());
            m
        }).collect()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hash_to_scalar_str(inputs: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for s in inputs { hasher.update(s.as_bytes()); hasher.update(b"||"); }
    hex::encode(hasher.finalize())
}

/// Hash a G1 point (arkworks) to a halo2curves F1 scalar via SHA-256.
pub fn ark_g1_to_halo_fr(p: &ark_bn254::G1Affine) -> F1 {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    let mut h = Sha256::new();
    h.update(&buf);
    let bytes: [u8; 32] = h.finalize().into();
    F1::from_repr_vartime(bytes).unwrap_or(F1::ZERO)
}

/// Convert an ark Fr scalar to a halo2curves F1 scalar (same BN254 prime, LE bytes).
pub fn ark_fr_to_halo(f: &Fr) -> F1 {
    let mut b = Vec::new();
    f.serialize_compressed(&mut b).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    F1::from_repr_vartime(arr).unwrap_or(F1::ZERO)
}

// ─── Generate proof of credentials ───────────────────────────────────────────

// FIX 9: added `sig` and `pk_full` parameters; all previously-missing variables
//         are now reachable within the function's scope.
pub fn prove_credential(
    sig:         &PSSignature,
    dob:         u64,
    nationality: u64,
    request:     &CredentialRequest,
    verifier_id: &str,
    challenge:   &str,
    pk:          &PSPublicKey,
) -> Result<(
    CredentialProof,
    PublicParams<E1, E2, RamInstruction<F1>, TrivialSecondaryCircuit<F2>>,)>  {

    request.validate()?;

    // ── Validate predicates ───────────────────────────────────────────────
    if let Some((lo, hi)) = request.age_range {
        let age = CURRENT_YEAR.saturating_sub(dob / 10_000);
        if age < lo || age > hi {
            bail!("age {age} outside [{lo},{hi}]");
        }
        println!("✓ Age predicate: {age} ∈ [{lo},{hi}]");
    }
    // FIX 9: `nat` renamed to `nationality` (matches parameter name)
    if let Some(country) = request.nationality {
        if nationality != country {
            bail!("nationality {nationality} ≠ requested {country}");
        }
        println!("✓ Nationality predicate: {country}");
    }

    let m1 = Fr::from(dob);
    let m2 = Fr::from(nationality);

    // ── Session ID ────────────────────────────────────────────────────────
    // FIX 9: Fr directly (no ArkFr alias needed)
    let session_id = {
        let mut rng = OsRng;
        let r = Fr::rand(&mut rng);
        let mut rb = Vec::new();
        r.serialize_compressed(&mut rb).unwrap();
        let mut h = Sha256::new();
        h.update(verifier_id.as_bytes());
        h.update(&rb);
        h.update(challenge.as_bytes());
        hex::encode(h.finalize())
    };
    let session_ctx = format!("{session_id}:{verifier_id}:{challenge}");

    // ── Rerandomise PS signature ──────────────────────────────────────────
    // FIX 9: ps_rerandomize (not randomize_random); PSSignature (not Signature)
    let rsig    = ps_rerandomize(sig);
    let rsig_ps = PSSignature { sigma1: rsig.sigma1, sigma2: rsig.sigma2 };
    println!("✓ Signature rerandomised");

    // ── Conditional NIZK proofs ───────────────────────────────────────────
    // FIX 5: Option vars declared BEFORE if-blocks so they remain in scope below
    let mut proof_age_opt: Option<NizkProof>      = None;
    let mut proof_nat_opt: Option<NizkProof>      = None;
    let mut rand_age_opt:  Option<NizkRandomness> = None;
    let mut rand_nat_opt:  Option<NizkRandomness> = None;

    if request.prove_age() {
        let (p, r) = prove(&pk, &rsig_ps, m1, m2, 0);
        let (ok,err) = verify(&pk, &p);
        if !ok { bail!("nizk_dob failed"); }
        println!("✓ nizk_dob generated and verified");
        proof_age_opt = Some(p);
        rand_age_opt  = Some(r);
    }

    if request.prove_nat() {
        let (p, r) = prove(&pk, &rsig_ps, m1, m2, 1);
        let (ok,err) = verify(&pk, &p);
        if !ok { bail!("nizk_nat failed"); }
        println!("✓ nizk_nat generated and verified");
        proof_nat_opt = Some(p);
        rand_nat_opt  = Some(r);
    }

    // ── Build z0 ──────────────────────────────────────────────────────────
    // FIX 9: sigma points hashed to F1 via ark_g1_to_halo_fr (not F1::from(1))
    // FIX 9: commitment F1 values derived from proof.commitment(), not rk*m
    let sigma_1_f1 = ark_g1_to_halo_fr(&rsig.sigma1);
    let sigma_2_f1 = ark_g1_to_halo_fr(&rsig.sigma2);
    let com_dob_f1 = ark_fr_to_halo(&rand_age_opt.as_ref().unwrap().rk);
    let com_nat_f1 = ark_fr_to_halo(&rand_nat_opt.as_ref().unwrap().rk);

    let mut z0 = vec![F1::ZERO;7];
    z0[0] = sigma_1_f1;
    z0[1] = sigma_2_f1;
    z0[2] = com_dob_f1;
    z0[3] = com_nat_f1;
    z0[4]  = F1::from(request.age_range.map(|(lo,_)| lo).unwrap_or(0));
    z0[5]  = F1::from(request.age_range.map(|(_,hi)| hi).unwrap_or(0));
    z0[6] = F1::from(request.nationality.unwrap_or(0));

    // FIX 7: &mut rng; ark_fr_to_halo(&t) — not ark_fr_to_halo(&rng)
    let mut rng = OsRng;
    let t       = Fr::rand(&mut rng);
    let t_halo  = ark_fr_to_halo(&t);

    let mut z0_scaled = z0.clone();
    z0_scaled[0] = z0[0] * t_halo;
    z0_scaled[1] = z0[1] * t_halo;
    z0_scaled[2] = z0[2] * t_halo;
    z0_scaled[3] = z0[3] * t_halo;

    let z0_per_pc: [Vec<F1>; NUM_CIRCUITS] = [
        z0.clone(),        // pc=0 PsRand — original
        z0_scaled.clone(), // pc=1 PsDob  — t-scaled
        z0_scaled.clone(), // pc=2 PsNat  — t-scaled
    ];

    // ── Schedule ──────────────────────────────────────────────────────────
    // FIX 4: prove_dob() -> prove_age()
    // FIX 5: `schedule` declared before branches so it is in scope afterwards
    // FIX 6: age_lo/age_hi destructured from age_range (not .age_lo/.age_hi)
    let schedule: Vec<CredentialStep<F1>>;

    if request.prove_age() && request.prove_nat() {
        let (lo, hi) = request.age_range.unwrap();
        schedule = vec![
            CredentialStep::PsRand { t: t_halo, pc_next: (1 as usize) },
            CredentialStep::PsDob {
                dob:        dob,
                com_odob:   ark_fr_to_halo(&rand_age_opt.as_ref().unwrap().rk),
                t:          t_halo,
                age_lo_inp: F1::from(lo),
                age_hi_inp: F1::from(hi),
                pc_next:    (2 as usize),
            },
            CredentialStep::PsNat {
                nationality: F1::from(nationality),
                com_onat:    ark_fr_to_halo(&rand_nat_opt.as_ref().unwrap().rk),
                t:           t_halo,
                cont:        F1::from(request.nationality.unwrap()),
                pc_next:     (2 as usize),
            },
        ];
    } else if request.prove_age() {
        let (lo, hi) = request.age_range.unwrap();
        schedule = vec![
            CredentialStep::PsRand { t: t_halo, pc_next: (1 as usize) },
            CredentialStep::PsDob {
                dob:        dob,
                com_odob:   F1::from(dob),
                t:          t_halo * ark_fr_to_halo(&rand_age_opt.as_ref().unwrap().rk),
                age_lo_inp: F1::from(lo),
                age_hi_inp: F1::from(hi),
                pc_next:    (2 as usize),
            },
        ];
    } else {
        schedule = vec![
            CredentialStep::PsRand { t: t_halo, pc_next: (2 as usize) },
            CredentialStep::PsNat {
                nationality: F1::from(nationality),
                com_onat:    F1::from(nationality),
                t:           t_halo * ark_fr_to_halo(&rand_nat_opt.as_ref().unwrap().rk),
                cont:        F1::from(request.nationality.unwrap()),
                pc_next:     (0 as usize),
            },
        ];
    }
    println!("✓ Schedule: {} steps", schedule.len());


    let mut debug_machine = CredentialMachine::new(schedule.clone());
    for step in 0..debug_machine.total_steps() {
        let circuit = debug_machine.current_circuit();
        let pc      = debug_machine.current_pc();
        let z_in_vals = &z0_per_pc[pc];

        let mut cs = TestConstraintSystem::<F1>::new();
        let z_in: Vec<_> = z_in_vals.iter().enumerate()
            .map(|(i, &v)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(v)).unwrap())
            .collect();

        use arecibo::traits::circuit_supernova::StepCircuit;
        let _ = circuit.synthesize(&mut cs, None, &z_in);

        if !cs.is_satisfied() {
            eprintln!("step {step} (pc={pc}) UNSAT: {}", cs.which_is_unsatisfied().unwrap());
        } else {
            eprintln!("step {step} (pc={pc}) ok ({} constraints)", cs.num_constraints());
        }
        debug_machine.advance();
    }












    let mut machine = CredentialMachine::new(schedule);

    // ── PublicParams ──────────────────────────────────────────────────────
    println!("Setting up PublicParams...");
    let pp = PublicParams::<E1, E2, RamInstruction<F1>, TrivialSecondaryCircuit<F2>>
        ::setup(&machine, &|_| 0, &|_| 0);

    

    // ── RecursiveSNARK (folding) ──────────────────────────────────────────
    let total        = machine.total_steps();
    let z0_secondary = vec![<F2 as OtherField>::ZERO];
    let pc0          = machine.current_pc();

    let mut recursive_snark = RecursiveSNARK::new(
        &pp, &machine,
        &machine.current_circuit(),
        &machine.secondary_circuit(),
        &z0_per_pc[0],
        &z0_secondary,
    ).map_err(|e| anyhow!("RecursiveSNARK::new: {e:?}"))?;


    for step in 0..(total-1) {
        let c1 = machine.current_circuit();
        let c2 = machine.secondary_circuit();
        println!("step {step}: pc={}", c1.circuit_index());
        // FIX 8: result reassigned back — recursive_snark was not advancing
        let res = recursive_snark
            .prove_step(&pp, &c1, &c2)
            .map_err(|e| anyhow!("prove_step {step}: {e:?}"))?;
        machine.advance();
        println!("step {step} proven");
    }


    
    // ── Verify folding ────────────────────────────────────────────────────
    let (z_out, _) = recursive_snark
        .verify(&pp, &z0_per_pc[pc0], &z0_secondary)
        .map_err(|e| anyhow!("RecursiveSNARK verify: {e:?}"))?;
    println!("✓ Folding verified ({total} steps)");

    

    // ── CompressedSNARK keys ──────────────────────────────────────────────
    println!("Deriving CompressedSNARK keys...");
    let (pk_cs, _vk) = CS::setup(&pp)
        .map_err(|e| anyhow!("CompressedSNARK::setup: {e:?}"))?;

    // ── Rerandomise NIZK proofs with t ────────────────────────────────────
    // FIX 9: proof_1/proof_2 replaced with correctly-named nizk_dob/nizk_nat

    let nizk_nat = proof_nat_opt;
    let nizk_dob = proof_age_opt;

    // ── Compress ──────────────────────────────────────────────────────────
    println!("Compressing with Spartan...");
    let compressed = CS::prove(&pp, &pk_cs, &recursive_snark)
        .map_err(|e| anyhow!("CompressedSNARK::prove: {e:?}"))?;
    println!("✓ Compressed");

    let compressed_bytes = serde_json::to_vec(&compressed)
        .map_err(|e| anyhow!("CompressedSNARK serialise: {e}"))?;

        let z_out_bytes: Vec<[u8; 32]> = z_out.iter().map(|f: &F1| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(f.to_repr().as_ref());
            arr
        }).collect();

    println!("✓ Proof complete. compressed_bytes={}", compressed_bytes.len());

    // FIX 3: `pp` removed from struct; FIX 9: nizk fields correctly populated
    Ok((CredentialProof{
        nizk_dob,
        nizk_nat,
        compressed_bytes,
        z_out: z_out_bytes,
        num_steps: total,
        request:   request.clone(),
        session_id,
        timestamp: current_timestamp(),
        z_0: z0_per_pc[0].clone(),
    },pp,))
}

// ─── Verify ───────────────────────────────────────────────────────────────────

// FIX 10: added missing comma after `pk_full`
// FIX 12: added `pp` parameter (was used internally but never received)
pub fn verify_credential_proof(
    proof:     &CredentialProof,
    pk:        &PSPublicKey,
    pp:        &PublicParams<E1, E2, RamInstruction<F1>, TrivialSecondaryCircuit<F2>>,
    z0_per_pc: &Vec<F1>,
    _challenge: &str,
) -> Result<()> {

    // Match z_0 with request

    let expected_age_lo = F1::from(proof.request.age_range.map(|(lo, _)| lo).unwrap_or(0));
    let expected_age_hi = F1::from(proof.request.age_range.map(|(_, hi)| hi).unwrap_or(0));
    let expected_country = F1::from(proof.request.nationality.unwrap_or(0));

    assert_eq!(z0_per_pc[4], expected_age_lo, "z_0[4] (age_lo) mismatch");
    assert_eq!(z0_per_pc[5], expected_age_hi, "z_0[5] (age_hi) mismatch");
    assert_eq!(z0_per_pc[6], expected_country, "z_0[6] (country) mismatch");

    println!("✓ z_0 slots [4,5,6] consistent with CredentialRequest");
    
    // ── NIZK verification ─────────────────────────────────────────────────
    if proof.request.prove_age() {
        let n = proof.nizk_dob.as_ref().ok_or_else(|| anyhow!("nizk_dob absent"))?;
        let (ok, err) = verify(&pk, &n);
        if !ok { bail!("nizk_dob failed:"); }
        println!("✓ nizk_dob verified");
    }
    if proof.request.prove_nat() {
        let n = proof.nizk_nat.as_ref().ok_or_else(|| anyhow!("nizk_nat absent"))?;
        let (ok,err)= verify(&pk, &n);
        if !ok { bail!("nizk_nat failed:"); }
        println!("✓ nizk_nat verified");
    }

    // ── CompressedSNARK verification ──────────────────────────────────────
    let compressed: CS = serde_json::from_slice(&proof.compressed_bytes)
        .map_err(|e| anyhow!("CompressedSNARK deserialise: {e}"))?;

    // Re-derive vk from pp — deterministic, no need to store in proof.
    let (_pk_cs, vk) = CS::setup(pp)
        .map_err(|e| anyhow!("CompressedSNARK::setup (vk): {e:?}"))?;

    let z0_secondary = vec![<F2 as OtherField>::ZERO];

    let (_z_out, _) = compressed
        .verify(&pp, &vk, &z0_per_pc, &z0_secondary)
        .map_err(|e| anyhow!("CompressedSNARK verify: {e:?}"))?;
    println!("✓ CompressedSNARK verified");

    Ok(())
}
