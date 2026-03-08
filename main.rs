// ─── main.rs ──────────────────────────────────────────────────────────────────
//
// Integration test for prove_credential / verify_credential_proof.
//
// Usage:
//   cargo run -- age 18 99
//   cargo run -- nationality 826
//   cargo run -- both 18 99 826
//   cargo run                     (runs all three)

pub mod bn254_ps;
pub mod wallet_core;
pub mod credential_machine;
pub mod circuits;


use anyhow::{bail, Result};
use std::env;
use ark_bn254::Fr;

use crate::bn254_ps::{ps_keygen, ps_sign, attribute_to_scalar};
use crate::wallet_core::{
    CredentialRequest, CredentialProof,
    prove_credential, verify_credential_proof};
    


fn main() -> Result<()> {
    // ── Issuer: generate keypair and sign credential ───────────────────────
    // Holder: born 19920315, nationality 826 (GBR), age 33 in 2026.
    let kp          = ps_keygen(2);
    let dob         = 19_920_315_u64;
    let nationality = 826_u64;
    let m1          = Fr::from(dob);
    let m2          = Fr::from(nationality);
    let sig         = ps_sign(&[m1, m2], &kp.sk);
    println!("✓ credential issued");


    // ── Holder: prove age ∈ [18, 99] and nationality == 826 ───────────────
    let request = CredentialRequest::both(18, 99, 826);
    let (proof, pp) = prove_credential(
        &sig,
        dob,
        nationality,
        &request,
        "test-verifier",
        "test-challenge-001",
        &kp.pk,
    )?;
    println!("✓ proof generated ({} bytes)", proof.compressed_bytes.len());

    // ── Verifier: verify ──────────────────────────────────────────────────
    verify_credential_proof(
        &proof, &kp.pk, &pp, &(proof.z_0), "test-challenge-001",
    )?;
    println!("✓ proof verified");

    Ok(())
}