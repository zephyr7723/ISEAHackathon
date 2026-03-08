/// ps_nat_circuit.rs
///
/// PS nationality circuit
/// ======================
///
/// SPECIFICATION
/// -------------
/// ps_nat_circuit(sig, com_cdob, com_cnat, country,
///                nationality, com_onat, t):
///
///   If inputs are garbage (any of sig_s1, sig_s2, com_cnat == 0):
///     output (sig, com_cdob, com_cnat) unchanged
///
///   Else if nationality == country  AND  com_onat * t == com_cnat:
///     output (sig, com_cdob, com_cnat)
///
///   Else:
///     output (0, 0, 0)
///
/// OUTPUT SELECTOR DERIVATION
/// ---------------------------
/// Let ok_inputs = 1 iff inputs are non-garbage.
/// Let ok_checks = 1 iff nationality == country AND com_onat * t == com_cnat.
///
/// We want:
///   garbage inputs  (ok_inputs=0): output z_in unchanged
///   checks pass     (ok_inputs=1, ok_checks=1): output z_in
///   checks fail     (ok_inputs=1, ok_checks=0): output 0
///
/// Both "garbage" and "checks pass" output z_in; only "non-garbage + fail"
/// outputs zero.  Define:
///
///   fail = ok_inputs * (1 - ok_checks)   [1 only when non-garbage and failing]
///   z_out[i] = (1 - fail) * z_in[i]
///
/// Expanding: (1 - fail) = 1 - ok_inputs + ok_inputs * ok_checks
///
/// Implementation uses two wires:
///   fail    = ok_inputs * (1 - ok_checks)    1 constraint
///   pass    = 1 - fail  (linear, no constraint)
///   z_out[i] = pass * z_in[i]                1 constraint per output
///
/// PUBLIC INPUTS  z_in  [6 wires]
/// --------------------------------
///   [0]  sig_s1    -- sigma_1 of PS signature
///   [1]  sig_s2    -- sigma_2 of PS signature
///   [2]  com_cdob  -- current randomised dob commitment (passed through)
///   [3]  com_cnat  -- current randomised nationality commitment
///   [4]  country   -- hash(country_name) to match against (public)
///   [5]  (unused slot reserved for symmetry with ps_dob_circuit)
///        In practice age_lo / age_hi are not needed here; slot [5]
///        carries a constant 0 or can be repurposed by the caller.
///
/// PRIVATE WITNESSES  [3 wires]
/// -----------------------------
///   nationality  -- hash(nationality_string) held by the prover
///   com_onat     -- original commitment to nationality: G^(nationality) * H^r
///                   encoded as a scalar field element
///   t            -- randomisation scalar: com_cnat = com_onat * t
///
/// WHAT THE CIRCUIT CHECKS (only when inputs are non-garbage)
/// -----------------------------------------------------------
///   (A) nationality == country
///       Pure field equality: the private nationality hash matches the
///       public country hash.  Encoded as nationality - country == 0.
///
///   (B) com_onat * t == com_cnat
///       The current commitment is the original raised to t.
///       Same scalar encoding as in ps_dob_circuit.
///
/// CONSTRAINTS
/// -----------
///   (a,b)  is_nonzero(sig_s1)      2  }
///   (c,d)  is_nonzero(sig_s2)      2  } non-garbage  6 total
///   (e,f)  is_nonzero(com_cnat)    2  }
///          ok_s1s2 = ok_s1 AND ok_s2    1
///          ok_inputs = ok_s1s2 AND ok_com  1             2 total
///   (g)    ok_nat: (nat - country) * ok_nat_inv == ok_eq  1 }
///          (1 - ok_eq) * (nat - country) == 0             1 } equality  3 total
///          ok_nat = ok_eq (alias)
///   (h)    com_onat * t == com_cnat                       1  randomisation
///          ok_checks = ok_nat AND ok_rand                 1  2 total
///   (i)    fail = ok_inputs * (1 - ok_checks)             1
///   (j-l)  (1-fail) * z_in[i] == z_out[i]   i=0,1,2,3   4  conditional
///   -----------------------------------------------------------
///   TOTAL                                               ~20 constraints

use bellpepper_core::{
    boolean::AllocatedBit,
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use arecibo::traits::circuit_supernova::StepCircuit;
use ff::PrimeField;

// ---------------------------------------------------------------------------
// Witness struct
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PsNatCircuit<F: PrimeField> {
    /// hash(nationality_string) held by the prover.
    pub nationality: Option<F>,
    /// Original commitment to nationality, encoded as a scalar.
    pub com_onat: Option<F>,
    /// Randomisation scalar: com_cnat = com_onat * t.
    pub t: Option<F>,
    /// Country name supplied by verifier
    pub cont: Option<F>,
    pub pc_next: Option<F>, 
}

impl<F: PrimeField> PsNatCircuit<F> {
    pub fn new(nationality: F, com_onat: F, t: F, cont: F, pc_next: usize) -> Self {
        Self {
            nationality: Some(nationality),
            com_onat:    Some(com_onat),
            t:           Some(t),
            cont: Some(cont),
            pc_next: Some(F::from(pc_next as u64)),
        }
    }

    pub fn blank() -> Self {
        Self { nationality: None, com_onat: None, t: None, cont: None, pc_next: None }
    }
}

// ---------------------------------------------------------------------------
// Public input builder
// ---------------------------------------------------------------------------

/// Build z_in from the six public values.
/// country is a hash value matching the prover's private nationality.
/// slot [5] is a padding zero; callers may repurpose it.


// ---------------------------------------------------------------------------
// StepCircuit
// ---------------------------------------------------------------------------

impl<F: PrimeField> PsNatCircuit<F> {
    pub fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        synthesize_ps_nat(cs, z_in, self)
    }
}

// ---------------------------------------------------------------------------
// Core synthesis
// ---------------------------------------------------------------------------

fn synthesize_ps_nat<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    z_in: &[AllocatedNum<F>],
    w: &PsNatCircuit<F>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {

    let sig_s1   = &z_in[0];
    let sig_s2   = &z_in[1];
    let com_cdob = &z_in[2];
    let com_cnat = &z_in[3];
    let age_lo = &z_in[4];
    let age_hi = &z_in[5];
    let country  = &z_in[6];

    // =========================================================================
    // STEP 1 -- Allocate private witness wires
    // =========================================================================

    let nat_wire = AllocatedNum::alloc(
        cs.namespace(|| "nationality"),
        || w.nationality.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let com_onat_wire = AllocatedNum::alloc(
        cs.namespace(|| "com_onat"),
        || w.com_onat.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let t_wire = AllocatedNum::alloc(
        cs.namespace(|| "t"),
        || w.t.ok_or(SynthesisError::AssignmentMissing),
    )?;
    
    let cont_wire = AllocatedNum::alloc(
        cs.namespace(|| "cont"),
        || w.cont.ok_or(SynthesisError::AssignmentMissing),
    )?;

    cs.enforce(
        || "correct commitment",
        |lc| lc + nat_wire.get_variable() - com_onat_wire.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );

    let com_cnat_wire = com_cnat.clone();

    // =========================================================================
    // STEP 2 -- Non-garbage check on public inputs
    // =========================================================================
    // ok_inputs = 1 iff sig_s1 != 0 AND sig_s2 != 0 AND com_cnat != 0.
    // When ok_inputs = 0 we pass z_in through unchanged (see step 5).

    let ok_s1  = is_nonzero(cs.namespace(|| "ok_s1"),  sig_s1)?;
    let ok_s2  = is_nonzero(cs.namespace(|| "ok_s2"),  sig_s2)?;
    let ok_com = is_nonzero(cs.namespace(|| "ok_com"), com_cnat)?;

    let ok_s1s2   = alloc_and(cs.namespace(|| "ok_s1 AND ok_s2"),    &ok_s1, &ok_s2)?;
    let ok_inputs = alloc_and(cs.namespace(|| "ok_s1s2 AND ok_com"), &ok_s1s2, &ok_com)?;

    // =========================================================================
    // STEP 3 -- Nationality equality check
    // =========================================================================
    // Check nationality == country (both are hash values as field elements).
    //
    // Encoding:
    //   diff = nat_wire - country
    //   ok_eq = is_zero(diff)  i.e. 1 iff nat_wire == country
    //
    // We use the complement of is_nonzero: allocate ok_eq as a Boolean
    // where ok_eq = 1 iff diff == 0.
    //
    //   diff * inv    == ok_nz        (ok_nz = 1 iff diff != 0)
    //   (1 - ok_nz) * diff == 0
    //   ok_eq = 1 - ok_nz             (linear, no constraint)


    let diff_wire = AllocatedNum::alloc(
        cs.namespace(|| "diff = nationality - country"),
        || {
            let n = nat_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let c = cont_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(n - c)
        },
    )?;
    // diff = nat_wire - country  (linear combination, no R1CS constraint needed;
    // we enforce it implicitly by using diff_wire in the constraints below)
    cs.enforce(
        || "diff == nationality - country",
        |lc| lc + nat_wire.get_variable() - country.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + diff_wire.get_variable(),
    );

    // ok_nz_diff = 1 iff nationality != country
    let ok_nz_diff = is_nonzero(cs.namespace(|| "ok_nz_diff"), &diff_wire)?;

    // ok_eq = 1 - ok_nz_diff  (nationality == country)
    // Represented as an AllocatedNum to use in AND gates below.
    let ok_eq_wire = AllocatedNum::alloc(
        cs.namespace(|| "ok_eq = 1 - ok_nz_diff"),
        || {
            let nz = ok_nz_diff.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(if nz { F::ZERO } else { F::ONE })
        },
    )?;
    cs.enforce(
        || "ok_eq + ok_nz_diff == 1",
        |lc| lc + ok_eq_wire.get_variable() + ok_nz_diff.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
    );

    // =========================================================================
    // STEP 4 -- Commitment randomisation check
    // =========================================================================
    // Check com_onat * t == com_cnat.
    //
    // This binds the prover's original nationality commitment to the
    // current public commitment.  If t is wrong or com_onat is wrong,
    // the check fails and ok_rand = 0.
    //
    // We encode this as a conditional check: the constraint must hold
    // when ok_inputs = 1, and we capture the result in ok_rand.
    //
    // Standard approach: allocate the product as a wire and allocate
    // ok_rand as a Boolean measuring whether the product matches com_cnat.

    let product_wire = AllocatedNum::alloc(
        cs.namespace(|| "com_onat * t"),
        || {
            let o = com_onat_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let t = t_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(o * t)
        },
    )?;
    cs.enforce(
        || "com_onat * t == product",
        |lc| lc + com_cnat_wire.get_variable() - product_wire.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );

    // diff_rand = product - com_cnat;  ok_rand = is_zero(diff_rand)
    let diff_rand = AllocatedNum::alloc(
        cs.namespace(|| "diff_rand = product - com_cnat"),
        || {
            let p = product_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let c = com_cnat.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(p - c)
        },
    )?;
    cs.enforce(
        || "diff_rand == product - com_cnat",
        |lc| lc + product_wire.get_variable() - com_cnat.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + diff_rand.get_variable(),
    );

    let ok_nz_rand = is_nonzero(cs.namespace(|| "ok_nz_rand"), &diff_rand)?;

    // ok_rand = 1 - ok_nz_rand  (product == com_cnat)
    let ok_rand_wire = AllocatedNum::alloc(
        cs.namespace(|| "ok_rand = 1 - ok_nz_rand"),
        || {
            let nz = ok_nz_rand.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(if nz { F::ZERO } else { F::ONE })
        },
    )?;
    cs.enforce(
        || "ok_rand + ok_nz_rand == 1",
        |lc| lc + ok_rand_wire.get_variable() + ok_nz_rand.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
    );

    // =========================================================================
    // STEP 5 -- Compute fail flag and output selector
    // =========================================================================
    // ok_checks = ok_eq AND ok_rand
    // fail      = ok_inputs * (1 - ok_checks)
    //           = ok_inputs - ok_inputs * ok_checks
    //
    // Output rule:
    //   z_out[i] = (1 - fail) * z_in[i]
    //
    // When fail = 0 (garbage input OR checks pass): z_out = z_in
    // When fail = 1 (non-garbage input AND checks fail): z_out = 0

    // ok_checks = ok_eq AND ok_rand  (both encoded as AllocatedNum with 0/1 values)
    let ok_checks_wire = AllocatedNum::alloc(
        cs.namespace(|| "ok_checks = ok_eq * ok_rand"),
        || {
            let e = ok_eq_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let r = ok_rand_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(e * r)
        },
    )?;
    cs.enforce(
        || "ok_eq * ok_rand == ok_checks",
        |lc| lc + ok_eq_wire.get_variable(),
        |lc| lc + ok_rand_wire.get_variable(),
        |lc| lc + ok_checks_wire.get_variable(),
    );

    // ok_inputs_times_checks = ok_inputs * ok_checks
    let ok_inputs_checks = AllocatedNum::alloc(
        cs.namespace(|| "ok_inputs * ok_checks"),
        || {
            let i = if ok_inputs.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                F::ONE
            } else {
                F::ZERO
            };
            let c = ok_checks_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(i * c)
        },
    )?;
    cs.enforce(
        || "ok_inputs * ok_checks == ok_inputs_checks",
        |lc| lc + ok_inputs.get_variable(),
        |lc| lc + ok_checks_wire.get_variable(),
        |lc| lc + ok_inputs_checks.get_variable(),
    );

    // fail = ok_inputs - ok_inputs_checks  (linear, no constraint)
    // pass = 1 - fail = 1 - ok_inputs + ok_inputs_checks

    // =========================================================================
    // STEP 6 -- Conditional output: z_out[i] = (1 - fail) * z_in[i]
    // =========================================================================
    // (1 - fail) = 1 - ok_inputs + ok_inputs_checks
    // expressed as a linear combination in the A slot.

    let outputs: Vec<AllocatedNum<F>> = [sig_s1, sig_s2, com_cdob, com_cnat, age_lo, age_hi, country]
        .iter()
        .enumerate()
        .map(|(i, &inp)| {
            let out = AllocatedNum::alloc(
                cs.namespace(|| format!("z_out_{i}")),
                || {
                    let ok_i  = ok_inputs.get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let ok_c  = ok_checks_wire.get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let v     = inp.get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    // fail = ok_inputs - ok_inputs*ok_checks
                    let ok_i_f  = if ok_i { F::ONE } else { F::ZERO };
                    let fail    = ok_i_f - ok_i_f * ok_c;
                    if i == 6 {
                        return inp.get_value().ok_or(SynthesisError::AssignmentMissing);
                    }
                    Ok((F::ONE - fail) * v)
                },
            )?;
            // Constraint: (1 - ok_inputs + ok_inputs_checks) * z_in[i] == z_out[i]
            if i!=6 {
                cs.enforce(
                    || format!("(1-fail) * z_in[{i}] == z_out[{i}]"),
                    |lc| lc + CS::one()
                            - ok_inputs.get_variable()
                            + ok_inputs_checks.get_variable(),
                    |lc| lc + inp.get_variable(),
                    |lc| lc + out.get_variable(),
                );
            } else {
                cs.enforce(
                    || "country == z_out_6",
                    |lc| lc + inp.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + out.get_variable(),
                );
            }
            
            Ok(out)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(outputs)
}

// ---------------------------------------------------------------------------
// Gadgets
// ---------------------------------------------------------------------------

/// Returns AllocatedBit = 1 iff x != 0.
fn is_nonzero<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    x: &AllocatedNum<F>,
) -> Result<AllocatedBit, SynthesisError> {
    let inv_wire = AllocatedNum::alloc(
        cs.namespace(|| "inv"),
        || {
            let v = x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(v.invert().unwrap_or(F::ZERO))
        },
    )?;
    let ok_nz = AllocatedBit::alloc(
        cs.namespace(|| "ok_nz"),
        x.get_value().map(|v| !bool::from(v.is_zero())),
    )?;
    cs.enforce(
        || "x * inv == ok_nz",
        |lc| lc + x.get_variable(),
        |lc| lc + inv_wire.get_variable(),
        |lc| lc + ok_nz.get_variable(),
    );
    cs.enforce(
        || "(1 - ok_nz) * x == 0",
        |lc| lc + CS::one() - ok_nz.get_variable(),
        |lc| lc + x.get_variable(),
        |lc| lc,
    );
    Ok(ok_nz)
}

/// Returns AllocatedBit = a AND b.
fn alloc_and<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedBit,
    b: &AllocatedBit,
) -> Result<AllocatedBit, SynthesisError> {
    let result = AllocatedBit::alloc(
        cs.namespace(|| "result"),
        a.get_value().and_then(|av| b.get_value().map(|bv| av && bv)),
    )?;
    cs.enforce(
        || "a * b == result",
        |lc| lc + a.get_variable(),
        |lc| lc + b.get_variable(),
        |lc| lc + result.get_variable(),
    );
    Ok(result)
}

fn field_to_u64<F: PrimeField>(f: F) -> u64 {
    let repr  = f.to_repr();
    let bytes = repr.as_ref();
    u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]))
}



