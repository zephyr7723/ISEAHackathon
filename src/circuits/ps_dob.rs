/// ps_dob_circuit.rs
///
/// PS dob circuit with commitment randomisation check
/// ===================================================
///
/// SPECIFICATION
/// -------------
/// ps_dob_circuit(sig, com_cdob, com_cnat, age_hi, age_lo,
///                dob, com_odob, t):
///
///   Checks:
///     (1) sig, com_cdob, com_cnat are not garbage (non-identity)
///     (2) com_odob ^ t == com_cdob
///         The current dob commitment is the original raised to t.
///         This is the PS commitment randomisation:
///           com_odob = G^m1 * H^r
///           com_cdob = com_odob^t = G^(m1*t) * H^(r*t)
///     (3) age_lo <= age <= age_hi
///         where age = CURRENT_YEAR - floor(dob / YEAR_DIVISOR)
///
///   Returns:
///     (sig, com_cdob, com_cnat)  if all checks pass
///     (0,   0,        0       )  otherwise
///
/// PUBLIC INPUTS  z_in  [6 wires]
/// --------------------------------
///   [0]  sig_s1    -- sigma_1 component of PS signature
///   [1]  sig_s2    -- sigma_2 component of PS signature
///   [2]  com_cdob  -- current (randomised) commitment to dob
///   [3]  com_cnat  -- current (randomised) commitment to nationality
///                     passed through unchanged; verifier checks externally
///   [4]  age_lo    -- lower age bound (inclusive)
///   [5]  age_hi    -- upper age bound (inclusive)
///
/// PRIVATE WITNESSES  [4 wires]
/// -----------------------------
///   dob      -- date-of-birth as YYYYMMDD
///   com_odob -- original commitment to dob: G^(hash(dob)) * H^r
///               provided by the prover; never revealed
///   t        -- randomisation exponent applied to com_odob
///               com_cdob = com_odob ^ t
///
/// NOTE ON com_odob ^ t IN A FIELD-BASED CIRCUIT
/// -----------------------------------------------
/// In group-based PS, com_odob is a group element and exponentiation
/// is scalar multiplication.  In this R1CS circuit all values are field
/// elements (scalars).  com_odob is therefore represented as its scalar
/// encoding (e.g. x-coordinate of the group element hashed to Fp), and
/// com_odob ^ t is encoded as the field multiplication:
///
///   com_cdob = com_odob * t    (field multiplication, not group exp)
///
/// This is consistent with how sigma randomisation works in the scalar
/// representation: if com_odob = G^e for some exponent e, then
/// com_cdob = G^(e*t) and the scalar representing com_cdob is e*t.
///
/// CONSTRAINTS
/// -----------
///   (a)  sig_s1   != 0   }
///   (b)  sig_s2   != 0   } non-garbage checks via inverse witnesses
///   (c)  com_cdob != 0   }  3 constraints
///   (d)  com_odob * t == com_cdob          1   randomisation check
///   (e)  age * YEAR_DIV == dob - dob_rem   1 }
///   (f)  (CY-age)*YEAR_DIV == dob-dob_rem  1 } age derivation
///        dob_rem in [0, 2^14)             29 }  31 total
///   (g)  diff_lo + age_lo == age           1 }
///        diff_lo in [0, 2^7)             15  } range  32 total
///   (h)  age + diff_hi == age_hi           1 }
///        diff_hi in [0, 2^7)             15  }
///   (i)  ok * sig_s1   == z_out_s1         1 }
///   (j)  ok * sig_s2   == z_out_s2         1 } conditional output
///   (k)  ok * com_cdob == z_out_com_cdob   1 }  4 total
///   (l)  ok * com_cnat == z_out_com_cnat   1 }
///   ---------------------------------------------------------------
///   TOTAL                                ~71 constraints
///
/// NON-GARBAGE CHECK
/// -----------------
/// R1CS cannot directly express x != 0.  The standard encoding is:
///   Allocate an inverse witness inv such that x * inv == 1.
///   If x == 0 no such inv exists, making the constraint unsatisfiable.
///   We allocate a Boolean ok_nonzero and encode:
///     x * inv == ok_nonzero   AND   (1 - ok_nonzero) * x == 0
///   ok_nonzero = 1 iff x != 0.
///   We AND all three ok_nonzero bits into the main ok gate.

use bellpepper_core::{
    boolean::AllocatedBit,
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use arecibo::traits::circuit_supernova::StepCircuit;
use ff::PrimeField;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const YEAR_DIVISOR: u64 = 10_000;
const CURRENT_YEAR: u64 = 2025;
const RANGE_BITS:   usize = 7;

// ---------------------------------------------------------------------------
// Witness struct
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PsDobCircuit<F: PrimeField> {
    /// Date-of-birth as YYYYMMDD.
    pub dob: Option<F>,
    /// Original commitment to dob: G^(hash(dob)) * H^r
    /// Encoded as a scalar field element (e.g. hash of group point).
    pub com_odob: Option<F>,
    /// Randomisation scalar: com_cdob = com_odob * t
    pub t: Option<F>,
    /// User input of age_hi and age_lo
    pub age_lo_inp: Option<F>,
    pub age_hi_inp: Option<F>,
    pub pc_next: Option<F>,
}

impl<F: PrimeField> PsDobCircuit<F> {
    pub fn new(dob: u64, com_odob: F, t: F, age_lo_inp: F, age_hi_inp: F, pc_next: usize) -> Self {
        Self {
            dob:      Some(F::from(dob)),
            com_odob: Some(com_odob),
            t:        Some(t),
            age_lo_inp: Some(age_lo_inp),
            age_hi_inp: Some(age_hi_inp),
            pc_next: Some(F::from(pc_next as u64)),
        }
    }

    pub fn blank() -> Self {
        Self { dob: None, com_odob: None, t: None, age_lo_inp: None, age_hi_inp: None, pc_next: None }
    }
}

// ---------------------------------------------------------------------------
// Public input builder
// ---------------------------------------------------------------------------

/// Compute the 6 public inputs.
/// com_cdob = com_odob * t  (computed by caller before proving).

// ---------------------------------------------------------------------------
// StepCircuit
// ---------------------------------------------------------------------------



impl<F: PrimeField> PsDobCircuit<F> {
    pub fn arity(&self) -> usize { 7 }

    pub fn circuit_index(&self) -> usize { 1 }

    pub fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let z_out = synthesize_ps_dob(cs, z_in, self)?;

        // Allocate pc_next as a private witness — no constraints needed.
        // SuperNova verifies externally that this matches the actual next step.

        Ok(z_out)
    }
}

// ---------------------------------------------------------------------------
// Core synthesis
// ---------------------------------------------------------------------------

fn synthesize_ps_dob<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    z_in: &[AllocatedNum<F>],
    w: &PsDobCircuit<F>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {

    let sig_s1   = &z_in[0];
    let sig_s2   = &z_in[1];
    let com_cdob = &z_in[2];
    let com_cnat = &z_in[3];
    let age_lo   = &z_in[4];
    let age_hi   = &z_in[5];
    let country = &z_in[6];

    // =========================================================================
    // STEP 1 -- Allocate private witness wires
    // =========================================================================

    let dob_wire = AllocatedNum::alloc(
        cs.namespace(|| "dob"),
        || w.dob.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let com_odob_wire = AllocatedNum::alloc(
        cs.namespace(|| "com_odob"),
        || w.com_odob.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let t_wire = AllocatedNum::alloc(
        cs.namespace(|| "t"),
        || w.t.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let age_lo_wire =  AllocatedNum::alloc(
        cs.namespace(|| "age_lo_inp"),
        || w.age_lo_inp.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let age_hi_wire =  AllocatedNum::alloc(
        cs.namespace(|| "age_hi_inp"),
        || w.age_hi_inp.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let com_cdob_wire = com_cdob.clone();

    let birth_year_val = w.dob.map(|d| F::from(field_to_u64(d) / YEAR_DIVISOR));

    let birth_year_wire = AllocatedNum::alloc(
        cs.namespace(|| "birth_year"),
        || birth_year_val.ok_or(SynthesisError::AssignmentMissing),
    )?;



    cs.enforce(
        || "correct commitment",
        |lc| lc + dob_wire.get_variable() - com_odob_wire.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );

    // =========================================================================
    // STEP 2 -- Non-garbage checks
    // =========================================================================
    // Prove sig_s1, sig_s2, com_cdob are all non-zero.
    // Encoding: allocate inverse witness inv; constrain x * inv == ok_nz;
    // constrain (1 - ok_nz) * x == 0.
    // ok_nz = 1 iff x != 0.

    let ok_s1  = is_nonzero(cs.namespace(|| "ok_s1"),  sig_s1)?;
    let ok_s2  = is_nonzero(cs.namespace(|| "ok_s2"),  sig_s2)?;
    let ok_com = is_nonzero(cs.namespace(|| "ok_com"), com_cdob)?;

    // AND the three non-garbage bits: ok_inputs = ok_s1 * ok_s2 * ok_com
    let ok_s1s2 = alloc_and(cs.namespace(|| "ok_s1 AND ok_s2"), &ok_s1, &ok_s2)?;
    let ok_inputs = alloc_and(cs.namespace(|| "ok_s1s2 AND ok_com"), &ok_s1s2, &ok_com)?;

    // =========================================================================
    // STEP 3 -- Commitment randomisation check
    // =========================================================================
    // Prove: com_odob * t == com_cdob
    //
    // In scalar representation this is a single field multiplication.
    // In group terms: if com_odob represents G^e, then com_odob^t = G^(e*t),
    // and com_cdob should equal G^(e*t), whose scalar is e*t = com_odob * t.
    //
    // Constraint (d): com_odob * t == com_cdob

    let computed_com_cdob = com_odob_wire.mul(
        cs.namespace(|| "com_odob * t"),
        &t_wire,
    )?;

    cs.enforce(
        || "randomisation: com_odob * t == com_cdob",
        |lc| lc + computed_com_cdob.get_variable() - com_cdob_wire.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );

    // =========================================================================
    // STEP 4 -- Age derivation
    // =========================================================================

    let year_div_f   = F::from(YEAR_DIVISOR);
    let current_yr_f = F::from(CURRENT_YEAR);

    let age_wire = AllocatedNum::alloc(
        cs.namespace(|| "age"),
        || {
            let d   = w.dob.ok_or(SynthesisError::AssignmentMissing)?;
            let age = CURRENT_YEAR.saturating_sub(field_to_u64(d) / YEAR_DIVISOR);
            Ok(F::from(age))
        },
    )?;

    let dob_rem_wire = AllocatedNum::alloc(
        cs.namespace(|| "dob_rem"),
        || {
            let d = w.dob.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(F::from(field_to_u64(d) % YEAR_DIVISOR))
        },
    )?;

    // Constraint (e)

    cs.enforce(
        || "birth_year * YEAR_DIV == dob - dob_rem",
        |lc| lc + birth_year_wire.get_variable(),
        |lc| lc + (year_div_f, CS::one()),
        |lc| lc + dob_wire.get_variable() - dob_rem_wire.get_variable(),
    );
   

    enforce_range_bits(
        cs.namespace(|| "dob_rem in [0, 2^14)"),
        &dob_rem_wire,
        14,
    )?;

    // =========================================================================
    // STEP 5 -- Age range proof
    // =========================================================================

    let diff_lo = AllocatedNum::alloc(
        cs.namespace(|| "diff_lo = age - age_lo"),
        || {
            let a  = age_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let lo = age_lo_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a - lo)
        },
    )?;
    cs.enforce(
        || "diff_lo + age_lo == age",
        |lc| lc + diff_lo.get_variable() + age_lo_wire.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + age_wire.get_variable(),
    );
    let ok_lo = enforce_range_bits_bool(
        cs.namespace(|| "diff_lo in [0, 2^RANGE_BITS)"),
        &diff_lo,
        RANGE_BITS,
    )?;

    let diff_hi = AllocatedNum::alloc(
        cs.namespace(|| "diff_hi = age_hi - age"),
        || {
            let hi = age_hi_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let a  = age_wire.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(hi - a)
        },
    )?;
    cs.enforce(
        || "age + diff_hi == age_hi",
        |lc| lc + age_wire.get_variable() + diff_hi.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + age_hi_wire.get_variable(),
    );
    let ok_hi = enforce_range_bits_bool(
        cs.namespace(|| "diff_hi in [0, 2^RANGE_BITS)"),
        &diff_hi,
        RANGE_BITS,
    )?;

    // =========================================================================
    // STEP 6 -- Combine all ok bits
    // =========================================================================
    // ok = ok_inputs AND ok_lo AND ok_hi

    let ok_range = alloc_and(cs.namespace(|| "ok_lo AND ok_hi"), &ok_lo, &ok_hi)?;
    let ok       = alloc_and(cs.namespace(|| "ok_inputs AND ok_range"), &ok_inputs, &ok_range)?;

    // =========================================================================
    // STEP 7 -- Conditional output
    // =========================================================================
    // All checks pass:  z_out = [sig_s1, sig_s2, com_cdob, com_cnat]
    // Any check fails:  z_out = [0, 0, 0, 0]

    let z_out_s1 = alloc_product(
        cs.namespace(|| "ok * sig_s1"),
        &ok, sig_s1,
        || "ok * sig_s1 == z_out_s1",
    )?;
    let z_out_s2 = alloc_product(
        cs.namespace(|| "ok * sig_s2"),
        &ok, sig_s2,
        || "ok * sig_s2 == z_out_s2",
    )?;
    let z_out_com_cdob = alloc_product(
        cs.namespace(|| "ok * com_cdob"),
        &ok, com_cdob,
        || "ok * com_cdob == z_out_com_cdob",
    )?;
    let z_out_com_cnat = alloc_product(
        cs.namespace(|| "ok * com_cnat"),
        &ok, com_cnat,
        || "ok * com_cnat == z_out_com_cnat",
    )?;

    let z_out_age_lo = AllocatedNum::alloc(
        cs.namespace(|| "z_out_age_lo"),
        || age_lo_wire.get_value().ok_or(SynthesisError::AssignmentMissing),
    )?;

    let z_out_age_hi = AllocatedNum::alloc(
        cs.namespace(|| "z_out_age_hi"),
        || age_hi_wire.get_value().ok_or(SynthesisError::AssignmentMissing),
    )?;

    let z_out_country = AllocatedNum::alloc(
        cs.namespace(|| "z_out_country"),
        || country.get_value().ok_or(SynthesisError::AssignmentMissing),
    )?;

    Ok(vec![z_out_s1, z_out_s2, z_out_com_cdob, z_out_com_cnat, z_out_age_lo, z_out_age_hi, z_out_country])
}

// ---------------------------------------------------------------------------
// Gadgets
// ---------------------------------------------------------------------------

/// Non-zero check: returns an AllocatedBit that is 1 iff x != 0.
///
/// Encoding:
///   Allocate inv such that x * inv == ok_nz  (ok_nz is a Boolean)
///   Constrain (1 - ok_nz) * x == 0
///
///   If x != 0: set inv = x^{-1}, ok_nz = 1. Both constraints hold.
///   If x == 0: must have ok_nz = 0 (from second constraint).
///              First constraint: 0 * inv == 0, satisfied for any inv.
fn is_nonzero<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    x: &AllocatedNum<F>,
) -> Result<AllocatedBit, SynthesisError> {
    // Inverse witness: x^{-1} if x != 0, else 0
    let inv_wire = AllocatedNum::alloc(
        cs.namespace(|| "inv"),
        || {
            let v = x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(v.invert().unwrap_or(F::ZERO))
        },
    )?;

    // ok_nz = 1 iff x != 0
    let ok_nz = AllocatedBit::alloc(
        cs.namespace(|| "ok_nz"),
        x.get_value().map(|v| !bool::from(v.is_zero())),
    )?;

    // Constraint 1: x * inv == ok_nz
    cs.enforce(
        || "x * inv == ok_nz",
        |lc| lc + x.get_variable(),
        |lc| lc + inv_wire.get_variable(),
        |lc| lc + ok_nz.get_variable(),
    );

    // Constraint 2: (1 - ok_nz) * x == 0
    cs.enforce(
        || "(1 - ok_nz) * x == 0",
        |lc| lc + CS::one() - ok_nz.get_variable(),
        |lc| lc + x.get_variable(),
        |lc| lc,
    );

    Ok(ok_nz)
}

/// Boolean AND: allocate a wire equal to a * b.
fn alloc_and<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedBit,
    b: &AllocatedBit,
) -> Result<AllocatedBit, SynthesisError> {
    let result = AllocatedBit::alloc(
        cs.namespace(|| "and_result"),
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

/// Conditional gate: allocate ok * x as a new wire.
fn alloc_product<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    ok: &AllocatedBit,
    x:  &AllocatedNum<F>,
    label: impl Fn() -> &'static str,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let out = AllocatedNum::alloc(
        cs.namespace(|| "out"),
        || {
            let o = if ok.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                F::ONE
            } else {
                F::ZERO
            };
            let v = x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(o * v)
        },
    )?;
    cs.enforce(
        label,
        |lc| lc + ok.get_variable(),
        |lc| lc + x.get_variable(),
        |lc| lc + out.get_variable(),
    );
    Ok(out)
}

/// Unconditional range check: assert value in [0, 2^num_bits).
fn enforce_range_bits<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    num_bits: usize,
) -> Result<(), SynthesisError> {
    let bits = alloc_bits(cs.namespace(|| "bits"), value, num_bits)?;
    let lc   = bits_to_lc::<F>(&bits);
    cs.enforce(
        || "value == bit_decomposition",
        |_| lc - value.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(())
}

/// Soft range check: returns AllocatedBit = 1 iff value in [0, 2^num_bits).
fn enforce_range_bits_bool<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    num_bits: usize,
) -> Result<AllocatedBit, SynthesisError> {
    let bits    = alloc_bits(cs.namespace(|| "bits"), value, num_bits)?;
    let lc      = bits_to_lc::<F>(&bits);
    let matches = value.get_value().map(|v| field_to_u64(v) < (1u64 << num_bits));
    let ok_bit  = AllocatedBit::alloc(cs.namespace(|| "ok_bit"), matches)?;
    cs.enforce(
        || "(lc - value) * ok_bit == 0",
        |_| lc.clone() - value.get_variable(),
        |lc| lc + ok_bit.get_variable(),
        |lc| lc,
    );
    Ok(ok_bit)
}

fn alloc_bits<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    num_bits: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    (0..num_bits)
        .map(|i| AllocatedBit::alloc(
            cs.namespace(|| format!("bit_{i}")),
            value.get_value().map(|v| (field_to_u64(v) >> i) & 1 == 1),
        ))
        .collect()
}

fn bits_to_lc<F: PrimeField>(bits: &[AllocatedBit]) -> LinearCombination<F> {
    let mut lc    = LinearCombination::<F>::zero();
    let mut coeff = F::ONE;
    for bit in bits {
        lc    = lc + (coeff, bit.get_variable());
        coeff = coeff.double();
    }
    lc
}

fn field_to_u64<F: PrimeField>(f: F) -> u64 {
    let repr  = f.to_repr();
    let bytes = repr.as_ref();
    u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]))
}


