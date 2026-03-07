// ps_rand.rs
//
// Nova StepCircuit implementing ps_rand rerandomisation.
//
//   z_in  = [sigma_1,   sigma_2,   com_dob,   com_nat,   age_lo, age_hi, country]
//   z_out = [t·sigma_1, t·sigma_2, t·com_dob, t·com_nat, age_lo, age_hi, country]
//
// Private witness: t (the rerandomisation scalar)
//
// Constraint per scaled slot:
//   t * z_in[i] == z_out[i]    (one R1CS multiplication gate each)
//
// The three pass-through slots (age_lo, age_hi, country) reuse the z_in
// variables directly — no additional constraints.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;


const IDX_SIGMA_1: usize = 0;
const IDX_SIGMA_2: usize = 1;
const IDX_COM_DOB: usize = 2;
const IDX_COM_NAT: usize = 3;
const IDX_AGE_LO:  usize = 4;
const IDX_AGE_HI:  usize = 5;
const IDX_COUNTRY: usize = 6;

#[derive(Clone, Debug)]
pub struct PsRand<F: PrimeField> {
    pub t: Option<F>,
    pub pc_next: Option<F>,
}

impl<F: PrimeField> PsRand<F> {
    pub fn new(t: F, pc_next: usize,) -> Self       { Self { t: Some(t), pc_next :Some(F::from(pc_next as u64)) ,} }
    pub fn blank() -> Self         { Self { t: None, pc_next: None, } }

    pub fn make_z0(
        sigma_1: F, sigma_2: F,
        com_dob: F, com_nat: F,
        age_lo:  F, age_hi:  F,
        country: F,
    ) -> Vec<F> {
        let mut z = vec![F::ZERO; 8];
        z[IDX_SIGMA_1] = sigma_1;
        z[IDX_SIGMA_2] = sigma_2;
        z[IDX_COM_DOB] = com_dob;
        z[IDX_COM_NAT] = com_nat;
        z[IDX_AGE_LO]  = age_lo;
        z[IDX_AGE_HI]  = age_hi;
        z[IDX_COUNTRY] = country;
        z
    }

}

impl<F: PrimeField> PsRand<F> {

    pub fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {

        
        
        // Allocate t as a private witness.
        let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
            self.t.ok_or(SynthesisError::AssignmentMissing)
        })?;


        // Scale the four credential components.
        // AllocatedNum::mul(cs, other) enforces  self * other == output  via
        // a single R1CS constraint and returns the output as a new AllocatedNum.
        let t_sigma_1 = t.mul(cs.namespace(|| "t_sigma_1"), &z[IDX_SIGMA_1])?;
        let t_sigma_2 = t.mul(cs.namespace(|| "t_sigma_2"), &z[IDX_SIGMA_2])?;
        let t_com_dob = t.mul(cs.namespace(|| "t_com_dob"), &z[IDX_COM_DOB])?;
        let t_com_nat = t.mul(cs.namespace(|| "t_com_nat"), &z[IDX_COM_NAT])?;

        // Assemble z_out.  Pass-through slots reuse z_in variables directly.
        Ok(vec![
            t_sigma_1,               // 0: t·sigma_1
            t_sigma_2,               // 1: t·sigma_2
            t_com_dob,               // 2: t·com_dob
            t_com_nat,               // 3: t·com_nat
            z[IDX_AGE_LO].clone(),   // 4: age_lo  (unchanged)
            z[IDX_AGE_HI].clone(),   // 5: age_hi  (unchanged)
            z[IDX_COUNTRY].clone(),  // 6: country (unchanged)
        ])
    }
}

