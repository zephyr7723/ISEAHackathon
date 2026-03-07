use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper::gadgets::num::AllocatedNum;
use ff::PrimeField;

use arecibo::{
    supernova::{
        NonUniformCircuit,
        PublicParams,
        RecursiveSNARK
    },
    traits::circuit_supernova::{TrivialSecondaryCircuit}
};

use arecibo::traits::circuit_supernova::StepCircuit;
use arecibo::provider::{Bn256Engine, GrumpkinEngine};
use arecibo::traits::Engine;
use crate::circuits::{ps_rand, ps_dob, ps_nat};

// ------------------------------------------------------------
// Curve aliases
// ------------------------------------------------------------

type E1 = Bn256Engine;
type E2 = GrumpkinEngine;

type F1 = <E1 as Engine>::Scalar;
type F2 = <E2 as Engine>::Scalar;

// ------------------------------------------------------------
// PC constants
// ------------------------------------------------------------

pub const PC_PS_RAND: usize = 0;
pub const PC_PS_DOB:  usize = 1;
pub const PC_PS_NAT:  usize = 2;

pub const NUM_CIRCUITS: usize = 3;
pub const ARITY:        usize = 2;

// ------------------------------------------------------------
// RamInstruction enum — implements circuit_supernova::StepCircuit
// ------------------------------------------------------------

#[derive(Clone)]
pub enum RamInstruction<F: PrimeField> {
    PsRand(ps_rand::PsRand<F>),
    PsDob(ps_dob::PsDobCircuit<F>),
    PsNat(ps_nat::PsNatCircuit<F>),
}

impl<F: PrimeField> StepCircuit<F> for RamInstruction<F> {

    fn arity(&self) -> usize {
        (7 as usize)
    }

    fn circuit_index(&self) -> usize {
        match self {
            RamInstruction::PsRand(_) => PC_PS_RAND,
            RamInstruction::PsDob(_)  => PC_PS_DOB,
            RamInstruction::PsNat(_)  => PC_PS_NAT,
        }
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<F>>,
        z_in: &[AllocatedNum<F>],
    ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let z_out = match self {
            RamInstruction::PsRand(c) => c.synthesize(cs, z_in),
            RamInstruction::PsDob(c)  => c.synthesize(cs, z_in),
            RamInstruction::PsNat(c)  => c.synthesize(cs, z_in),
        }?;
        let pc_next = {
            let next = AllocatedNum::alloc(cs.namespace(|| "pc_next"), 
            || match self {
                RamInstruction::PsRand(c) => Ok(c.pc_next.unwrap()),
                RamInstruction::PsDob(c)  => Ok(c.pc_next.unwrap()),
                RamInstruction::PsNat(c)  => Ok(c.pc_next.unwrap()),
            })?;
            Some(next)
        };
        Ok((pc_next, z_out))
    }
}

// ------------------------------------------------------------
// CredentialStep schedule
// ------------------------------------------------------------

#[derive(Clone)]
pub enum CredentialStep<F: PrimeField> {

    PsRand { t: F, pc_next: usize},

    PsDob {
        dob:        u64,
        com_odob:   F,
        t:          F,
        age_lo_inp: F,
        age_hi_inp: F,
        pc_next : usize,
    },

    PsNat {
        nationality: F,
        com_onat:    F,
        t:           F,
        cont:        F,
        pc_next : usize,
    },
}

// ------------------------------------------------------------
// CredentialMachine
// ------------------------------------------------------------

pub struct CredentialMachine<F: PrimeField> {
    schedule: Vec<CredentialStep<F>>,
    current:  usize,
}

impl<F: PrimeField> CredentialMachine<F> {

    pub fn new(schedule: Vec<CredentialStep<F>>) -> Self {
        Self { schedule, current: 0 }
    }

    pub fn total_steps(&self) -> usize {
        self.schedule.len()
    }

    pub fn current_pc(&self) -> usize {
        match &self.schedule[self.current] {
            CredentialStep::PsRand { .. } => PC_PS_RAND,
            CredentialStep::PsDob  { .. } => PC_PS_DOB,
            CredentialStep::PsNat  { .. } => PC_PS_NAT,
        }
    }

    pub fn current_circuit(&self) -> RamInstruction<F> {
        match &self.schedule[self.current] {
            CredentialStep::PsRand { t, pc_next } =>
                RamInstruction::PsRand(ps_rand::PsRand::new(*t, *pc_next,)),

            CredentialStep::PsDob { dob, com_odob, t, age_lo_inp, age_hi_inp, pc_next } =>
                RamInstruction::PsDob(ps_dob::PsDobCircuit::new(
                    *dob, *com_odob, *t, *age_lo_inp, *age_hi_inp, *pc_next,
                )),

            CredentialStep::PsNat { nationality, com_onat, t, cont, pc_next } =>
                RamInstruction::PsNat(ps_nat::PsNatCircuit::new(
                    *nationality, *com_onat, *t, *cont, *pc_next,
                )),
        }
    }

    pub fn advance(&mut self) {
        self.current += 1;
    }
}

// ------------------------------------------------------------
// NonUniformCircuit implementation
// ------------------------------------------------------------

impl NonUniformCircuit<
    E1,
    E2,
    RamInstruction<F1>,
    TrivialSecondaryCircuit<F2>,
> for CredentialMachine<F1>
{
    fn num_circuits(&self) -> usize { NUM_CIRCUITS }

    fn primary_circuit(&self, pc: usize) -> RamInstruction<F1> {
        match pc {
            PC_PS_RAND => RamInstruction::PsRand(ps_rand::PsRand::blank()),
            PC_PS_DOB  => RamInstruction::PsDob(ps_dob::PsDobCircuit::blank()),
            PC_PS_NAT  => RamInstruction::PsNat(ps_nat::PsNatCircuit::blank()),
            _          => panic!("unknown pc {pc}"),
        }
    }

    fn secondary_circuit(&self) -> TrivialSecondaryCircuit<F2> {
        TrivialSecondaryCircuit::default()
    }
}
