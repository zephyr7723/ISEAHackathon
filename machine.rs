use arecibo::{
    supernova::{
        NonUniformCircuit,
        PublicParams,
        RecursiveSNARK
    },
};

use ff::Field;

use arecibo::provider::{Bn256Engine, GrumpkinEngine};
use arecibo::traits::Engine;
use arecibo::traits::circuit_supernova::TrivialSecondaryCircuit;
use arecibo::traits::circuit_supernova::StepCircuit;

use crate::utils::credential_machine::{
    CredentialMachine, RamInstruction, NUM_CIRCUITS,
};

use bellpepper_core::SynthesisError;

// ------------------------------------------------------------
// Curve aliases
// ------------------------------------------------------------

type E1 = Bn256Engine;
type E2 = GrumpkinEngine;

type F1 = <E1 as Engine>::Scalar;
type F2 = <E2 as Engine>::Scalar;

// ------------------------------------------------------------
// Driver
// ------------------------------------------------------------

pub fn run_credential_machine(
    mut machine: CredentialMachine<F1>,
    z0:   &[Vec<F1>;NUM_CIRCUITS],
) -> anyhow::Result<Vec<F1>> {

    let total = machine.total_steps();

    println!("Setting up Arecibo parameters...");
    let pp = PublicParams::<
        E1,
        E2,
        RamInstruction<F1>,
        TrivialSecondaryCircuit<F2>,
    >::setup(&machine, &|_| 0, &|_| 0);

    println!("Public params ready.");

    // Step 0
    let z0_secondary = vec![<F2 as Field>::ZERO];
    let pc0   = machine.current_pc();
    let mut circ0 = machine.current_circuit();
    let mut circ1 = machine.secondary_circuit();

    // RecursiveSNARK::new proves step 0 internally, advance before the loop.
    

    let mut recursive_snark = RecursiveSNARK::new(
        &pp,
        &machine,
        &circ0,
        &circ1,
        &z0[pc0],
        &z0_secondary,
    ).unwrap();

    for step in 0..total {
        let mut circuit1 = machine.current_circuit();
        let mut circuit2 = machine.secondary_circuit();
        
        println!("step {step}: circuit_index={}", circuit1.circuit_index());

        let mut res = recursive_snark.prove_step(&pp, &circuit1, &circuit2);

        machine.advance();

        println!("step {step} proven");
    }

    let res1 = recursive_snark.verify(&pp, &z0[pc0], &z0_secondary);

    println!("✓ credential proof verified");

    let (z_out, _) = recursive_snark
    .verify(&pp, &z0[pc0], &z0_secondary)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Ok(z_out)
}
