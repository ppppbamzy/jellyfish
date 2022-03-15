// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This file contains an example showing how to build a proof of knowledge
//! of the exponent over a native field.
//!
//! - secret input `x`;
//! - public generator `G`;
//! - public group element `X := xG`

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{
    twisted_edwards_extended::GroupAffine as TEAffine, AffineCurve, ModelParameters, PairingEngine,
    ProjectiveCurve, TEModelParameters,
};
// use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsParameters, Fr};
use ark_ff::PrimeField;
use ark_std::{rand::SeedableRng, UniformRand};
use jf_plonk::{
    circuit::{customized::ecc::Point, Arithmetization, Circuit, PlonkCircuit},
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};
use jf_utils::fr_to_fq;
use rand_chacha::ChaCha20Rng;

// The following example proves knowledge of exponent.
#[allow(non_snake_case)]
fn main() -> Result<(), PlonkError> {
    let x = Fr::from(13_u64);
    let y = Fr::from(17_u64);

    let mut circuit: PlonkCircuit<Fr> = PlonkCircuit::new_turbo_plonk();
    let x_var = circuit.create_variable(x)?;
    let y_var = circuit.create_variable(y)?;
    let z_var = circuit.add(x_var, y_var)?;
    let two_var = circuit.create_constant_variable(Fr::from(2_u64))?;
    let w_var = circuit.mul(z_var, two_var)?;
    circuit.set_variable_public(w_var)?;
    assert_eq!(Fr::from(60_u64), circuit.witness(w_var)?);

    // 固定的后处理
    circuit.finalize_for_arithmetization()?;

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let srs_size = circuit.srs_size()?;
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng)?;

    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit)?;

    let proof = PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(
        &mut rng, &circuit, &pk, None,
    )?;

    let public_inputs = circuit.public_input().unwrap();
    
    let extra_transcript_init_msg = None;
    assert!(PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(
        &vk,
        &public_inputs,
        &proof,
        extra_transcript_init_msg,
    )
    .is_ok());

    Ok(())
}
