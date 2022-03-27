use ark_bls12_381::Bls12_381;
use ark_ec::{
    twisted_edwards_extended::GroupAffine as TEAffine, AffineCurve, ModelParameters, PairingEngine,
    ProjectiveCurve, TEModelParameters,
};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsParameters, Fr};
use ark_ff::{PrimeField, FftField};
use ark_std::{rand::SeedableRng, UniformRand};
use jf_plonk::{
    circuit::{customized::{ecc::{Point, PointVariable}, rescue::RescueGadget}, Arithmetization, Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};
use jf_utils::fr_to_fq;
use rand_chacha::ChaCha20Rng;

// The following example proves knowledge of exponent.
#[allow(non_snake_case)]
fn main() -> Result<(), PlonkError> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut circuit = PlonkCircuit::<<EdwardsParameters as ModelParameters>::BaseField>::new_turbo_plonk();

    println!("new circuit: ");
    for v in 0..circuit.num_vars() { println!("{}: {}", v, circuit.witness(v).unwrap()); }

    let x = <EdwardsParameters as ModelParameters>::BaseField::from(42_u64);
    let x_var = circuit.create_variable(x)?;
    proof_of_quintic_equ_root(&mut circuit, x_var)?;

    println!("after adding the quintic equ root: ");
    for v in 0..circuit.num_vars() { println!("{}: {}", v, circuit.witness(v).unwrap()); }

    let x = Fr::rand(&mut rng);
    let G = EdwardsAffine::prime_subgroup_generator();
    let X = G.mul(x).into_affine();
    let X_var = proof_of_exponent_circuit::<EdwardsParameters, Bls12_381>(&mut circuit, x, X)?;

    println!("after add ec part: ");
    for v in 0..circuit.num_vars() { println!("{}: {}", v, circuit.witness(v).unwrap()); }

    let hash_out_var = proof_of_point_hashing(&mut circuit, X_var)?;

    println!("after hashing part: ");
    for v in 0..circuit.num_vars() { println!("{}: {}", v, circuit.witness(v).unwrap()); }
    
    /////////////////////
    // 标出公开变量、算术化
    /////////////////////

    circuit.set_variable_public(hash_out_var)?;
    circuit.finalize_for_arithmetization()?;

    /////////////////////
    // 协议部分
    /////////////////////

    // Knowing the circuit size, we are able to simulate the universal
    // setup and obtain the structured reference string (SRS).
    //
    // The required SRS size can be obtained from the circuit.
    let srs_size = circuit.srs_size()?;
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng)?;

    // Then, we generate the proving key and verification key from the SRS and
    // circuit.
    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit)?;

    // Next, we generate the proof.
    // The proof generation will need an internal transcript for Fiat-Shamir
    // transformation. For this example we use a `StandardTranscript`.
    let proof = PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(
        &mut rng, &circuit, &pk, None,
    )?;

    // Last step, verify the proof against the public inputs.
    let public_inputs = circuit.public_input().unwrap();
    // extra messages to bound to proof by appending in its transcripts, not used
    // here.
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

#[allow(non_snake_case)]
fn proof_of_exponent_circuit<EmbedCurve, PairingCurve>(
    circuit: &mut PlonkCircuit<EmbedCurve::BaseField>,
    x: EmbedCurve::ScalarField,
    X: TEAffine<EmbedCurve>,
) -> Result<PointVariable, PlonkError>
where
    EmbedCurve: TEModelParameters + Clone,
    <EmbedCurve as ModelParameters>::BaseField: PrimeField,
    PairingCurve: PairingEngine,
{
    // Let's check that the inputs are indeed correct before we build a circuit.
    let G = TEAffine::<EmbedCurve>::prime_subgroup_generator();
    assert_eq!(X, G.mul(x), "the inputs are incorrect: X != xG");

    // Step 2:
    // now we create variables for each input to the circuit.

    // First variable is x which is an field element over P::ScalarField.
    // We will need to lift it to P::BaseField.
    let x_fq = fr_to_fq::<_, EmbedCurve>(&x);
    let x_var = circuit.create_variable(x_fq)?;

    // The next variable is a public constant: generator `G`.
    // We need to convert the point to Jellyfish's own `Point` struct.
    let G_jf: Point<EmbedCurve::BaseField> = G.into();
    let G_var = circuit.create_constant_point_variable(G_jf)?;

    // The last variable is a public variable `X`.
    let X_jf: Point<EmbedCurve::BaseField> = X.into();
    let X_var = circuit.create_public_point_variable(X_jf)?;

    // Step 3:
    // Connect the wires.
    let X_var_computed = circuit.variable_base_scalar_mul::<EmbedCurve>(x_var, &G_var)?;
    circuit.point_equal_gate(&X_var_computed, &X_var)?;

    // Sanity check: the circuit must be satisfied.
    assert!(circuit
        .check_circuit_satisfiability(&[X_jf.get_x(), X_jf.get_y()])
        .is_ok());

    Ok(X_var)
}

fn proof_of_quintic_equ_root<F>(
    circuit: &mut PlonkCircuit<F>,
    x_var: Variable,
) -> Result<(), PlonkError>
where
    F: PrimeField
{
    let x2_var = circuit.mul(x_var, x_var)?;
    let x3_var = circuit.mul(x2_var, x_var)?;
    let x4_var = circuit.mul(x3_var, x_var)?;
    let x5_var = circuit.mul(x4_var, x_var)?;

    let x2_times_2_var = circuit.mul_constant(x2_var, &F::from(2_u64))?;
    let x3_times_3_var = circuit.mul_constant(x3_var, &F::from(3_u64))?;
    let x4_times_4_var = circuit.mul_constant(x4_var, &F::from(4_u64))?;
    let x5_times_5_var = circuit.mul_constant(x5_var, &F::from(5_u64))?;

    let acc_var = x_var;
    let acc_var = circuit.add(acc_var, x2_times_2_var)?;
    let acc_var = circuit.add(acc_var, x3_times_3_var)?;
    let acc_var = circuit.add(acc_var, x4_times_4_var)?;
    let acc_var = circuit.add(acc_var, x5_times_5_var)?;

    Ok(())
}

fn proof_of_point_hashing<F>(
    circuit: &mut PlonkCircuit<F>,
    X_var: PointVariable,
) -> Result<Variable, PlonkError>
where
    F: PrimeField + jf_rescue::RescueParameter
{
    let x_var = X_var.get_x();
    let y_var = X_var.get_y();
    let z = circuit.zero();

    let hash_out_var = circuit.rescue_sponge_no_padding(&[x_var, y_var, z], 1)?;

    Ok(hash_out_var[0])
}
