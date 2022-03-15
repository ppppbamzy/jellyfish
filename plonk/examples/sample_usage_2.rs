use ark_bls12_381::{Bls12_381, Fr};
use ark_std::{rand::SeedableRng};
use jf_plonk::{
    circuit::{Arithmetization, Circuit, PlonkCircuit},
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};
use rand_chacha::ChaCha20Rng;

#[allow(non_snake_case)]
fn main() -> Result<(), PlonkError> {
    ///////////////////////////////
    // 电路部分
    ///////////////////////////////

    // 私有值
    let x = Fr::from(13_u64);
    let y = Fr::from(17_u64);

    // 新建一个电路
    let mut circuit: PlonkCircuit<Fr> = PlonkCircuit::new_turbo_plonk();

    // 加入私有变量并绑定值
    // verifier 在此处使用 dummy value
    let x_var = circuit.create_variable(x)?;
    let y_var = circuit.create_variable(y)?;

    // 断言 x 和 y 不超过 2^5
    circuit.range_gate(x_var, 5)?;
    circuit.range_gate(y_var, 5)?;

    // 加入中间变量 z = x + y，其值自动算出并保存在变量中
    let z_var = circuit.add(x_var, y_var)?;
    // 可以检查一下 z 的值
    assert_eq!(Fr::from(30_u64), circuit.witness(z_var)?);

    // 加入常量 2
    let two_var = circuit.create_constant_variable(Fr::from(2_u64))?;

    // 加入结果变量 w = 2 * z，其值自动算出并保存在变量中
    let w_var = circuit.mul(z_var, two_var)?;
    // 可以检查一下 w 的值
    assert_eq!(Fr::from(60_u64), circuit.witness(w_var)?);

    // 若 z 的值不超过 2^5，b 包含的值为 1；否则 b 包含的值为 0
    let b_var = circuit.is_in_range(z_var, 5)?;

    // 按 b 包含的值选择 w 或 z，输出最后结果 o 并公开
    let o_var = circuit.conditional_select(b_var, w_var, z_var)?;
    circuit.set_variable_public(o_var)?;

    // 固定的后处理
    circuit.finalize_for_arithmetization()?;

    ///////////////////////////////
    // 协议部分
    ///////////////////////////////

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let srs_size = circuit.srs_size()?;
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng)?;

    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit)?;

    // prover 生成 proof
    // (verifier 跳过这步)
    let proof = PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(
        &mut rng, &circuit, &pk, None,
    )?;

    // verifier 验证 proof
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
