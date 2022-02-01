(function() {var implementors = {};
implementors["jf_plonk"] = [{"text":"impl&lt;E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.UniversalSrs.html\" title=\"struct jf_plonk::proof_system::structs::UniversalSrs\">UniversalSrs</a>&lt;E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::UniversalSrs"]},{"text":"impl&lt;E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.Proof.html\" title=\"struct jf_plonk::proof_system::structs::Proof\">Proof</a>&lt;E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::Proof"]},{"text":"impl&lt;E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.PlookupProof.html\" title=\"struct jf_plonk::proof_system::structs::PlookupProof\">PlookupProof</a>&lt;E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::PlookupProof"]},{"text":"impl&lt;E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.BatchProof.html\" title=\"struct jf_plonk::proof_system::structs::BatchProof\">BatchProof</a>&lt;E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::BatchProof"]},{"text":"impl&lt;F:&nbsp;Field&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.ProofEvaluations.html\" title=\"struct jf_plonk::proof_system::structs::ProofEvaluations\">ProofEvaluations</a>&lt;F&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::ProofEvaluations"]},{"text":"impl&lt;F:&nbsp;Field&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.PlookupEvaluations.html\" title=\"struct jf_plonk::proof_system::structs::PlookupEvaluations\">PlookupEvaluations</a>&lt;F&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::PlookupEvaluations"]},{"text":"impl&lt;'a, E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.ProvingKey.html\" title=\"struct jf_plonk::proof_system::structs::ProvingKey\">ProvingKey</a>&lt;'a, E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::ProvingKey"]},{"text":"impl&lt;E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.PlookupProvingKey.html\" title=\"struct jf_plonk::proof_system::structs::PlookupProvingKey\">PlookupProvingKey</a>&lt;E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::PlookupProvingKey"]},{"text":"impl&lt;E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.VerifyingKey.html\" title=\"struct jf_plonk::proof_system::structs::VerifyingKey\">VerifyingKey</a>&lt;E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::VerifyingKey"]},{"text":"impl&lt;E:&nbsp;PairingEngine&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.PlookupVerifyingKey.html\" title=\"struct jf_plonk::proof_system::structs::PlookupVerifyingKey\">PlookupVerifyingKey</a>&lt;E&gt;","synthetic":false,"types":["jf_plonk::proof_system::structs::PlookupVerifyingKey"]}];
implementors["jf_primitives"] = [{"text":"impl CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/aead/struct.EncKey.html\" title=\"struct jf_primitives::aead::EncKey\">EncKey</a>","synthetic":false,"types":["jf_primitives::aead::EncKey"]},{"text":"impl CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/aead/struct.KeyPair.html\" title=\"struct jf_primitives::aead::KeyPair\">KeyPair</a>","synthetic":false,"types":["jf_primitives::aead::KeyPair"]},{"text":"impl CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/aead/struct.Ciphertext.html\" title=\"struct jf_primitives::aead::Ciphertext\">Ciphertext</a>","synthetic":false,"types":["jf_primitives::aead::Ciphertext"]},{"text":"impl&lt;P&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/elgamal/struct.EncKey.html\" title=\"struct jf_primitives::elgamal::EncKey\">EncKey</a>&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Parameters + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.58.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["jf_primitives::elgamal::EncKey"]},{"text":"impl&lt;P&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/elgamal/struct.KeyPair.html\" title=\"struct jf_primitives::elgamal::KeyPair\">KeyPair</a>&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Parameters + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.58.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["jf_primitives::elgamal::KeyPair"]},{"text":"impl&lt;P&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/elgamal/struct.Ciphertext.html\" title=\"struct jf_primitives::elgamal::Ciphertext\">Ciphertext</a>&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Parameters + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.58.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["jf_primitives::elgamal::Ciphertext"]},{"text":"impl CanonicalSerialize for <a class=\"enum\" href=\"jf_primitives/merkle_tree/enum.NodePos.html\" title=\"enum jf_primitives::merkle_tree::NodePos\">NodePos</a> <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.58.1/std/primitive.u8.html\">u8</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.58.1/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"jf_primitives/merkle_tree/enum.NodePos.html\" title=\"enum jf_primitives::merkle_tree::NodePos\">NodePos</a>&gt;,&nbsp;</span>","synthetic":false,"types":["jf_primitives::merkle_tree::NodePos"]},{"text":"impl&lt;F:&nbsp;PrimeField&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/merkle_tree/struct.MerklePathNode.html\" title=\"struct jf_primitives::merkle_tree::MerklePathNode\">MerklePathNode</a>&lt;F&gt;","synthetic":false,"types":["jf_primitives::merkle_tree::MerklePathNode"]},{"text":"impl&lt;F:&nbsp;PrimeField&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/merkle_tree/struct.MerklePath.html\" title=\"struct jf_primitives::merkle_tree::MerklePath\">MerklePath</a>&lt;F&gt;","synthetic":false,"types":["jf_primitives::merkle_tree::MerklePath"]},{"text":"impl&lt;F:&nbsp;Field&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/merkle_tree/struct.NodeValue.html\" title=\"struct jf_primitives::merkle_tree::NodeValue\">NodeValue</a>&lt;F&gt;","synthetic":false,"types":["jf_primitives::merkle_tree::NodeValue"]},{"text":"impl&lt;F&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/merkle_tree/struct.MerkleCommitment.html\" title=\"struct jf_primitives::merkle_tree::MerkleCommitment\">MerkleCommitment</a>&lt;F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: PrimeField,&nbsp;</span>","synthetic":false,"types":["jf_primitives::merkle_tree::MerkleCommitment"]},{"text":"impl&lt;F:&nbsp;Field&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/merkle_tree/struct.MerkleLeaf.html\" title=\"struct jf_primitives::merkle_tree::MerkleLeaf\">MerkleLeaf</a>&lt;F&gt;","synthetic":false,"types":["jf_primitives::merkle_tree::MerkleLeaf"]},{"text":"impl&lt;F:&nbsp;PrimeField&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/merkle_tree/struct.MerkleLeafProof.html\" title=\"struct jf_primitives::merkle_tree::MerkleLeafProof\">MerkleLeafProof</a>&lt;F&gt;","synthetic":false,"types":["jf_primitives::merkle_tree::MerkleLeafProof"]},{"text":"impl&lt;F:&nbsp;PrimeField&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/merkle_tree/struct.AccMemberWitness.html\" title=\"struct jf_primitives::merkle_tree::AccMemberWitness\">AccMemberWitness</a>&lt;F&gt;","synthetic":false,"types":["jf_primitives::merkle_tree::AccMemberWitness"]},{"text":"impl&lt;F:&nbsp;PrimeField&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/prf/struct.PrfKey.html\" title=\"struct jf_primitives::prf::PrfKey\">PrfKey</a>&lt;F&gt;","synthetic":false,"types":["jf_primitives::prf::PrfKey"]},{"text":"impl&lt;P&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/schnorr_dsa/struct.VerKey.html\" title=\"struct jf_primitives::schnorr_dsa::VerKey\">VerKey</a>&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Parameters + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.58.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["jf_primitives::schnorr_dsa::VerKey"]},{"text":"impl&lt;P&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/schnorr_dsa/struct.KeyPair.html\" title=\"struct jf_primitives::schnorr_dsa::KeyPair\">KeyPair</a>&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Parameters + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.58.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["jf_primitives::schnorr_dsa::KeyPair"]},{"text":"impl&lt;P&gt; CanonicalSerialize for <a class=\"struct\" href=\"jf_primitives/schnorr_dsa/struct.Signature.html\" title=\"struct jf_primitives::schnorr_dsa::Signature\">Signature</a>&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Parameters + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.58.1/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["jf_primitives::schnorr_dsa::Signature"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()