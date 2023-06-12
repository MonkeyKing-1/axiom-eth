use super::*;
use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakCircuitBuilder, VarLenRLCs},
    rlp::builder::RlcThreadBuilder,
    util::EthConfigParams,
};
use ark_std::{end_timer, start_timer};
use ethers_core::{utils::keccak256, abi::encode};
use halo2_base::{
    halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    utils::fs::gen_srs,
};
use hasher::HasherKeccak;
use hex::FromHex;
use rand_core::OsRng;
use rayon::string;
use std::{
    cell::RefCell,
    env::{set_var, var},
    fs::File,
    io::{BufReader, Write},
    path::Path, sync::Arc,
};
use test_log::test;
use test_case::test_case;
use cita_trie::{self, PatriciaTrie, MemoryDB, Trie};




#[test_case(1; "1 leaf")]
#[test_case(2; "2 keys")]


fn full_tree_test(num_keys: usize) {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    for idx in 0..num_keys {
        let key = rlp::encode(&idx.to_string()).to_vec();
        let val = [0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16];
        trie.insert(key, val.to_vec()).unwrap();
    }
    for idx in 0..num_keys {
        let k = params.degree;
        let key = rlp::encode(&idx.to_string()).to_vec();
        let val = [0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16];
        let key_byte_len = key.len();
        let input = mpt_direct_input(val.to_vec(), trie.get_proof(&key).unwrap(), trie.root().unwrap(), key, false, 6, 32, Some(key_byte_len)); // depth = max_depth
        let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }
}


fn mpt_direct_input(value: Vec<u8>, proof: Vec<Vec<u8> >, hash: Vec<u8>, key: Vec<u8>, slot_is_empty: bool, max_depth: usize, max_key_byte_len: usize, key_byte_len: Option<usize>) -> MPTKeyInput {
    /*let block: serde_json::Value =
    serde_json::from_reader(File::open("scripts/input_gen/block.json").unwrap()).unwrap();*/
    // println!("acct_pf {:?}", acct_pf);
    // println!("storage_root {:?}", pf["storageHash"]);
    // println!("storage_pf {:?}", storage_pf);
    let path = match key_byte_len {
        Some(_key_byte_len) => PathType::Var(key),
        None => PathType::Fixed(H256(keccak256(key)))
    };
    // let path = keccak256(from_hex(&key_bytes_str));
    //= ::rlp::encode(&from_hex(&value_bytes_str)).to_vec();
    let value_max_byte_len = 33;

    MPTKeyInput {
        path,
        value,
        root_hash: H256::from_slice(&hash.as_slice()),
        proof,
        slot_is_empty,
        value_max_byte_len,
        max_depth,
        max_key_byte_len,
        key_byte_len,
    }
}





#[test_case("scripts/input_gen/pos_data/inclusion1_pf.json".to_string(), 5, 32, Some(32); "correct inclusion 1")]
#[test_case("scripts/input_gen/pos_data/inclusion2_pf.json".to_string(), 5, 32, Some(32); "correct inclusion 2")]
#[test_case("scripts/input_gen/neg_data/wrong_path_default_storage_pf.json".to_string(), 5, 32, Some(32); "wrong path inclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_val_default_storage_pf.json".to_string(), 5, 32, Some(32); "wrong val inclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_proof_default_storage_pf.json".to_string(), 5, 32, Some(32); "wrong proof inclusion")]
#[test_case("scripts/input_gen/pos_data/inclusion1_pf.json".to_string(), 5, 32, None; "fixed correct inclusion 1")]
#[test_case("scripts/input_gen/pos_data/inclusion2_pf.json".to_string(), 5, 32, None; "fixed correct inclusion 2")]
#[test_case("scripts/input_gen/neg_data/wrong_proof_default_storage_pf.json".to_string(), 5, 32, None; "fixed wrong proof inclusion")]
#[test_case("scripts/input_gen/pos_data/small_case.json".to_string(), 3, 1, Some(1); "correct small case")]

pub fn test_mpt_inclusion_fixed(path : String, depth: usize, max_byte_len: usize, byte_len: Option<usize>) {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    // std::env::set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input = mpt_input(path, false, depth, max_byte_len, byte_len); // depth = max_depth
    let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}



#[test_case("scripts/input_gen/pos_data/noninclusion_branch_pf.json".to_string(), 5, 32, Some(32); "branch exclusion")]
#[test_case("scripts/input_gen/pos_data/noninclusion_extension_pf.json".to_string(), 6, 32, Some(32); "extension exclusion")]
#[test_case("scripts/input_gen/pos_data/noninclusion_extension_pf.json".to_string(), 6, 32, Some(32); "wrong depth extension exclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_path_noninclusion_branch_pf.json".to_string(), 6, 32, Some(32); "wrong path exclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_val_noninclusion_branch_pf.json".to_string(), 6, 32, Some(32); "wrong val exclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_proof_noninclusion_extension_pf.json".to_string(), 6, 32, Some(32); "wrong proof exclusion")]
pub fn test_mpt_exclusion_fixed(path : String, depth : usize, max_byte_len: usize, byte_len: Option<usize>) {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    // std::env::set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input = mpt_input(path, true, depth, max_byte_len, byte_len); // depth = max_depth
    let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}