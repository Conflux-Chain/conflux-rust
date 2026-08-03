// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::proof::{
    AccumulatorConsistencyProof, TestAccumulatorProof,
    TestAccumulatorRangeProof, TransactionInfoWithProof, TransactionListProof,
};
use bcs::test_helpers::assert_canonical_encode_decode;
use diem_crypto::{
    hash::{CryptoHash, CryptoHasher},
    HashValue,
};
use diem_crypto_derive::CryptoHasher;
use proptest::prelude::*;

#[derive(
    CryptoHasher, Clone, PartialEq, serde::Serialize, serde::Deserialize,
)]
struct TestBlob(Vec<u8>);

impl CryptoHash for TestBlob {
    type Hasher = TestBlobHasher;

    fn hash(&self) -> HashValue {
        let mut hasher = Self::Hasher::default();
        hasher.update(&self.0);
        hasher.finish()
    }
}

impl std::fmt::Debug for TestBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestBlob({:?})", self.0)
    }
}

type SparseMerkleProof = crate::proof::SparseMerkleProof<TestBlob>;

proptest! {


    #[test]
    fn test_accumulator_bcs_roundtrip(proof in any::<TestAccumulatorProof>()) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_sparse_merkle_bcs_roundtrip(proof in any::<SparseMerkleProof>()) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_accumulator_consistency_bcs_roundtrip(
        proof in any::<AccumulatorConsistencyProof>(),
    ) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_accumulator_range_bcs_roundtrip(
        proof in any::<TestAccumulatorRangeProof>(),
    ) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_transaction_proof_bcs_roundtrip(proof in any::<TransactionInfoWithProof>()) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_transaction_list_proof_bcs_roundtrip(proof in any::<TransactionListProof>()) {
        assert_canonical_encode_decode(proof);
    }
}
