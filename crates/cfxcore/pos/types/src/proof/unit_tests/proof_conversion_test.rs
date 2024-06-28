// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    account_state_blob::AccountStateBlob,
    proof::{
        AccountStateProof, AccumulatorConsistencyProof, EventProof,
        SparseMerkleRangeProof, TestAccumulatorProof,
        TestAccumulatorRangeProof, TransactionInfoWithProof,
        TransactionListProof,
    },
};
use bcs::test_helpers::assert_canonical_encode_decode;
use proptest::prelude::*;

type SparseMerkleProof = crate::proof::SparseMerkleProof<AccountStateBlob>;

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
    fn test_sparse_merkle_range_bcs_roundtrip(
        proof in any::<SparseMerkleRangeProof>(),
    ) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_transaction_proof_bcs_roundtrip(proof in any::<TransactionInfoWithProof>()) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_account_state_proof_bcs_roundtrip(proof in any::<AccountStateProof>()) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_event_proof_bcs_roundtrip(proof in any::<EventProof>()) {
        assert_canonical_encode_decode(proof);
    }


    #[test]
    fn test_transaction_list_proof_bcs_roundtrip(proof in any::<TransactionListProof>()) {
        assert_canonical_encode_decode(proof);
    }
}
