// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    account_address::AccountAddress,
    chain_id::ChainId,
    transaction::{
        RawTransaction, RetirePayload, SignedTransaction, Transaction,
        TransactionInfo, TransactionPayload, TransactionWithProof,
    },
};
use bcs::test_helpers::assert_canonical_encode_decode;
use diem_crypto::{
    bls::{self, BLSPrivateKey},
    PrivateKey, SigningKey, Uniform,
};
use proptest::prelude::*;

#[test]
fn test_invalid_signature() {
    let private_key = BLSPrivateKey::generate_for_testing();
    let message = vec![0];
    let sig = private_key.sign_arbitrary_message(&message[..]);
    let sig_bytes = bcs::to_bytes(&sig).unwrap();
    let txn: SignedTransaction = SignedTransaction::new(
        RawTransaction::new(
            AccountAddress::random(),
            TransactionPayload::Retire(RetirePayload {
                node_id: AccountAddress::random(),
                votes: 0,
            }),
            0,
            ChainId::test(),
        ),
        BLSPrivateKey::generate_for_testing().public_key(),
        bcs::from_bytes(&sig_bytes[..]).unwrap(),
    );
    txn.check_signature()
        .expect_err("signature checking should fail");
}

proptest! {
    #[test]
    fn test_sign_raw_transaction(raw_txn in any::<RawTransaction>(), keypair in bls::keypair_strategy()) {
        let txn = raw_txn.sign(&keypair.private_key).unwrap();
        let signed_txn = txn.into_inner();
        assert!(signed_txn.check_signature().is_ok());
    }

    #[test]
    fn transaction_payload_bcs_roundtrip(txn_payload in any::<TransactionPayload>()) {
        assert_canonical_encode_decode(txn_payload);
    }

    #[test]
    fn raw_transaction_bcs_roundtrip(raw_txn in any::<RawTransaction>()) {
        assert_canonical_encode_decode(raw_txn);
    }

    #[test]
    fn signed_transaction_bcs_roundtrip(signed_txn in any::<SignedTransaction>()) {
        assert_canonical_encode_decode(signed_txn);
    }

    #[test]
    fn transaction_info_bcs_roundtrip(txn_info in any::<TransactionInfo>()) {
        assert_canonical_encode_decode(txn_info);
    }
}

proptest! {
#![proptest_config(ProptestConfig::with_cases(10))]

#[test]
fn transaction_bcs_roundtrip(txn in any::<Transaction>()) {
    assert_canonical_encode_decode(txn);
}

#[test]
fn transaction_with_proof_bcs_roundtrip(txn_with_proof in any::<TransactionWithProof>()) {
    assert_canonical_encode_decode(txn_with_proof);
}
}
