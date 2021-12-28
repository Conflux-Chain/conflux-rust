// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    account_address::AccountAddress,
    chain_id::ChainId,
    transaction::{
        metadata, GovernanceRole, RawTransaction, Script, SignedTransaction,
        Transaction, TransactionInfo, TransactionListWithProof,
        TransactionPayload, TransactionWithProof,
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
        RawTransaction::new_script(
            AccountAddress::random(),
            Script::new(vec![], vec![], vec![]),
            0,
            ChainId::test(),
        ),
        BLSPrivateKey::generate_for_testing().public_key(),
        bcs::from_bytes(&sig_bytes[..]).unwrap(),
    );
    txn.check_signature()
        .expect_err("signature checking should fail");
}

#[test]
fn test_role_ordering() {
    use GovernanceRole::*;
    assert!(DiemRoot.priority() > TreasuryCompliance.priority());
    assert!(DiemRoot.priority() > Validator.priority());
    assert!(DiemRoot.priority() > ValidatorOperator.priority());
    assert!(DiemRoot.priority() > DesignatedDealer.priority());

    assert!(TreasuryCompliance.priority() > Validator.priority());
    assert!(TreasuryCompliance.priority() > ValidatorOperator.priority());
    assert!(TreasuryCompliance.priority() > DesignatedDealer.priority());

    assert!(Validator.priority() == ValidatorOperator.priority());
    assert!(Validator.priority() == DesignatedDealer.priority());
}

#[test]
fn test_general_metadata_constructor_and_setters() {
    let raw_to_subaddr = b"to_subaddr".to_vec();
    let to_subaddress = Some(raw_to_subaddr.clone());
    let raw_from_subaddr = b"from_subaddr".to_vec();
    let from_subaddress = Some(raw_from_subaddr.clone());
    let referenced_event = Some(1337);
    let general_metadata = metadata::GeneralMetadataV0::new(
        to_subaddress,
        from_subaddress,
        referenced_event,
    );

    assert!(
        general_metadata
            .to_subaddress()
            .as_ref()
            .expect("incorrect to_subaddress")
            == &raw_to_subaddr
    );
    assert!(
        general_metadata
            .from_subaddress()
            .as_ref()
            .expect("incorrect from suabbdress")
            == &raw_from_subaddr
    );
    assert!(general_metadata.referenced_event() == &referenced_event);
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
fn transaction_list_with_proof_bcs_roundtrip(txn_list in any::<TransactionListWithProof>()) {
    assert_canonical_encode_decode(txn_list);
}


#[test]
fn transaction_bcs_roundtrip(txn in any::<Transaction>()) {
    assert_canonical_encode_decode(txn);
}


#[test]
fn transaction_with_proof_bcs_roundtrip(txn_with_proof in any::<TransactionWithProof>()) {
    assert_canonical_encode_decode(txn_with_proof);
}
}
