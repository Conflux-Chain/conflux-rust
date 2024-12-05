// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    account_address::AccountAddress,
    chain_id::ChainId,
    transaction::{
        Module, RawTransaction, Script, SignatureCheckedTransaction,
        SignedTransaction,
    },
    write_set::WriteSet,
};
use diem_crypto::{bls::*, traits::*};

static EMPTY_SCRIPT: &[u8] = include_bytes!("empty_script.mv");

// Create an expiration time 'seconds' after now
fn expiration_time(seconds: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("System time is before the UNIX_EPOCH")
        .as_secs()
        + seconds
}

// Test helper for transaction creation
pub fn get_test_signed_module_publishing_transaction(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    public_key: BLSPublicKey, module: Module,
) -> SignedTransaction {
    let expiration_time = expiration_time(10);
    let raw_txn = RawTransaction::new_module(
        sender,
        module,
        expiration_time,
        ChainId::test(),
    );

    let signature = private_key.sign(&raw_txn);

    SignedTransaction::new(raw_txn, public_key, signature)
}

// Test helper for transaction creation
pub fn get_test_signed_transaction(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    public_key: BLSPublicKey, script: Option<Script>,
    expiration_timestamp_secs: u64,
) -> SignedTransaction {
    let raw_txn = RawTransaction::new_script(
        sender,
        script.unwrap_or_else(|| {
            Script::new(EMPTY_SCRIPT.to_vec(), vec![], Vec::new())
        }),
        expiration_timestamp_secs,
        ChainId::test(),
    );

    let signature = private_key.sign(&raw_txn);

    SignedTransaction::new(raw_txn, public_key, signature)
}

// Test helper for creating transactions for which the signature hasn't been
// checked.
pub fn get_test_unchecked_transaction(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    public_key: BLSPublicKey, script: Option<Script>, expiration_time: u64,
) -> SignedTransaction {
    get_test_unchecked_transaction_(
        sender,
        private_key,
        public_key,
        script,
        expiration_time,
        ChainId::test(),
    )
}

// Test helper for creating transactions for which the signature hasn't been
// checked.
fn get_test_unchecked_transaction_(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    public_key: BLSPublicKey, script: Option<Script>,
    expiration_timestamp_secs: u64, chain_id: ChainId,
) -> SignedTransaction {
    let raw_txn = RawTransaction::new_script(
        sender,
        script.unwrap_or_else(|| {
            Script::new(EMPTY_SCRIPT.to_vec(), vec![], Vec::new())
        }),
        expiration_timestamp_secs,
        chain_id,
    );

    let signature = private_key.sign(&raw_txn);

    SignedTransaction::new(raw_txn, public_key, signature)
}

// Test helper for transaction creation. Short version for
// get_test_signed_transaction Omits some fields
pub fn get_test_signed_txn(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    public_key: BLSPublicKey, script: Option<Script>,
) -> SignedTransaction {
    let expiration_time = expiration_time(10);
    get_test_signed_transaction(
        sender,
        private_key,
        public_key,
        script,
        expiration_time,
    )
}

pub fn get_test_unchecked_txn(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    public_key: BLSPublicKey, script: Option<Script>,
) -> SignedTransaction {
    let expiration_time = expiration_time(10);
    get_test_unchecked_transaction(
        sender,
        private_key,
        public_key,
        script,
        expiration_time,
    )
}

pub fn get_test_txn_with_chain_id(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    public_key: BLSPublicKey, chain_id: ChainId,
) -> SignedTransaction {
    let expiration_time = expiration_time(10);
    get_test_unchecked_transaction_(
        sender,
        private_key,
        public_key,
        None,
        expiration_time,
        chain_id,
    )
}

pub fn get_write_set_txn(
    sender: AccountAddress, private_key: &BLSPrivateKey,
    _public_key: BLSPublicKey, write_set: Option<WriteSet>,
) -> SignatureCheckedTransaction {
    let write_set = write_set.unwrap_or_default();
    RawTransaction::new_write_set(sender, write_set, ChainId::test())
        .sign(&private_key)
        .unwrap()
}
