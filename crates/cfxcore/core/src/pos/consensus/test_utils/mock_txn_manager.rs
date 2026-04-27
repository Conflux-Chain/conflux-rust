// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::consensus::{
    error::MempoolError, state_replication::TxnManager,
};
use anyhow::Result;
use consensus_types::{
    block::block_test_utils::random_payload, common::Payload,
};
use diem_crypto::HashValue;
use diem_types::validator_verifier::ValidatorVerifier;

#[derive(Clone, Default)]
pub struct MockTransactionManager;

#[async_trait::async_trait]
impl TxnManager for MockTransactionManager {
    async fn pull_txns(
        &self, _max_size: u64, _exclude_txns: Vec<&Payload>, _hash: HashValue,
        _validators: ValidatorVerifier,
    ) -> Result<Payload, MempoolError> {
        // generate 1k txn is too slow with coverage instrumentation
        Ok(random_payload(10))
    }
}
