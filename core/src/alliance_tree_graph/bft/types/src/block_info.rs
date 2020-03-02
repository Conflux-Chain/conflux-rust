// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account_config, crypto_proxies::ValidatorSet, event::EventKey,
    transaction::Version,
};
use anyhow::{Error, Result};
use cfx_types::H256;
use libra_crypto::hash::HashValue;
#[cfg(any(test, feature = "fuzzing"))]
use libra_crypto::hash::ACCUMULATOR_PLACEHOLDER_HASH;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
};

/// The round of a block is a consensus-internal counter, which starts with 0
/// and increases monotonically.
pub type Round = u64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]

pub struct PivotBlockDecision {
    pub height: u64,
    pub block_hash: H256,
    pub parent_hash: H256,
}

impl PivotBlockDecision {
    pub fn pivot_select_event_key() -> EventKey {
        EventKey::new_from_address(
            &account_config::pivot_chain_select_address(),
            2,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        lcs::from_bytes(bytes).map_err(Into::into)
    }
}

impl TryFrom<crate::proto::types::PivotBlockDecision> for PivotBlockDecision {
    type Error = Error;

    fn try_from(
        proto: crate::proto::types::PivotBlockDecision,
    ) -> Result<Self> {
        Ok(PivotBlockDecision {
            height: proto.height,
            block_hash: H256::from_slice(&proto.block_hash),
            parent_hash: H256::from_slice(&proto.parent_hash),
        })
    }
}

impl From<PivotBlockDecision> for crate::proto::types::PivotBlockDecision {
    fn from(pivot: PivotBlockDecision) -> Self {
        Self {
            height: pivot.height,
            block_hash: Vec::from(&pivot.block_hash[..]),
            parent_hash: Vec::from(&pivot.parent_hash[..]),
        }
    }
}

/// This structure contains all the information needed for tracking a block
/// without having access to the block or its execution output state. It
/// assumes that the block is the last block executed within the ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]

pub struct BlockInfo {
    /// Epoch number corresponds to the set of validators that are active for
    /// this block.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically
    /// increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The last pivot block selection after executing this block.
    /// None means choosing TreeGraph genesis as the first pivot block.
    pivot: Option<PivotBlockDecision>,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the set of validators for the start of the
    /// next epoch
    next_validator_set: Option<ValidatorSet>,
}

impl BlockInfo {
    pub fn new(
        epoch: u64, round: Round, id: HashValue,
        pivot: Option<PivotBlockDecision>, executed_state_id: HashValue,
        version: Version, timestamp_usecs: u64,
        next_validator_set: Option<ValidatorSet>,
    ) -> Self
    {
        Self {
            epoch,
            round,
            id,
            pivot,
            executed_state_id,
            version,
            timestamp_usecs,
            next_validator_set,
        }
    }

    pub fn empty() -> Self {
        Self {
            epoch: 0,
            round: 0,
            id: HashValue::zero(),
            pivot: None,
            executed_state_id: HashValue::zero(),
            version: 0,
            timestamp_usecs: 0,
            next_validator_set: None,
        }
    }

    pub fn random(round: Round) -> Self {
        Self {
            epoch: 1,
            round,
            id: HashValue::zero(),
            pivot: None,
            executed_state_id: HashValue::zero(),
            version: 0,
            timestamp_usecs: 0,
            next_validator_set: None,
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn genesis() -> Self {
        Self {
            epoch: 0,
            round: 0,
            id: HashValue::zero(),
            pivot: None,
            executed_state_id: *ACCUMULATOR_PLACEHOLDER_HASH,
            version: 0,
            timestamp_usecs: 0,
            next_validator_set: Some(ValidatorSet::new(vec![])),
        }
    }

    pub fn epoch(&self) -> u64 { self.epoch }

    pub fn executed_state_id(&self) -> HashValue { self.executed_state_id }

    pub fn has_reconfiguration(&self) -> bool {
        self.next_validator_set.is_some()
    }

    pub fn id(&self) -> HashValue { self.id }

    pub fn next_validator_set(&self) -> Option<&ValidatorSet> {
        self.next_validator_set.as_ref()
    }

    pub fn pivot_decision(&self) -> Option<&PivotBlockDecision> {
        self.pivot.as_ref()
    }

    pub fn round(&self) -> Round { self.round }

    pub fn timestamp_usecs(&self) -> u64 { self.timestamp_usecs }

    pub fn version(&self) -> Version { self.version }
}

impl Display for BlockInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "BlockInfo: [epoch: {}, round: {}, id: {}, pivot: {:?}, version: {}, timestamp (us): {}, next_validator_set: {}]",
            self.epoch(),
            self.round(),
            self.id(),
            self.pivot_decision(),
            self.version(),
            self.timestamp_usecs(),
            self.next_validator_set.as_ref().map_or("None".to_string(), |validator_set| format!("{}", validator_set)),
        )
    }
}
