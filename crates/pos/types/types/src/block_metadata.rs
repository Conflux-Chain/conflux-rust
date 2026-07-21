// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    account_address::AccountAddress, account_config::diem_root_address,
    event::EventKey,
};
use diem_crypto::HashValue;
use serde::{Deserialize, Serialize};

/// Struct that will be persisted on chain to store the information of the
/// current block.
///
/// The flow will look like following:
/// 1. Consensus prepends a `Transaction::BlockMetadata` to each PoS block.
/// 2. The Rust `PosVM` processes it before user transactions; it is a block
/// marker and may emit PoS state events such as unlock/new-epoch events. The
/// stored metadata is later used by storage/RPC for block timestamp/id.
/// 3. No on-chain Move resource/read method exposes consensus or leader info.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMetadata {
    id: HashValue,
    round: u64,
    timestamp_usecs: u64,
    // The vector has to be sorted to ensure consistent result among all nodes
    previous_block_votes: Vec<AccountAddress>,
    proposer: AccountAddress,
}

impl BlockMetadata {
    pub fn new(
        id: HashValue, round: u64, timestamp_usecs: u64,
        previous_block_votes: Vec<AccountAddress>, proposer: AccountAddress,
    ) -> Self {
        Self {
            id,
            round,
            timestamp_usecs,
            previous_block_votes,
            proposer,
        }
    }

    pub fn id(&self) -> HashValue { self.id }

    pub fn into_inner(self) -> (u64, u64, Vec<AccountAddress>, AccountAddress) {
        (
            self.round,
            self.timestamp_usecs,
            self.previous_block_votes.clone(),
            self.proposer,
        )
    }

    pub fn timestamp_usec(&self) -> u64 { self.timestamp_usecs }

    pub fn proposer(&self) -> AccountAddress { self.proposer }
}

pub fn new_block_event_key() -> EventKey {
    EventKey::new_from_address(&diem_root_address(), 17)
}

#[derive(Clone, Deserialize, Serialize)]
pub struct NewBlockEvent {
    round: u64,
    proposer: AccountAddress,
    votes: Vec<AccountAddress>,
    timestamp: u64,
}

impl NewBlockEvent {
    pub fn new(
        round: u64, proposer: AccountAddress, votes: Vec<AccountAddress>,
        timestamp: u64,
    ) -> Self {
        Self {
            round,
            proposer,
            votes,
            timestamp,
        }
    }

    pub fn round(&self) -> u64 { self.round }

    pub fn proposer(&self) -> AccountAddress { self.proposer }

    pub fn votes(&self) -> Vec<AccountAddress> { self.votes.clone() }
}
