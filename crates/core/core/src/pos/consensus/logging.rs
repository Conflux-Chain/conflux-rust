// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use consensus_types::common::Author;
use diem_logger::Schema;
use diem_types::block_info::Round;
use serde::Serialize;

#[derive(Schema)]
pub struct LogSchema {
    event: LogEvent,
    remote_peer: Option<Author>,
    epoch: Option<u64>,
    round: Option<Round>,
}

#[derive(Serialize)]
pub enum LogEvent {
    CommitViaBlock,
    HelpPeerSync,
    NewEpoch,
    NewRound,
    Propose,
    ReceiveEpochChangeProof,
    ReceiveEpochRetrieval,
    ReceiveMessageFromDifferentEpoch,
    ReceiveProposal,
    ReceiveSyncInfo,
    ReceiveVote,
    RetrieveBlock,
    StateSync,
    SyncToPeer,
    Timeout,
    Vote,
    VoteNIL,
}

impl LogSchema {
    pub fn new(event: LogEvent) -> Self {
        Self {
            event,
            remote_peer: None,
            epoch: None,
            round: None,
        }
    }
}
