// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]
// Increase recursion limit to allow for use of select! macro.

//! Mempool is used to hold transactions that have been submitted but not yet
//! agreed upon and executed.
//!
//! **Flow**: AC sends transactions into mempool which holds them for a period
//! of time before sending them into consensus.  When a new transaction is
//! added, Mempool shares this transaction with other nodes in the system.  This
//! is a form of “shared mempool” in that transactions between mempools are
//! shared with other validators.  This helps maintain a pseudo global ordering
//! since when a validator receives a transaction from another mempool, it will
//! be ordered when added in the ordered queue of the recipient validator. To
//! reduce network consumption, in “shared mempool” each validator is
//! responsible for delivery of its own transactions (we don't rebroadcast
//! transactions originated on a different peer). Also we only broadcast
//! transactions that have some chance to be included in next block: their
//! sequence number equals to the next sequence number of account or sequential
//! to it. For example, if the current sequence number for an account is 2 and
//! local mempool contains transactions with sequence numbers 2,3,4,7,8, then
//! only transactions 2, 3 and 4 will be broadcast.
//!
//! Consensus pulls transactions from mempool rather than mempool pushing into
//! consensus. Mempool doesn't track which transactions have already been sent
//! to Consensus; on each `get_block` request Consensus forwards a set of
//! transactions that were pulled from Mempool but not yet committed, so
//! Mempool can stay agnostic about Consensus proposal branches. Once a
//! transaction is fully executed and written to storage, Consensus notifies
//! Mempool and the transaction is dropped.
//!
//! **Internals**: Mempool is modeled as
//! `HashMap<AccountAddress, AccountTransactions>` plus a TTL index used only
//! for expiration/GC. There is no priority ordering — the PoS mempool carries
//! only PoS-specific transactions (Election, PivotDecision, BLS signatures),
//! not user traffic, so gas-price ranking does not apply. `get_block` iterates
//! accounts, returning sequence-number-ordered transactions per account while
//! skipping those that Consensus has already seen.
//!
//! Mempool caps both total transaction count and per-account count to bound
//! memory use.
//!
//! Transactions in Mempool have two types of expirations: systemTTL and
//! client-specified expiration. Once we hit either of those, the transaction is
//! removed from Mempool. SystemTTL is checked periodically in the background,
//! while the client-specified expiration is checked on every Consensus commit
//! request. We use a separate system TTL to ensure that a transaction won't
//! remain stuck in Mempool forever, even if Consensus doesn't make progress

pub use shared_mempool::{
    bootstrap, network,
    types::{
        CommitNotification, CommitResponse, CommittedTransaction,
        ConsensusRequest, ConsensusResponse, MempoolClientSender,
        SubmissionStatus, TransactionExclusion,
    },
};

mod core_mempool;
mod logging;
mod shared_mempool;
