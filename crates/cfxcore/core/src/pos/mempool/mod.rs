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
//! **Flow**: Local transactions are submitted by the consensus layer itself
//! (round_manager signs and submits its own Election/PivotDecision/Dispute
//! transactions through the client-submission channel); there is no external
//! client/AC submission path.  When a new transaction is
//! added, Mempool shares this transaction with other nodes in the system.  This
//! is a form of “shared mempool” in that transactions between mempools are
//! shared with other validators.  This helps maintain a pseudo global ordering
//! since when a validator receives a transaction from another mempool, it will
//! be ordered when added in the ordered queue of the recipient validator. Every
//! newly inserted transaction — locally submitted or peer-received — is
//! appended to the broadcast timeline, so nodes rebroadcast peer-received
//! transactions. Duplicate suppression is receive-side: already-known
//! transaction hashes are filtered before validation/insertion.
//!
//! Consensus pulls transactions from mempool rather than mempool pushing into
//! consensus. Mempool doesn't track which transactions have already been sent
//! to Consensus; on each `get_block` request Consensus forwards a set of
//! transactions that were pulled from Mempool but not yet committed, so
//! Mempool can stay agnostic about Consensus proposal branches. Once a
//! transaction is fully executed and written to storage, Consensus notifies
//! Mempool and the transaction is dropped.
//!
//! **Internals**: Mempool stores normal and pivot-decision transactions in
//! hash-keyed maps. It also maintains a `PivotBlockDecision::hash()` ->
//! `(sender, tx_hash)` index for pivot-decision vote aggregation, per-sender
//! counters for the capacity cap, a TTL index for expiration/GC, and a
//! timeline index for broadcast; there is no account/sequence ordering or
//! gas-price priority. `get_block` iterates all stored transactions in
//! arbitrary order, skipping those Consensus has already seen and
//! revalidating Election/Dispute payloads against the parent block's
//! PosState; pivot decisions are handled separately — votes for the same
//! pivot hash are grouped and the highest decision backed by a quorum of
//! voting power is emitted as a single aggregated BLS-multisig transaction.
//!
//! Mempool has no global transaction-count cap; it enforces per-sender
//! capacity and evicts old transactions by system TTL.
//!
//! Transactions expire only by systemTTL, GC'd periodically in the background,
//! so a transaction can't stay stuck in Mempool forever even if Consensus
//! stalls. (Client-specified expiration was removed; see the validator.)

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
