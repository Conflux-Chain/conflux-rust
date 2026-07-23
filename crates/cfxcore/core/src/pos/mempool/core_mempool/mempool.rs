// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Mempool is used to track transactions which have been submitted but not yet
//! agreed upon.
use crate::pos::mempool::{
    core_mempool::{
        index::TxnPointer,
        transaction::{MempoolTransaction, TimelineState},
        transaction_store::TransactionStore,
    },
    logging::{LogEntry, LogSchema, TxnsLog},
};
use diem_config::config::NodeConfig;
use diem_crypto::{hash::CryptoHash, HashValue};
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress,
    mempool_status::MempoolStatus,
    term_state::PosState,
    transaction::{
        authenticator::TransactionAuthenticator, SignedTransaction,
        TransactionPayload,
    },
    validator_verifier::ValidatorVerifier,
};
use executor::vm::verify_dispute;
use std::{collections::HashSet, time::Duration};

pub struct Mempool {
    // Stores the metadata of all transactions in mempool (of all states).
    pub transactions: TransactionStore,

    pub system_transaction_timeout: Duration,
}

impl Mempool {
    pub fn new(config: &NodeConfig) -> Self {
        Mempool {
            transactions: TransactionStore::new(&config.mempool),
            system_transaction_timeout: Duration::from_secs(
                config.mempool.system_transaction_timeout_secs,
            ),
        }
    }

    /// This function will be called once the transaction has been stored.
    pub(crate) fn remove_transaction(&mut self, hash: HashValue) {
        self.transactions.commit_transaction(hash);
    }

    /// Used to add a transaction to the Mempool.
    /// Performs basic validation: checks account's sequence number.
    pub(crate) fn add_txn(
        &mut self, txn: SignedTransaction, timeline_state: TimelineState,
    ) -> MempoolStatus {
        diem_trace!(LogSchema::new(LogEntry::AddTxn)
            .txns(TxnsLog::new_txn(txn.sender(), txn.hash())),);

        let expiration_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH")
            + self.system_transaction_timeout;

        let txn_info =
            MempoolTransaction::new(txn, expiration_time, timeline_state);

        self.transactions.insert(txn_info)
    }

    /// Fetches next block of transactions for consensus.
    /// `batch_size` - size of requested block.
    /// `seen_txns` - transactions that were sent to Consensus but were not
    /// committed yet,  mempool should filter out such transactions.
    #[allow(clippy::explicit_counter_loop)]
    pub(crate) fn get_block(
        &mut self, _batch_size: u64, mut seen: HashSet<TxnPointer>,
        pos_state: &PosState, validators: ValidatorVerifier,
    ) -> Vec<SignedTransaction> {
        let mut block = vec![];
        let mut block_log = TxnsLog::new();
        let seen_size = seen.len();
        let mut txn_walked = 0usize;
        for txn in self.transactions.iter() {
            txn_walked += 1;
            if seen.contains(&TxnPointer::from(txn)) {
                continue;
            }
            let validate_result = match txn.txn.payload() {
                TransactionPayload::Election(election_payload) => {
                    pos_state.validate_election(election_payload)
                }
                TransactionPayload::PivotDecision(_) => {
                    seen.insert((txn.get_sender(), txn.get_hash()));
                    continue;
                }
                TransactionPayload::Dispute(dispute_payload) => {
                    // TODO(lpl): Only dispute a node once.
                    pos_state.validate_dispute(dispute_payload).and(
                        verify_dispute(dispute_payload)
                            .then_some(())
                            .ok_or(anyhow::anyhow!("invalid dispute")),
                    )
                }
                _ => {
                    continue;
                }
            };
            if validate_result.is_ok() {
                block.push(txn.txn.clone());
                block_log.add(txn.get_sender(), txn.get_hash());
                seen.insert((txn.get_sender(), txn.get_hash()));
            }
        }
        let mut max_pivot_height = 0;
        let mut chosen_pivot_tx = None;
        // iterate all pivot decision transaction
        for pivot_decision_set in self.transactions.iter_pivot_decision() {
            // Admission accepts node_map (non-committee) voters, and
            // `check_voting_power` errors `UnknownAuthor` on them; filter to
            // the committee so one such vote can't fail a valid quorum.
            let committee_votes: Vec<&(AccountAddress, HashValue)> =
                pivot_decision_set
                    .iter()
                    .filter(|(addr, _)| {
                        validators.get_voting_power(addr).is_some()
                    })
                    .collect();
            if validators
                .check_voting_power(
                    committee_votes.iter().map(|(addr, _)| addr),
                )
                .is_ok()
            {
                // Any committee vote carries the same payload; use the first.
                let Some(pivot_decision) = committee_votes
                    .iter()
                    .find_map(|(_, hash)| self.transactions.get(hash))
                else {
                    continue;
                };
                let pivot_height = match pivot_decision.payload() {
                    TransactionPayload::PivotDecision(decision) => {
                        decision.height
                    }
                    _ => unreachable!(),
                };
                if pivot_height > max_pivot_height
                    && pivot_height > pos_state.pivot_decision().height
                {
                    max_pivot_height = pivot_height;
                    chosen_pivot_tx = Some(pivot_decision);
                }
            }
        }
        if let Some(tx) = chosen_pivot_tx {
            let pivot_decision_hash = match tx.payload() {
                TransactionPayload::PivotDecision(decision) => decision.hash(),
                _ => unreachable!(),
            };
            // aggregate signatures
            let txn_hashes =
                self.transactions.get_pivot_decisions(&pivot_decision_hash);
            let senders: Vec<AccountAddress> =
                validators.get_ordered_account_addresses_iter().collect();
            let mut signatures = vec![];
            let mut seen_signers = HashSet::new();
            for hash in &txn_hashes {
                if let Some(txn) = self.transactions.get(hash) {
                    match txn.authenticator() {
                        TransactionAuthenticator::BLS { signature, .. } => {
                            if let Ok(index) =
                                senders.binary_search(&txn.sender())
                            {
                                // One slot per validator: guard the index so a
                                // repeated signer can't abort aggregation.
                                if seen_signers.insert(index) {
                                    signatures.push((signature, index));
                                }
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
            match SignedTransaction::new_multisig(tx.raw_txn(), signatures) {
                Ok(new_tx) => {
                    block_log.add(new_tx.sender(), new_tx.hash());
                    block.push(new_tx);
                }
                Err(e) => {
                    // Never panic in proposal construction; skip this decision.
                    diem_error!(
                        "get_block: failed to aggregate pivot decision \
                         multisig, skipping: {:?}",
                        e
                    );
                }
            }
        }

        diem_debug!(
            LogSchema::new(LogEntry::GetBlock).txns(block_log),
            seen_consensus = seen_size,
            walked = txn_walked,
            seen_after = seen.len(),
            result_size = block.len(),
            block_size = block.len()
        );
        block
    }

    /// Periodic core mempool garbage collection. Removes all expired
    /// transactions by system TTL.
    pub(crate) fn gc(&mut self) { self.transactions.gc_by_system_ttl(); }

    /// Read `count` transactions from timeline since `timeline_id`.
    /// Returns block of transactions and new last_timeline_id.
    pub(crate) fn read_timeline(
        &mut self, timeline_id: u64, count: usize,
    ) -> (Vec<SignedTransaction>, u64) {
        self.transactions.read_timeline(timeline_id, count)
    }

    /// Read transactions from timeline from `start_id` (exclusive) to `end_id`
    /// (inclusive).
    pub(crate) fn timeline_range(
        &mut self, start_id: u64, end_id: u64,
    ) -> Vec<SignedTransaction> {
        self.transactions.timeline_range(start_id, end_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_types::H256;
    use diem_crypto::{PrivateKey, Uniform};
    use diem_types::{
        block_info::PivotBlockDecision,
        chain_id::ChainId,
        mempool_status::MempoolStatusCode,
        term_state::{
            pos_state_config::{PosStateConfig, POS_STATE_CONFIG},
            NodeID, PosState,
        },
        transaction::RawTransaction,
        validator_config::{ConsensusPrivateKey, ConsensusVRFPrivateKey},
    };

    fn new_node() -> (NodeID, ConsensusPrivateKey) {
        let sk = ConsensusPrivateKey::generate_for_testing();
        let vrf_sk = ConsensusVRFPrivateKey::generate_for_testing();
        (NodeID::new(sk.public_key(), vrf_sk.public_key()), sk)
    }

    fn insert_pivot_vote(
        mempool: &mut Mempool, node: &NodeID, sk: &ConsensusPrivateKey,
        decision: &PivotBlockDecision,
    ) {
        let signed = RawTransaction::new_pivot_decision(
            node.addr,
            decision.clone(),
            ChainId::new(1),
        )
        .sign(sk)
        .unwrap()
        .into_inner();
        assert_eq!(
            mempool.add_txn(signed, TimelineState::NotReady).code,
            MempoolStatusCode::Accepted
        );
    }

    /// A registered non-committee voter (admission gates on `node_map`,
    /// broader than the committee) must not stall aggregation of a committee
    /// quorum: it is ignored, not counted as `UnknownAuthor`.
    #[test]
    fn get_block_aggregates_committee_quorum_ignoring_non_committee_voter() {
        POS_STATE_CONFIG.get_or_init(PosStateConfig::default);
        let (v1, sk1) = new_node();
        let (v2, sk2) = new_node();
        let (v3, sk3) = new_node();
        let (outsider, sk_out) = new_node();

        // All four are registered (node_map), so the outsider's vote is
        // admitted; the committee is only v1/v2/v3.
        let initial_nodes = vec![
            (v1.clone(), 1),
            (v2.clone(), 1),
            (v3.clone(), 1),
            (outsider.clone(), 1),
        ];
        let initial_committee = vec![(v1.addr, 1), (v2.addr, 1), (v3.addr, 1)];
        let pos_state = PosState::new(
            vec![7; 32],
            initial_nodes,
            initial_committee,
            PivotBlockDecision {
                block_hash: H256::zero(),
                height: 0,
            },
        );
        let validators = pos_state.epoch_state().verifier().clone();
        let mut mempool = Mempool::new(&NodeConfig::default());

        let decision = PivotBlockDecision {
            block_hash: H256::from([9u8; 32]),
            height: 1,
        };
        // Full committee reaches quorum; the outsider also votes.
        insert_pivot_vote(&mut mempool, &v1, &sk1, &decision);
        insert_pivot_vote(&mut mempool, &v2, &sk2, &decision);
        insert_pivot_vote(&mut mempool, &v3, &sk3, &decision);
        insert_pivot_vote(&mut mempool, &outsider, &sk_out, &decision);

        let block =
            mempool.get_block(10, HashSet::new(), &pos_state, validators);

        let aggregated_pivot = block.iter().any(|tx| {
            matches!(
                tx.payload(),
                TransactionPayload::PivotDecision(d) if *d == decision
            )
        });
        assert!(
            aggregated_pivot,
            "committee quorum must aggregate despite a non-committee voter",
        );
    }
}
