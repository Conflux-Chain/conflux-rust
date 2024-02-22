// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::consensus::{
    block_storage::{BlockReader, BlockStore},
    logging::{LogEvent, LogSchema},
    network::{ConsensusMsg, ConsensusNetworkSender},
    persistent_liveness_storage::{PersistentLivenessStorage, RecoveryData},
    state_replication::StateComputer,
};
use anyhow::{bail, format_err};
use consensus_types::{
    block::Block,
    block_retrieval::{BlockRetrievalRequest, BlockRetrievalStatus},
    common::Author,
    quorum_cert::QuorumCert,
};
use diem_crypto::HashValue;
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress, epoch_change::EpochChangeProof,
    ledger_info::LedgerInfoWithSignatures,
};
use rand::{prelude::*, Rng};
use std::{clone::Clone, sync::Arc, time::Duration};

pub const BLOCK_FETCH_BATCH_MAX_SIZE: u64 = 60;

#[derive(Debug, PartialEq)]
/// Whether we need to do block retrieval if we want to insert a Quorum Cert.
pub enum NeedFetchResult {
    QCRoundBeforeRoot,
    QCAlreadyExist,
    QCBlockExist,
    NeedFetch,
}

impl BlockStore {
    /// Checks if quorum certificate can be inserted in block store without RPC
    /// Returns the enum to indicate the detailed status.
    pub fn need_fetch_for_quorum_cert(
        &self, qc: &QuorumCert,
    ) -> NeedFetchResult {
        if qc.certified_block().round() < self.root().round() {
            return NeedFetchResult::QCRoundBeforeRoot;
        }
        if self
            .get_quorum_cert_for_block(qc.certified_block().id())
            .is_some()
        {
            return NeedFetchResult::QCAlreadyExist;
        }
        if self.block_exists(qc.certified_block().id()) {
            return NeedFetchResult::QCBlockExist;
        }
        NeedFetchResult::NeedFetch
    }

    pub async fn insert_quorum_cert(
        &self, qc: &QuorumCert, retriever: &mut BlockRetriever,
    ) -> anyhow::Result<()> {
        match self.need_fetch_for_quorum_cert(&qc) {
            NeedFetchResult::NeedFetch => {
                self.fetch_quorum_cert(qc.clone(), retriever).await?
            }
            NeedFetchResult::QCBlockExist => {
                self.insert_single_quorum_cert(qc.clone())?
            }
            _ => (),
        }
        if self.root().round() < qc.commit_info().round() {
            let finality_proof = qc.ledger_info();
            self.commit(finality_proof.clone()).await?;
            if qc.ends_epoch() {
                retriever
                    .network
                    .broadcast(
                        ConsensusMsg::EpochChangeProof(Box::new(
                            EpochChangeProof::new(
                                vec![finality_proof.clone()],
                                /* more = */ false,
                            ),
                        )),
                        vec![],
                    )
                    .await;
            }
            // Wait for PoW to process fetched PoS references.
            // We wait after commit `qc`, so PoW can process its pivot decision
            // correctly.
            // This is not needed for correctness/liveness, but we still add the
            // waiting here to make the syncing more predictable and
            // avoid unnecessarily message processing.
            self.pow_handler
                .wait_for_initialization(
                    finality_proof
                        .ledger_info()
                        .pivot_decision()
                        .clone()
                        .unwrap()
                        .block_hash,
                )
                .await;
        }
        Ok(())
    }

    /// Insert the quorum certificate separately from the block, used to split
    /// the processing of updating the consensus state(with qc) and deciding
    /// whether to vote(with block) The missing ancestors are going to be
    /// retrieved from the given peer. If a given peer fails to provide the
    /// missing ancestors, the qc is not going to be added.
    async fn fetch_quorum_cert(
        &self, qc: QuorumCert, retriever: &mut BlockRetriever,
    ) -> anyhow::Result<()> {
        debug!("fetch_quorum_cert: qc={:?}", qc);
        let mut pending = vec![];
        let mut retrieve_qc = qc.clone();
        loop {
            // round 0 blocks is the genesis of every epoch.
            if self.block_exists(retrieve_qc.certified_block().id())
                || retrieve_qc.certified_block().round() <= self.root().round()
            {
                break;
            }
            // This will not underflow because of the check above.
            let round_gap =
                retrieve_qc.certified_block().round() - self.root().round();
            let mut blocks = retriever
                .retrieve_block_for_qc(
                    &retrieve_qc,
                    round_gap.min(BLOCK_FETCH_BATCH_MAX_SIZE),
                )
                .await?;
            // retriever ensures that the blocks are chained.
            retrieve_qc = blocks
                .last()
                .expect("checked by retriever")
                .quorum_cert()
                .clone();
            pending.append(&mut blocks);
        }

        if !pending.is_empty() {
            // Execute the blocks in catch_up mode.
            while let Some(block) = pending.pop() {
                // We may receive more blocks than needed in a batch, so check
                // again here.
                if self.block_exists(block.id())
                    || block.round() <= self.root().round()
                {
                    continue;
                }

                let block_qc = block.quorum_cert().clone();
                self.insert_single_quorum_cert(block_qc.clone())?;
                self.execute_and_insert_block(
                    block, true, /* catch_up_mode */
                    true, /* force_recompute */
                )?;
                if block_qc.commit_info().round() > self.root().round() {
                    match self.commit(block_qc.ledger_info().clone()).await {
                        Ok(()) => {}
                        Err(e) => {
                            // TODO(lpl): Blocks not committed before crash
                            // should be committed
                            // here? Make sure
                            // they are recovered to
                            // BlockStore during start.
                            diem_warn!(
                                "fetch_quorum_cert: commit error={:?}",
                                e
                            );
                        }
                    }
                } else {
                    diem_debug!(
                        "skip commit, qc_round={} root_root={}",
                        block_qc.commit_info().round(),
                        self.root().round()
                    );
                }
            }
        }

        self.insert_single_quorum_cert(qc)
    }

    pub async fn fast_forward_sync<'a>(
        highest_commit_cert: &'a QuorumCert, retriever: &'a mut BlockRetriever,
        storage: Arc<dyn PersistentLivenessStorage>,
        state_computer: Arc<dyn StateComputer>,
    ) -> anyhow::Result<RecoveryData> {
        diem_debug!(
            LogSchema::new(LogEvent::StateSync)
                .remote_peer(retriever.preferred_peer),
            "Start state sync with peer to block: {}",
            highest_commit_cert.commit_info(),
        );

        let blocks = retriever
            .retrieve_block_for_qc(&highest_commit_cert, 3)
            .await?;
        assert_eq!(
            blocks.last().expect("should have 3-chain").id(),
            highest_commit_cert.commit_info().id(),
        );
        let mut quorum_certs = vec![];
        quorum_certs.push(highest_commit_cert.clone());
        quorum_certs.extend(
            blocks
                .iter()
                .take(2)
                .map(|block| block.quorum_cert().clone()),
        );
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.id(), quorum_certs[i].certified_block().id());
        }

        // If a node restarts in the middle of state synchronization, it is
        // going to try to catch up to the stored quorum certs as the
        // new root.
        storage.save_tree(blocks.clone(), quorum_certs.clone())?;
        state_computer
            .sync_to(highest_commit_cert.ledger_info().clone())
            .await?;
        let recovery_data = storage.start().expect_recovery_data(
            "Failed to construct recovery data after fast forward sync",
        );

        Ok(recovery_data)
    }
}

/// BlockRetriever is used internally to retrieve blocks
pub struct BlockRetriever {
    network: ConsensusNetworkSender,
    preferred_peer: Author,
}

impl BlockRetriever {
    pub fn new(
        network: ConsensusNetworkSender, preferred_peer: Author,
    ) -> Self {
        Self {
            network,
            preferred_peer,
        }
    }

    /// Retrieve chain of n blocks for given QC
    ///
    /// Returns Result with Vec that has a size of `[1, num_blocks]`.
    /// This guarantee is based on BlockRetrievalResponse::verify that ensures
    /// that number of blocks in response is within the range.
    ///
    /// The first attempt of block retrieval will always be sent to
    /// preferred_peer to allow the leader to drive quorum certificate
    /// creation The other peers from the quorum certificate
    /// will be randomly tried next.  If all members of the quorum certificate
    /// are exhausted, an error is returned
    pub async fn retrieve_block_for_qc<'a>(
        &'a mut self, qc: &'a QuorumCert, num_blocks: u64,
    ) -> anyhow::Result<Vec<Block>> {
        let block_id = qc.certified_block().id();
        self.request_block(num_blocks, block_id).await
    }

    pub async fn retrieve_block_for_ledger_info(
        &mut self, ledger_info: &LedgerInfoWithSignatures,
    ) -> anyhow::Result<Block> {
        let block_id = ledger_info.ledger_info().consensus_block_id();
        let mut blocks = self.request_block(1, block_id).await?;
        if blocks.len() == 1 {
            Ok(blocks.remove(0))
        } else {
            bail!("retrieve_block_for_ledger_info returns incorrect block number: {}", blocks.len())
        }
    }

    async fn request_block(
        &mut self, num_blocks: u64, block_id: HashValue,
    ) -> anyhow::Result<Vec<Block>> {
        let mut peers: Vec<AccountAddress> = self
            .network
            .network_sender()
            .protocol_handler
            .pos_peer_mapping
            .read()
            .keys()
            .map(Clone::clone)
            .collect();
        let mut attempt = 0_u32;
        loop {
            if peers.is_empty() {
                bail!(
                    "Failed to fetch block {} in {} attempts: no more peers available",
                    block_id,
                    attempt
                );
            }
            let peer = self.pick_peer(attempt, &mut peers);
            attempt += 1;

            diem_debug!(
                LogSchema::new(LogEvent::RetrieveBlock).remote_peer(peer),
                block_id = block_id,
                "Fetching block, attempt {}",
                attempt
            );
            let response = self
                .network
                .request_block(
                    BlockRetrievalRequest::new(block_id, num_blocks),
                    peer,
                    retrieval_timeout(attempt),
                )
                .await;
            match response.and_then(|result| {
                if result.status() == BlockRetrievalStatus::Succeeded {
                    Ok(result.blocks().clone())
                } else {
                    Err(format_err!("{:?}", result.status()))
                }
            }) {
                result @ Ok(_) => return result,
                Err(e) => diem_warn!(
                    remote_peer = peer,
                    block_id = block_id,
                    error = ?e, "Failed to fetch block, trying another peer",
                ),
            }
        }
    }

    fn pick_peer(
        &self, attempt: u32, peers: &mut Vec<AccountAddress>,
    ) -> AccountAddress {
        assert!(!peers.is_empty(), "pick_peer on empty peer list");

        if attempt == 0 {
            // remove preferred_peer if its in list of peers
            // (strictly speaking it is not required to be there)
            for i in 0..peers.len() {
                if peers[i] == self.preferred_peer {
                    peers.remove(i);
                    break;
                }
            }
            return self.preferred_peer;
        }

        let peer_idx = thread_rng().gen_range(0, peers.len());
        peers.remove(peer_idx)
    }
}

// Max timeout is 16s=RETRIEVAL_INITIAL_TIMEOUT*(2^RETRIEVAL_MAX_EXP)
const RETRIEVAL_INITIAL_TIMEOUT: Duration = Duration::from_millis(1000);
const RETRIEVAL_MAX_EXP: u32 = 4;

/// Returns exponentially increasing timeout with
/// limit of RETRIEVAL_INITIAL_TIMEOUT*(2^RETRIEVAL_MAX_EXP)
#[allow(clippy::trivially_copy_pass_by_ref)]
fn retrieval_timeout(attempt: u32) -> Duration {
    assert!(attempt > 0, "retrieval_timeout attempt can't be 0");
    let exp = RETRIEVAL_MAX_EXP.min(attempt - 1); // [0..RETRIEVAL_MAX_EXP]
    RETRIEVAL_INITIAL_TIMEOUT * 2_u32.pow(exp)
}
