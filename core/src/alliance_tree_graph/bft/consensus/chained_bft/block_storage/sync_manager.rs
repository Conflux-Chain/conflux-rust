// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::super::super::{
    chained_bft::block_storage::{BlockReader, BlockStore},
    consensus_types::{
        block::Block,
        block_retrieval::{BlockRetrievalRequest, BlockRetrievalStatus},
        common::{Author, Payload},
        quorum_cert::QuorumCert,
        sync_info::SyncInfo,
    },
    counters,
};
use crate::alliance_tree_graph::hsb_sync_protocol::message::block_retrieval::BlockRetrievalRpcRequest;
use anyhow::{bail, format_err};
//use libra_logger::prelude::*;
use libra_types::account_address::AccountAddress;
//use libra_types::validator_change::ValidatorChangeProof;
use crate::{
    alliance_tree_graph::{
        bft::consensus::chained_bft::network::NetworkSender,
        consensus::error::ConsensusError,
        hsb_sync_protocol::{
            message::block_retrieval_response::BlockRetrievalRpcResponse,
            request_manager::Request, sync_protocol::RpcResponse,
            HSB_PROTOCOL_ID,
        },
    },
    sync::Error,
};
use cfx_types::H256;
use futures::channel::oneshot;
use io::IoContext;
use libra_crypto::HashValue;
use libra_types::validator_change::ValidatorChangeProof;
use mirai_annotations::checked_precondition;
use network::{service::NetworkContext, PeerId};
use rand::{prelude::*, Rng};
use std::{
    clone::Clone,
    sync::Arc,
    time::{Duration, Instant},
};
use termion::color::*;

#[derive(Debug, PartialEq)]
/// Whether we need to do block retrieval if we want to insert a Quorum Cert.
pub enum NeedFetchResult {
    QCRoundBeforeRoot,
    QCAlreadyExist,
    QCBlockExist,
    NeedFetch,
}

impl<T: Payload> BlockStore<T> {
    /// Check if we're far away from this ledger info and need to sync.
    /// Returns false if we have this block in the tree or the root's round is
    /// higher than the block.
    pub fn need_sync_for_quorum_cert(&self, qc: &QuorumCert) -> bool {
        // This precondition ensures that the check in the following lines
        // does not result in an addition overflow.
        checked_precondition!(self.root().round() < std::u64::MAX - 1);

        // If we have the block locally, we're not far from this QC thus don't
        // need to sync. In case root().round() is greater than that the
        // committed block carried by LI is older than my current
        // commit.
        !(self.block_exists(qc.commit_info().id())
            || self.root().round() >= qc.commit_info().round())
    }

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

    /// Fetches dependencies for given sync_info.quorum_cert
    /// If gap is large, performs state sync using process_highest_commit_cert
    /// Inserts sync_info.quorum_cert into block store as the last step
    pub async fn sync_to(
        &self, sync_info: &SyncInfo, retriever: BlockRetriever<T>,
    ) -> anyhow::Result<()> {
        /*
        self.process_highest_commit_cert(
            sync_info.highest_commit_cert().clone(),
            &mut retriever,
        )
        .await?;
        */

        match self.need_fetch_for_quorum_cert(sync_info.highest_quorum_cert()) {
            NeedFetchResult::NeedFetch => {
                self.fetch_quorum_cert(
                    sync_info.highest_quorum_cert().clone(),
                    retriever,
                )
                .await?
            }
            NeedFetchResult::QCBlockExist => self.insert_single_quorum_cert(
                sync_info.highest_quorum_cert().clone(),
            )?,
            _ => (),
        }
        Ok(())
    }

    /// Insert the quorum certificate separately from the block, used to split
    /// the processing of updating the consensus state(with qc) and deciding
    /// whether to vote(with block) The missing ancestors are going to be
    /// retrieved from the given peer. If a given peer fails to provide the
    /// missing ancestors, the qc is not going to be added.
    async fn fetch_quorum_cert(
        &self, qc: QuorumCert, mut retriever: BlockRetriever<T>,
    ) -> anyhow::Result<()> {
        let mut pending = vec![];
        let mut retrieve_qc = qc.clone();
        // FIXME: how to handle the case where epoch is different?
        assert_eq!(self.root().epoch(), retrieve_qc.certified_block().epoch());
        let block_batch_size = 1024 as u64;

        loop {
            if self.block_exists(retrieve_qc.certified_block().id()) {
                break;
            }

            // To this point, it means we have to fetch
            // retrieve_qc.certified_block()
            let min_round = self.root().round();
            let max_round = retrieve_qc.certified_block().round();
            let round_gap = if max_round > min_round {
                max_round - min_round
            } else {
                0
            };

            let mut to_fetch_block_count =
                std::cmp::min(round_gap, block_batch_size);
            if to_fetch_block_count == 0 {
                to_fetch_block_count = 1;
            }

            let blocks = retriever
                .retrieve_block_for_qc(&retrieve_qc, to_fetch_block_count)
                .await?;

            let mut done = false;
            for block in blocks {
                if self.block_exists(block.id()) {
                    done = true;
                    break;
                }
                retrieve_qc = block.quorum_cert().clone();
                pending.push(block);
            }

            if done {
                break;
            }
        }

        // insert the qc <- block pair
        while let Some(block) = pending.pop() {
            let block_qc = block.quorum_cert().clone();
            self.insert_single_quorum_cert(block_qc)?;
            while let Err(e) = self.execute_and_insert_block(
                block.clone(),
                false, /* verify_admin_transaction */
            ) {
                match e.downcast_ref::<ConsensusError>() {
                    Some(ConsensusError::VerifyPivotTimeout) => {
                        debug!(
                            "fetch_quorum_cert: Execute block {} timed out",
                            block.id()
                        );
                        continue;
                    }
                    _ => bail!("execute_and_insert_block Error"),
                }
            }
        }
        self.insert_single_quorum_cert(qc)
    }

    /// Check the highest commit cert sent by peer to see if we're behind and
    /// start a fast forward sync if the committed block doesn't exist in
    /// our tree. It works as follows:
    /// 1. request the committed 3-chain from the peer, if C2 is the
    /// highest_commit_cert we request for B0 <- C0 <- B1 <- C1 <- B2 (<-
    /// C2) 2. We persist the 3-chain to storage before start sync to ensure
    /// we could restart if we crash in the middle of the sync.
    /// 3. We prune the old tree and replace with a new tree built with the
    /// 3-chain.
    #[allow(dead_code)]
    async fn process_highest_commit_cert(
        &self, highest_commit_cert: QuorumCert,
        retriever: &mut BlockRetriever<T>,
    ) -> anyhow::Result<()>
    {
        if !self.need_sync_for_quorum_cert(&highest_commit_cert) {
            return Ok(());
        }
        debug!(
            "Start state sync with peer: {}, to block: {} from {}",
            retriever.preferred_peer.short_str(),
            highest_commit_cert.commit_info(),
            self.root()
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
        quorum_certs.push(blocks[0].quorum_cert().clone());
        quorum_certs.push(blocks[1].quorum_cert().clone());
        // If a node restarts in the middle of state synchronization, it is
        // going to try to catch up to the stored quorum certs as the
        // new root.
        self.storage
            .save_tree(blocks.clone(), quorum_certs.clone())?;
        let pre_sync_instance = Instant::now();
        /*
        self.state_computer
            .sync_to(highest_commit_cert.ledger_info().clone())
            .await?;
            */
        counters::STATE_SYNC_DURATION_S
            .observe_duration(pre_sync_instance.elapsed());
        let (
            root,
            root_executed_pivot,
            /* root_executed_trees, */ blocks,
            quorum_certs,
        ) = self.storage.start().take();
        debug!("{}Sync to{} {}", Fg(Blue), Fg(Reset), root.0);
        self.rebuild(
            root,
            root_executed_pivot,
            /* root_executed_trees, */ blocks,
            quorum_certs,
        )
        .await;

        if highest_commit_cert.ends_epoch() {
            let self_node_id = AccountAddress::new(
                retriever.network.protocol_handler.own_node_hash.into(),
            );
            retriever
                .network
                .protocol_handler
                .network_task
                .process_epoch_change(
                    self_node_id,
                    ValidatorChangeProof::new(
                        vec![highest_commit_cert.ledger_info().clone()],
                        /* more = */ false,
                    ),
                )
                .await?;
        }
        Ok(())
    }
}

/// BlockRetriever is used internally to retrieve blocks
pub struct BlockRetriever<P> {
    network: Arc<NetworkSender<P>>,
    deadline: Instant,
    preferred_peer: Author,
    peers: Vec<AccountAddress>,
}

impl<P: Payload> BlockRetriever<P> {
    pub fn new(
        network: Arc<NetworkSender<P>>, deadline: Instant,
        preferred_peer: Author, peers: Vec<AccountAddress>,
    ) -> Self
    {
        Self {
            network,
            deadline,
            preferred_peer,
            peers,
        }
    }

    pub fn issue_unary_rpc(
        &self, recipient: Option<PeerId>, mut request: Box<dyn Request>,
    ) -> oneshot::Receiver<Result<Box<dyn RpcResponse>, Error>> {
        let io = IoContext::new(
            self.network.network.io_service.as_ref().unwrap().channel(),
            0,
        );
        let io = match self.network.network.inner {
            Some(ref inner) => {
                Some(NetworkContext::new(&io, HSB_PROTOCOL_ID, &*inner))
            }
            None => None,
        };
        let io = io.unwrap();

        let (res_tx, res_rx) = oneshot::channel();
        request.set_response_notification(res_tx);

        self.network
            .protocol_handler
            .request_manager
            .request_with_delay(&io, request, recipient, None);
        res_rx
    }

    /// Retrieve chain of n blocks for given QC
    ///
    /// Returns Result with Vec that has a guaranteed size of num_blocks
    /// This guarantee is based on BlockRetrievalResponse::verify that ensures
    /// that number of blocks in response is equal to number of blocks
    /// requested.  This method will continue until either the round
    /// deadline is reached or the quorum certificate members all
    /// fail to return the missing chain.
    ///
    /// The first attempt of block retrieval will always be sent to
    /// preferred_peer to allow the leader to drive quorum certificate
    /// creation The other peers from the quorum certificate
    /// will be randomly tried next.  If all members of the quorum certificate
    /// are exhausted, an error is returned
    async fn retrieve_block_for_qc<'a, T>(
        &'a mut self, qc: &'a QuorumCert, num_blocks: u64,
    ) -> anyhow::Result<Vec<Block<T>>>
    where T: Payload {
        let block_id = qc.certified_block().id();
        let mut peers: Vec<&AccountAddress> = self.peers.iter().collect();
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

            let timeout = retrieval_timeout(&self.deadline, attempt);
            let timeout = timeout.ok_or_else(|| {
                format_err!("Failed to fetch block {} from {}, attempt {}: round deadline was reached, won't make more attempts", block_id, peer, attempt)
            })?;

            debug!(
                "Fetching {} from {}, attempt {}",
                block_id,
                peer.short_str(),
                attempt
            );

            let request = BlockRetrievalRpcRequest {
                request_id: 0,
                request: BlockRetrievalRequest::new(block_id, num_blocks),
                is_empty: false,
                response_tx: None,
                timeout,
            };

            let peer_hash = H256::from_slice(peer.to_vec().as_slice());
            let peer_state =
                self.network.protocol_handler.peers.get(&peer_hash);
            if peer_state.is_none() {
                continue;
            }

            let peer_state = peer_state.unwrap();
            let peer_id = peer_state.read().get_id();

            let response_rx =
                self.issue_unary_rpc(Some(peer_id), Box::new(request));
            let response = response_rx.await;

            let res = match response {
                Ok(res) => res,
                _ => {
                    continue;
                }
            };

            match res {
                Ok(response) => {
                    match response
                        .as_any()
                        .downcast_ref::<BlockRetrievalRpcResponse<T>>()
                    {
                        Some(r) => {
                            if r.response.status()
                                != BlockRetrievalStatus::Succeeded
                            {
                                warn!(
                                        "Failed to fetch block {} from {}: {:?}, trying another peer",
                                        block_id,
                                        peer.short_str(),
                                        r.response.status()
                                    );
                                continue;
                            }
                            return Ok(r.response.blocks().clone());
                        }
                        None => {
                            continue;
                        }
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }

    pub async fn retrieve_block<T>(
        &self, block_id: HashValue, num_blocks: u64,
    ) -> anyhow::Result<Vec<Block<T>>>
    where T: Payload {
        let mut peers: Vec<&AccountAddress> = self.peers.iter().collect();
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

            let timeout = retrieval_timeout(&self.deadline, attempt);
            let timeout = timeout.ok_or_else(|| {
                format_err!("Failed to fetch block {} from {}, attempt {}: round deadline was reached, won't make more attempts", block_id, peer, attempt)
            })?;

            debug!(
                "Fetching {} from {}, attempt {}",
                block_id,
                peer.short_str(),
                attempt
            );

            let request = BlockRetrievalRpcRequest {
                request_id: 0,
                request: BlockRetrievalRequest::new(block_id, num_blocks),
                is_empty: false,
                response_tx: None,
                timeout,
            };

            let peer_hash = H256::from_slice(peer.to_vec().as_slice());
            let peer_state =
                self.network.protocol_handler.peers.get(&peer_hash);
            if peer_state.is_none() {
                continue;
            }

            let peer_state = peer_state.unwrap();
            let peer_id = peer_state.read().get_id();

            let response_rx =
                self.issue_unary_rpc(Some(peer_id), Box::new(request));
            let response = response_rx.await;

            let res = match response {
                Ok(res) => res,
                _ => {
                    continue;
                }
            };

            match res {
                Ok(response) => {
                    match response
                        .as_any()
                        .downcast_ref::<BlockRetrievalRpcResponse<T>>()
                    {
                        Some(r) => {
                            if r.response.status()
                                != BlockRetrievalStatus::Succeeded
                            {
                                warn!(
                                    "Failed to fetch block {} from {}: {:?}, trying another peer",
                                    block_id,
                                    peer.short_str(),
                                    r.response.status()
                                );
                                continue;
                            }
                            if r.response.blocks().len() != num_blocks as usize
                            {
                                warn!("Failed to fetch {} blocks from {}: {:?}, trying another peer",
                                      num_blocks,
                                      peer.short_str(),
                                      r.response.status());
                                continue;
                            }
                            return Ok(r.response.blocks().clone());
                        }
                        None => {
                            continue;
                        }
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }

    fn pick_peer(
        &self, attempt: u32, peers: &mut Vec<&AccountAddress>,
    ) -> AccountAddress {
        assert!(!peers.is_empty(), "pick_peer on empty peer list");

        if attempt == 0 {
            // remove preferred_peer if its in list of peers
            // (strictly speaking it is not required to be there)
            for i in 0..peers.len() {
                if *peers[i] == self.preferred_peer {
                    peers.remove(i);
                    break;
                }
            }
            return self.preferred_peer;
        }

        let peer_idx = thread_rng().gen_range(0, peers.len());
        *peers.remove(peer_idx)
    }
}

// Max timeout is 16s=RETRIEVAL_INITIAL_TIMEOUT*(2^RETRIEVAL_MAX_EXP)
const RETRIEVAL_INITIAL_TIMEOUT: Duration = Duration::from_secs(1);
const RETRIEVAL_MAX_EXP: u32 = 4;

/// Returns exponentially increasing timeout with
/// limit of RETRIEVAL_INITIAL_TIMEOUT*(2^RETRIEVAL_MAX_EXP)
fn retrieval_timeout(_deadline: &Instant, attempt: u32) -> Option<Duration> {
    assert!(attempt > 0, "retrieval_timeout attempt can't be 0");
    let exp = RETRIEVAL_MAX_EXP.min(attempt - 1); // [0..RETRIEVAL_MAX_EXP]
    let request_timeout = RETRIEVAL_INITIAL_TIMEOUT * 2_u32.pow(exp);
    Some(request_timeout)
    /*
    let now = Instant::now();
    let deadline_timeout = if *deadline >= now {
        Some(deadline.duration_since(now))
    } else {
        None
    };
    deadline_timeout.map(|delay| request_timeout.min(delay))
    */
}
