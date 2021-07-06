// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    block_storage::{
        tracing::{observe_block, BlockStage},
        BlockReader, BlockRetriever, BlockStore,
    },
    counters,
    error::VerifyError,
    liveness::{
        proposal_generator::ProposalGenerator,
        proposer_election::ProposerElection,
        round_state::{NewRoundEvent, NewRoundReason, RoundState},
    },
    logging::{LogEvent, LogSchema},
    metrics_safety_rules::MetricsSafetyRules,
    network::{IncomingBlockRetrievalRequest, NetworkSender},
    network_interface::ConsensusMsg,
    pending_votes::VoteReceptionResult,
    persistent_liveness_storage::{PersistentLivenessStorage, RecoveryData},
    state_replication::{StateComputer, TxnManager},
};
use crate::pos::protocol::message::block_retrieval_response::BlockRetrievalRpcResponse;
use anyhow::{bail, ensure, Context, Result};
use consensus_types::{
    block::{Block, VRF_SEED},
    block_retrieval::{BlockRetrievalResponse, BlockRetrievalStatus},
    common::{Author, Round},
    proposal_msg::ProposalMsg,
    quorum_cert::QuorumCert,
    sync_info::SyncInfo,
    timeout_certificate::TimeoutCertificate,
    vote::Vote,
    vote_msg::VoteMsg,
};
use diem_crypto::VRFPrivateKey;
use diem_infallible::checked;
use diem_logger::prelude::*;
use diem_types::{
    block_info::PivotBlockDecision,
    chain_id::ChainId,
    epoch_state::EpochState,
    transaction::{ElectionPayload, RawTransaction},
    validator_verifier::ValidatorVerifier,
};
use fail::fail_point;
#[cfg(test)]
use safety_rules::ConsensusState;
use safety_rules::TSafetyRules;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use termion::color::*;

#[derive(Serialize, Clone)]
pub enum UnverifiedEvent {
    ProposalMsg(Box<ProposalMsg>),
    VoteMsg(Box<VoteMsg>),
    SyncInfo(Box<SyncInfo>),
}

impl UnverifiedEvent {
    pub fn verify(
        self, validator: &ValidatorVerifier,
    ) -> Result<VerifiedEvent, VerifyError> {
        Ok(match self {
            UnverifiedEvent::ProposalMsg(p) => {
                p.verify(validator)?;
                VerifiedEvent::ProposalMsg(p)
            }
            UnverifiedEvent::VoteMsg(v) => {
                v.verify(validator)?;
                VerifiedEvent::VoteMsg(v)
            }
            UnverifiedEvent::SyncInfo(s) => {
                s.verify(validator)?;
                VerifiedEvent::SyncInfo(s)
            }
        })
    }

    pub fn epoch(&self) -> u64 {
        match self {
            UnverifiedEvent::ProposalMsg(p) => p.epoch(),
            UnverifiedEvent::VoteMsg(v) => v.epoch(),
            UnverifiedEvent::SyncInfo(s) => s.epoch(),
        }
    }
}

impl From<ConsensusMsg> for UnverifiedEvent {
    fn from(value: ConsensusMsg) -> Self {
        match value {
            ConsensusMsg::ProposalMsg(m) => UnverifiedEvent::ProposalMsg(m),
            ConsensusMsg::VoteMsg(m) => UnverifiedEvent::VoteMsg(m),
            ConsensusMsg::SyncInfo(m) => UnverifiedEvent::SyncInfo(m),
            _ => unreachable!("Unexpected conversion"),
        }
    }
}

pub enum VerifiedEvent {
    ProposalMsg(Box<ProposalMsg>),
    VoteMsg(Box<VoteMsg>),
    SyncInfo(Box<SyncInfo>),
}

#[cfg(test)]
#[path = "round_manager_test.rs"]
mod round_manager_test;

#[cfg(feature = "fuzzing")]
#[path = "round_manager_fuzzing.rs"]
pub mod round_manager_fuzzing;

/// If the node can't recover corresponding blocks from local storage,
/// RecoveryManager is responsible for processing the events carrying sync info
/// and use the info to retrieve blocks from peers
pub struct RecoveryManager {
    epoch_state: EpochState,
    network: NetworkSender,
    storage: Arc<dyn PersistentLivenessStorage>,
    state_computer: Arc<dyn StateComputer>,
    last_committed_round: Round,
}

impl RecoveryManager {
    pub fn new(
        epoch_state: EpochState, network: NetworkSender,
        storage: Arc<dyn PersistentLivenessStorage>,
        state_computer: Arc<dyn StateComputer>, last_committed_round: Round,
    ) -> Self
    {
        RecoveryManager {
            epoch_state,
            network,
            storage,
            state_computer,
            last_committed_round,
        }
    }

    pub async fn process_proposal_msg(
        &mut self, proposal_msg: ProposalMsg,
    ) -> Result<RecoveryData> {
        let author = proposal_msg.proposer();
        let sync_info = proposal_msg.sync_info();
        self.sync_up(&sync_info, author).await
    }

    pub async fn process_vote_msg(
        &mut self, vote_msg: VoteMsg,
    ) -> Result<RecoveryData> {
        let author = vote_msg.vote().author();
        let sync_info = vote_msg.sync_info();
        self.sync_up(&sync_info, author).await
    }

    pub async fn sync_up(
        &mut self, sync_info: &SyncInfo, peer: Author,
    ) -> Result<RecoveryData> {
        sync_info
            .verify(&self.epoch_state.verifier)
            .map_err(VerifyError::from)?;
        ensure!(
            sync_info.highest_round() > self.last_committed_round,
            "[RecoveryManager] Received sync info has lower round number than committed block"
        );
        ensure!(
            sync_info.epoch() == self.epoch_state.epoch,
            "[RecoveryManager] Received sync info is in different epoch than committed block"
        );
        let mut retriever = BlockRetriever::new(self.network.clone(), peer);
        let recovery_data = BlockStore::fast_forward_sync(
            &sync_info.highest_commit_cert(),
            &mut retriever,
            self.storage.clone(),
            self.state_computer.clone(),
        )
        .await?;

        Ok(recovery_data)
    }

    pub fn epoch_state(&self) -> &EpochState { &self.epoch_state }
}

/// Consensus SMR is working in an event based fashion: RoundManager is
/// responsible for processing the individual events (e.g., process_new_round,
/// process_proposal, process_vote, etc.). It is exposing the async processing
/// functions for each event type. The caller is responsible for running the
/// event loops and driving the execution via some executors.
pub struct RoundManager {
    epoch_state: EpochState,
    block_store: Arc<BlockStore>,
    round_state: RoundState,
    proposer_election: Box<dyn ProposerElection + Send + Sync>,
    // None if this is not a validator.
    proposal_generator: Option<ProposalGenerator>,
    safety_rules: MetricsSafetyRules,
    network: NetworkSender,
    txn_manager: Arc<dyn TxnManager>,
    storage: Arc<dyn PersistentLivenessStorage>,
    sync_only: bool,
}

impl RoundManager {
    pub fn new(
        epoch_state: EpochState, block_store: Arc<BlockStore>,
        round_state: RoundState,
        proposer_election: Box<dyn ProposerElection + Send + Sync>,
        proposal_generator: Option<ProposalGenerator>,
        safety_rules: MetricsSafetyRules, network: NetworkSender,
        txn_manager: Arc<dyn TxnManager>,
        storage: Arc<dyn PersistentLivenessStorage>, sync_only: bool,
    ) -> Self
    {
        counters::OP_COUNTERS
            .gauge("sync_only")
            .set(sync_only as i64);
        Self {
            epoch_state,
            block_store,
            round_state,
            proposer_election,
            proposal_generator,
            safety_rules,
            txn_manager,
            network,
            storage,
            sync_only,
        }
    }

    fn create_block_retriever(&self, author: Author) -> BlockRetriever {
        BlockRetriever::new(self.network.clone(), author)
    }

    /// Leader:
    ///
    /// This event is triggered by a new quorum certificate at the previous
    /// round or a timeout certificate at the previous round.  In either
    /// case, if this replica is the new proposer for this round, it is
    /// ready to propose and guarantee that it can create a proposal
    /// that all honest replicas can vote for.  While this method should only be
    /// invoked at most once per round, we ensure that only at most one
    /// proposal can get generated per round to avoid accidental
    /// equivocation of proposals.
    ///
    /// Replica:
    ///
    /// Do nothing
    async fn process_new_round_event(
        &mut self, new_round_event: NewRoundEvent,
    ) -> anyhow::Result<()> {
        counters::CURRENT_ROUND.set(new_round_event.round as i64);
        counters::ROUND_TIMEOUT_MS
            .set(new_round_event.timeout.as_millis() as i64);
        match new_round_event.reason {
            NewRoundReason::QCReady => {
                counters::QC_ROUNDS_COUNT.inc();
            }
            NewRoundReason::Timeout => {
                counters::TIMEOUT_ROUNDS_COUNT.inc();
            }
        };
        diem_debug!(
            self.new_log(LogEvent::NewRound),
            reason = new_round_event.reason
        );
        if self.proposer_election.is_random_election() {
            self.proposer_election.next_round(new_round_event.round);
            self.round_state.setup_proposal_timeout();
        }
        if let Some(ref proposal_generator) = self.proposal_generator {
            if self.proposer_election.is_valid_proposer(
                proposal_generator.author(),
                new_round_event.round,
            ) {
                let proposal_msg = ConsensusMsg::ProposalMsg(Box::new(
                    self.generate_proposal(new_round_event).await?,
                ));
                let mut network = self.network.clone();
                network.broadcast(proposal_msg).await;
                counters::PROPOSALS_COUNT.inc();
            }
        }
        Ok(())
    }

    pub async fn broadcast_pivot_decision(&self) -> anyhow::Result<()> {
        if self.proposal_generator.is_none() {
            // Not an active validator, so do not need to sign pivot decision.
            return Ok(());
        }

        let hqc = self.block_store.highest_quorum_cert();
        let parent_block = hqc.certified_block();
        // TODO(lpl): Check if this may happen.
        if self.block_store.path_from_root(parent_block.id()).is_none() {
            bail!("HQC {} already pruned", parent_block);
        }

        // FIXME(lpl): For now, sending default H256 will return the first
        // pivot decision.
        let parent_decision = parent_block
            .pivot_decision()
            .map(|d| d.block_hash)
            .unwrap_or_default();
        let pivot_decision = loop {
            match self
                .block_store
                .pow_handler
                .next_pivot_decision(parent_decision)
                .await
            {
                Some(res) => break res,
                None => {
                    // No new pivot decision.
                    diem_debug!("No new pivot decision");
                    return Ok(());
                }
            }
        };

        let proposal_generator =
            self.proposal_generator.as_ref().expect("checked");
        diem_info!("Broadcast new pivot decision: {:?}", pivot_decision);
        // It's allowed for a node to sign conflict pivot decision,
        // so we do not need to persist this signing event.
        let raw_tx = RawTransaction::new_pivot_decision(
            proposal_generator.author(),
            0,
            PivotBlockDecision {
                block_hash: pivot_decision.1,
                height: pivot_decision.0,
            },
            ChainId::default(), // FIXME(lpl): Set chain id.
        );
        let signed_tx = raw_tx
            .sign(
                &proposal_generator.private_key,
                proposal_generator.public_key.clone(),
            )?
            .into_inner();
        // FIXME(lpl): Broadcast this tx using transaction pool.
        // self.network.broadcast(ConsensusMsg::PivotDecisionMsg())
        Ok(())
    }

    pub async fn broadcast_election(&self) -> anyhow::Result<()> {
        if self.proposal_generator.is_none() {
            // Not an active validator, so do not need to send election tx.
            return Ok(());
        }
        let proposal_generator =
            self.proposal_generator.as_ref().expect("checked");
        let committed_block = self.block_store.root().id();
        // TODO: Use cached pos state;
        let pos_state =
            self.storage.diem_db().get_pos_state(&committed_block)?;
        if let Some(target_term) =
            pos_state.next_elect_term(&proposal_generator.author())
        {
            let election_payload = ElectionPayload {
                public_key: proposal_generator.public_key.clone(),
                vrf_public_key: proposal_generator.vrf_public_key.clone(),
                target_term,
                vrf_proof: proposal_generator
                    .vrf_private_key
                    .compute(&VRF_SEED)
                    .unwrap(),
            };
            let raw_tx = RawTransaction::new_election(
                proposal_generator.author(),
                0,
                election_payload,
                ChainId::default(), // FIXME(lpl): Set chain id.
            );
            let signed_tx = raw_tx
                .sign(
                    &proposal_generator.private_key,
                    proposal_generator.public_key.clone(),
                )?
                .into_inner();
            // FIXME(lpl): Broadcast this tx using transaction pool.
            // self.network.broadcast(ConsensusMsg::PivotDecisionMsg())
        }
        Ok(())
    }

    async fn generate_proposal(
        &mut self, new_round_event: NewRoundEvent,
    ) -> anyhow::Result<ProposalMsg> {
        // Proposal generator will ensure that at most one proposal is generated
        // per round
        let proposal = self
            .proposal_generator
            .as_mut()
            .expect("checked by process_new_round_event")
            .generate_proposal(new_round_event.round)
            .await?;
        let signed_proposal = self.safety_rules.sign_proposal(proposal)?;
        observe_block(signed_proposal.timestamp_usecs(), BlockStage::SIGNED);
        diem_debug!(self.new_log(LogEvent::Propose), "{}", signed_proposal);
        // return proposal
        Ok(ProposalMsg::new(
            signed_proposal,
            self.block_store.sync_info(),
        ))
    }

    /// Process the proposal message:
    /// 1. ensure after processing sync info, we're at the same round as the
    /// proposal 2. execute and decide whether to vode for the proposal
    pub async fn process_proposal_msg(
        &mut self, proposal_msg: ProposalMsg,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process_proposal_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_proposal_msg"))
        });

        observe_block(
            proposal_msg.proposal().timestamp_usecs(),
            BlockStage::RECEIVED,
        );
        if self
            .ensure_round_and_sync_up(
                proposal_msg.proposal().round(),
                proposal_msg.sync_info(),
                proposal_msg.proposer(),
                true,
            )
            .await
            .context("[RoundManager] Process proposal")?
        {
            self.process_proposal(proposal_msg.clone().take_proposal())
                .await?;
            // If a proposal has been received and voted, it will return error.
            //
            // 1. For old leader elections where there is only one leader and we
            // vote after receiving the first proposal, the error is
            // returned in `execute_and_vote` because `vote_sent.
            // is_none()` is false. 2. For VRF leader election, we
            // return error when we insert a proposal from the same
            // author to proposal_candidates.
            //
            // This ensures that there is no broadcast storm
            // because we only broadcast a proposal when we receive it for the
            // first time.
            // TODO(lpl): Do not send to the sender and the original author.
            self.network
                .broadcast(ConsensusMsg::ProposalMsg(Box::new(proposal_msg)));
            Ok(())
        } else {
            bail!(
                "Stale proposal {}, current round {}",
                proposal_msg.proposal(),
                self.round_state.current_round()
            );
        }
    }

    /// Sync to the sync info sending from peer if it has newer certificates, if
    /// we have newer certificates and help_remote is set, send it back the
    /// local sync info.
    async fn sync_up(
        &mut self, sync_info: &SyncInfo, author: Author, help_remote: bool,
    ) -> anyhow::Result<()> {
        let local_sync_info = self.block_store.sync_info();
        if help_remote && local_sync_info.has_newer_certificates(&sync_info) {
            counters::SYNC_INFO_MSGS_SENT_COUNT.inc();
            diem_debug!(
                self.new_log(LogEvent::HelpPeerSync).remote_peer(author),
                "Remote peer has stale state {}, send it back {}",
                sync_info,
                local_sync_info,
            );
            self.network.send_sync_info(local_sync_info.clone(), author);
        }
        if sync_info.has_newer_certificates(&local_sync_info) {
            diem_debug!(
                self.new_log(LogEvent::SyncToPeer).remote_peer(author),
                "Local state {} is stale than remote state {}",
                local_sync_info,
                sync_info
            );
            // Some information in SyncInfo is ahead of what we have locally.
            // First verify the SyncInfo (didn't verify it in the yet).
            sync_info
                .verify(&self.epoch_state().verifier)
                .map_err(|e| {
                    diem_error!(
                        SecurityEvent::InvalidSyncInfoMsg,
                        sync_info = sync_info,
                        remote_peer = author,
                        error = ?e,
                    );
                    VerifyError::from(e)
                })?;
            /*
            let result = self
                .block_store
                .add_certs(&sync_info, self.create_block_retriever(author))
                .await;
             */
            // TODO(lpl): Ensure this does not cause OOM.
            let mut retriever = self.create_block_retriever(author);
            self.block_store
                .insert_quorum_cert(
                    &sync_info.highest_commit_cert(),
                    &mut retriever,
                )
                .await?;
            self.block_store
                .insert_quorum_cert(
                    &sync_info.highest_quorum_cert(),
                    &mut retriever,
                )
                .await?;
            if let Some(tc) = sync_info.highest_timeout_certificate() {
                self.block_store
                    .insert_timeout_certificate(Arc::new(tc.clone()))?;
            }
            self.process_certificates().await
        } else {
            Ok(())
        }
    }

    /// The function makes sure that it ensures the message_round equal to what
    /// we have locally, brings the missing dependencies from the QC and
    /// LedgerInfo of the given sync info and update the round_state with
    /// the certificates if succeed. Returns Ok(true) if the sync succeeds
    /// and the round matches so we can process further. Returns Ok(false)
    /// if the message is stale. Returns Error in case sync mgr failed to
    /// bring the missing dependencies. We'll try to help the remote if the
    /// SyncInfo lags behind and the flag is set.
    pub async fn ensure_round_and_sync_up(
        &mut self, message_round: Round, sync_info: &SyncInfo, author: Author,
        help_remote: bool,
    ) -> anyhow::Result<bool>
    {
        if message_round < self.round_state.current_round() {
            return Ok(false);
        }
        self.sync_up(sync_info, author, help_remote).await?;
        ensure!(
            message_round == self.round_state.current_round(),
            "After sync, round {} doesn't match local {}",
            message_round,
            self.round_state.current_round()
        );
        Ok(true)
    }

    /// Process the SyncInfo sent by peers to catch up to latest state.
    pub async fn process_sync_info_msg(
        &mut self, sync_info: SyncInfo, peer: Author,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process_sync_info_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_sync_info_msg"))
        });
        diem_debug!(
            self.new_log(LogEvent::ReceiveSyncInfo).remote_peer(peer),
            "{}",
            sync_info
        );
        // To avoid a ping-pong cycle between two peers that move forward
        // together.
        self.ensure_round_and_sync_up(
            checked!((sync_info.highest_round()) + 1)?,
            &sync_info,
            peer,
            false,
        )
        .await
        .context("[RoundManager] Failed to process sync info msg")?;
        Ok(())
    }

    /// The replica broadcasts a "timeout vote message", which includes the
    /// round signature, which can be aggregated to a TimeoutCertificate.
    /// The timeout vote message can be one of the following three options:
    /// 1) In case a validator has previously voted in this round, it repeats
    /// the same vote and sign a timeout.
    /// 2) Otherwise vote for a NIL block and sign a timeout.
    /// Note this function returns Err even if messages are broadcasted
    /// successfully because timeout is considered as error. It only returns
    /// Ok(()) when the timeout is stale.
    pub async fn process_local_timeout(
        &mut self, round: Round,
    ) -> anyhow::Result<()> {
        if !self.round_state.process_local_timeout(round) {
            return Ok(());
        }

        if self.sync_only {
            self.network
                .broadcast(ConsensusMsg::SyncInfo(Box::new(
                    self.block_store.sync_info(),
                )))
                .await;
            bail!(
                "[RoundManager] sync_only flag is set, broadcasting SyncInfo"
            );
        }

        if !self.is_validator() {
            return Ok(());
        }

        let (use_last_vote, mut timeout_vote) =
            match self.round_state.vote_sent() {
                Some(vote) if vote.vote_data().proposed().round() == round => {
                    (true, vote)
                }
                _ => {
                    // Didn't vote in this round yet, generate a backup vote
                    let nil_block = self
                        .proposal_generator
                        .as_ref()
                        .expect("checked in is_validator")
                        .generate_nil_block(round)?;
                    diem_debug!(
                        self.new_log(LogEvent::VoteNIL),
                        "Planning to vote for a NIL block {}",
                        nil_block
                    );
                    counters::VOTE_NIL_COUNT.inc();
                    let nil_vote = self.execute_and_vote(nil_block).await?;
                    (false, nil_vote)
                }
            };

        if !timeout_vote.is_timeout() {
            let timeout = timeout_vote.timeout();
            let signature = self
                .safety_rules
                .sign_timeout(&timeout)
                .context("[RoundManager] SafetyRules signs timeout")?;
            timeout_vote.add_timeout_signature(signature);
        }

        self.round_state.record_vote(timeout_vote.clone());
        let timeout_vote_msg = ConsensusMsg::VoteMsg(Box::new(VoteMsg::new(
            timeout_vote,
            self.block_store.sync_info(),
        )));
        self.network.broadcast(timeout_vote_msg).await;
        diem_error!(
            round = round,
            voted = use_last_vote,
            event = LogEvent::Timeout,
        );
        bail!("Round {} timeout, broadcast to all peers", round);
    }

    pub async fn process_proposal_timeout(
        &mut self, round: Round,
    ) -> anyhow::Result<()> {
        if let Some(proposal) = self.proposer_election.choose_proposal_to_vote()
        {
            if self.is_validator() {
                // Vote for proposal
                let vote = self
                    .execute_and_vote(proposal)
                    .await
                    .context("[RoundManager] Process proposal")?;
                diem_debug!(self.new_log(LogEvent::Vote), "{}", vote);

                self.round_state.record_vote(vote.clone());
                let vote_msg = VoteMsg::new(vote, self.block_store.sync_info());
                self.network
                    .broadcast(ConsensusMsg::VoteMsg(Box::new(vote_msg)))
                    .await;
                Ok(())
            } else {
                // Not a validator, just execute the block and wait for votes.
                self.block_store
                    .execute_and_insert_block(proposal, false)
                    .context(
                        "[RoundManager] Failed to execute_and_insert the block",
                    )?;
                Ok(())
            }
        } else {
            // No proposal to vote. Send Timeout earlier.
            self.process_local_timeout(round).await
        }
    }

    /// This function is called only after all the dependencies of the given QC
    /// have been retrieved.
    async fn process_certificates(&mut self) -> anyhow::Result<()> {
        let sync_info = self.block_store.sync_info();
        if let Some(new_round_event) =
            self.round_state.process_certificates(sync_info)
        {
            self.process_new_round_event(new_round_event).await?;
        }
        Ok(())
    }

    /// This function processes a proposal for the current round:
    /// 1. Filter if it's proposed by valid proposer.
    /// 2. Execute and add it to a block store.
    /// 3. Try to vote for it following the safety rules.
    /// 4. In case a validator chooses to vote, send the vote to the
    /// representatives at the next round.
    async fn process_proposal(&mut self, proposal: Block) -> Result<()> {
        let author = proposal
            .author()
            .expect("Proposal should be verified having an author");

        diem_info!(
            self.new_log(LogEvent::ReceiveProposal).remote_peer(author),
            block_hash = proposal.id(),
            block_parent_hash = proposal.quorum_cert().certified_block().id(),
        );

        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round",
            author,
            proposal,
        );

        let block_time_since_epoch =
            Duration::from_micros(proposal.timestamp_usecs());

        ensure!(
            block_time_since_epoch < self.round_state.current_round_deadline(),
            "[RoundManager] Waiting until proposal block timestamp usecs {:?} \
            would exceed the round duration {:?}, hence will not vote for this round",
            block_time_since_epoch,
            self.round_state.current_round_deadline(),
        );

        observe_block(proposal.timestamp_usecs(), BlockStage::SYNCED);

        if self.proposer_election.is_random_election() {
            self.block_store
                .execute_and_insert_block(proposal.clone(), false)?;
            // Keep the proposal, and choose to vote after proposal timeout.
            ensure!(
                self.proposer_election.receive_proposal_candidate(proposal),
                "Receive invalid or duplicate proposal from {}",
                author,
            );
        } else {
            let proposal_round = proposal.round();
            let vote = self
                .execute_and_vote(proposal)
                .await
                .context("[RoundManager] Process proposal")?;
            diem_debug!(
                self.new_log(LogEvent::Vote).remote_peer(author),
                "{}",
                vote
            );

            self.round_state.record_vote(vote.clone());
            let vote_msg = VoteMsg::new(vote, self.block_store.sync_info());
            let recipients = self
                .proposer_election
                .get_valid_proposer(proposal_round + 1);
            self.network.send_vote(vote_msg, vec![recipients]).await;
        }
        Ok(())
    }

    /// The function generates a VoteMsg for a given proposed_block:
    /// * first execute the block and add it to the block store
    /// * then verify the voting rules
    /// * save the updated state to consensus DB
    /// * return a VoteMsg with the LedgerInfo to be committed in case the vote
    ///   gathers QC.
    async fn execute_and_vote(
        &mut self, proposed_block: Block,
    ) -> anyhow::Result<Vote> {
        let executed_block = self
            .block_store
            .execute_and_insert_block(proposed_block, false)
            .context("[RoundManager] Failed to execute_and_insert the block")?;
        // notify mempool about failed txn
        let compute_result = executed_block.compute_result();
        if let Err(e) = self
            .txn_manager
            .notify(executed_block.block(), compute_result)
            .await
        {
            diem_error!(
                error = ?e, "[RoundManager] Failed to notify mempool of rejected txns",
            );
        }

        // Short circuit if already voted.
        ensure!(
            self.round_state.vote_sent().is_none(),
            "[RoundManager] Already vote on this round {}",
            self.round_state.current_round()
        );

        ensure!(
            !self.sync_only,
            "[RoundManager] sync_only flag is set, stop voting"
        );

        let maybe_signed_vote_proposal =
            executed_block.maybe_signed_vote_proposal();
        let vote = self
            .safety_rules
            .construct_and_sign_vote(&maybe_signed_vote_proposal)
            .context(format!(
                "[RoundManager] SafetyRules {}Rejected{} {}",
                Fg(Red),
                Fg(Reset),
                executed_block.block()
            ))?;
        observe_block(
            executed_block.block().timestamp_usecs(),
            BlockStage::VOTED,
        );

        self.storage
            .save_vote(&vote)
            .context("[RoundManager] Fail to persist last vote")?;

        Ok(vote)
    }

    /// Upon new vote:
    /// 1. Ensures we're processing the vote from the same round as local round
    /// 2. Filter out votes for rounds that should not be processed by this
    /// validator (to avoid potential attacks).
    /// 2. Add the vote to the pending votes and check whether it finishes a QC.
    /// 3. Once the QC/TC successfully formed, notify the RoundState.
    pub async fn process_vote_msg(
        &mut self, vote_msg: VoteMsg,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process_vote_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_vote_msg"))
        });
        if self
            .ensure_round_and_sync_up(
                vote_msg.vote().vote_data().proposed().round(),
                vote_msg.sync_info(),
                vote_msg.vote().author(),
                true,
            )
            .await
            .context("[RoundManager] Stop processing vote")?
        {
            self.process_vote(vote_msg.vote())
                .await
                .context("[RoundManager] Add a new vote")?;
            self.network
                .broadcast(ConsensusMsg::VoteMsg(Box::new(vote_msg)));
        }
        Ok(())
    }

    /// Add a vote to the pending votes.
    /// If a new QC / TC is formed then
    /// 1) fetch missing dependencies if required, and then
    /// 2) call process_certificates(), which will start a new round in return.
    async fn process_vote(&mut self, vote: &Vote) -> anyhow::Result<()> {
        let round = vote.vote_data().proposed().round();

        diem_info!(
            self.new_log(LogEvent::ReceiveVote)
                .remote_peer(vote.author()),
            vote = %vote,
            vote_epoch = vote.vote_data().proposed().epoch(),
            vote_round = vote.vote_data().proposed().round(),
            vote_id = vote.vote_data().proposed().id(),
            vote_state = vote.vote_data().proposed().executed_state_id(),
        );

        if !vote.is_timeout() {
            if let Some(ref proposal_generator) = self.proposal_generator {
                if !self.proposer_election.is_random_election() {
                    // Unlike timeout votes regular votes are sent to the
                    // leaders of the next round only.
                    let next_round = round + 1;
                    ensure!(
                self.proposer_election
                    .is_valid_proposer(proposal_generator.author(), next_round),
                "[RoundManager] Received {}, but I am not a valid proposer for round {}, ignore.",
                vote,
                next_round
            );
                }
            }
        }
        let block_id = vote.vote_data().proposed().id();
        // Check if the block already had a QC
        if self
            .block_store
            .get_quorum_cert_for_block(block_id)
            .is_some()
        {
            return Ok(());
        }
        // Add the vote and check whether it completes a new QC or a TC
        match self
            .round_state
            .insert_vote(vote, &self.epoch_state.verifier)
        {
            VoteReceptionResult::NewQuorumCertificate(qc) => {
                self.new_qc_aggregated(qc, vote.author()).await
            }
            VoteReceptionResult::NewTimeoutCertificate(tc) => {
                self.new_tc_aggregated(tc).await
            }
            VoteReceptionResult::VoteAdded(_) => Ok(()),
            // Return error so that duplicate or invalid votes will not be
            // broadcast to others.
            r => bail!("vote not added with result {:?}", r),
        }
    }

    async fn new_qc_aggregated(
        &mut self, qc: Arc<QuorumCert>, preferred_peer: Author,
    ) -> anyhow::Result<()> {
        observe_block(
            qc.certified_block().timestamp_usecs(),
            BlockStage::QC_AGGREGATED,
        );
        let result = self
            .block_store
            .insert_quorum_cert(
                &qc,
                &mut self.create_block_retriever(preferred_peer),
            )
            .await
            .context("[RoundManager] Failed to process a newly aggregated QC");
        self.process_certificates().await?;
        result
    }

    async fn new_tc_aggregated(
        &mut self, tc: Arc<TimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let result = self
            .block_store
            .insert_timeout_certificate(tc.clone())
            .context("[RoundManager] Failed to process a newly aggregated TC");
        self.process_certificates().await?;
        result
    }

    /// Retrieve a n chained blocks from the block store starting from
    /// an initial parent id, returning with <n (as many as possible) if
    /// id or its ancestors can not be found.
    ///
    /// The current version of the function is not really async, but keeping it
    /// this way for future possible changes.
    pub async fn process_block_retrieval(
        &self, request: IncomingBlockRetrievalRequest,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process_block_retrieval", |_| {
            Err(anyhow::anyhow!("Injected error in process_block_retrieval"))
        });
        let mut blocks = vec![];
        let mut status = BlockRetrievalStatus::Succeeded;
        let mut id = request.req.block_id();
        while (blocks.len() as u64) < request.req.num_blocks() {
            if let Some(executed_block) = self.block_store.get_block(id) {
                id = executed_block.parent_id();
                blocks.push(executed_block.block().clone());
            } else {
                status = BlockRetrievalStatus::NotEnoughBlocks;
                break;
            }
        }

        if blocks.is_empty() {
            status = BlockRetrievalStatus::IdNotFound;
        }

        let response = BlockRetrievalRpcResponse {
            request_id: request.request_id,
            response: BlockRetrievalResponse::new(status, blocks),
        };
        self.network
            .network_sender()
            .send_message_with_peer_id(&request.peer_id, &response);
        Ok(())
    }

    /// To jump start new round with the current certificates we have.
    pub async fn start(&mut self, last_vote_sent: Option<Vote>) {
        let new_round_event = self
            .round_state
            .process_certificates(self.block_store.sync_info())
            .expect(
                "Can not jump start a round_state from existing certificates.",
            );
        if let Some(vote) = last_vote_sent {
            self.round_state.record_vote(vote);
        }
        if let Err(e) = self.process_new_round_event(new_round_event).await {
            diem_error!(error = ?e, "[RoundManager] Error during start");
        }
    }

    /// Inspect the current consensus state.
    #[cfg(test)]
    pub fn consensus_state(&mut self) -> ConsensusState {
        self.safety_rules.consensus_state().unwrap()
    }

    #[cfg(test)]
    pub fn set_safety_rules(&mut self, safety_rules: MetricsSafetyRules) {
        self.safety_rules = safety_rules
    }

    pub fn epoch_state(&self) -> &EpochState { &self.epoch_state }

    pub fn round_state(&self) -> &RoundState { &self.round_state }

    fn new_log(&self, event: LogEvent) -> LogSchema {
        LogSchema::new(event)
            .round(self.round_state.current_round())
            .epoch(self.epoch_state.epoch)
    }

    fn is_validator(&self) -> bool {
        let r = self.proposal_generator.is_some();
        diem_debug!("Check validator: r={}", r);
        r
    }
}
