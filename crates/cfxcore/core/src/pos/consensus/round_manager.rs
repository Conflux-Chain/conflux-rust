// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use fail::fail_point;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use serde::Serialize;

use consensus_types::{
    block::Block,
    block_retrieval::{BlockRetrievalResponse, BlockRetrievalStatus},
    common::{Author, Round},
    proposal_msg::ProposalMsg,
    quorum_cert::QuorumCert,
    sync_info::SyncInfo,
    timeout_certificate::TimeoutCertificate,
    vote::Vote,
    vote_msg::VoteMsg,
};
use diem_config::keys::ConfigKey;
use diem_crypto::{hash::CryptoHash, HashValue, SigningKey, VRFPrivateKey};
use diem_infallible::checked;
use diem_logger::prelude::*;
use diem_types::{
    account_address::{from_consensus_public_key, AccountAddress},
    block_info::PivotBlockDecision,
    chain_id::ChainId,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    transaction::{
        ConflictSignature, DisputePayload, ElectionPayload, RawTransaction,
        SignedTransaction, TransactionPayload,
    },
    validator_config::{ConsensusPrivateKey, ConsensusVRFPrivateKey},
    validator_verifier::ValidatorVerifier,
};
#[cfg(test)]
use safety_rules::ConsensusState;
use safety_rules::{SafetyRules, TSafetyRules};

use crate::pos::{
    mempool::SubmissionStatus,
    protocol::message::block_retrieval_response::BlockRetrievalRpcResponse,
};

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
    network::{
        ConsensusMsg, ConsensusNetworkSender, IncomingBlockRetrievalRequest,
    },
    pending_votes::VoteReceptionResult,
    persistent_liveness_storage::{PersistentLivenessStorage, RecoveryData},
    state_replication::{StateComputer, TxnManager},
};

#[derive(Serialize, Clone)]
pub enum UnverifiedEvent {
    ProposalMsg(Box<ProposalMsg>),
    VoteMsg(Box<VoteMsg>),
    SyncInfo(Box<SyncInfo>),
}

impl UnverifiedEvent {
    pub fn verify(
        self, validator: &ValidatorVerifier, epoch_vrf_seed: &[u8],
    ) -> Result<VerifiedEvent, VerifyError> {
        Ok(match self {
            UnverifiedEvent::ProposalMsg(p) => {
                p.verify(validator, epoch_vrf_seed)?;
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
    network: ConsensusNetworkSender,
    storage: Arc<dyn PersistentLivenessStorage>,
    state_computer: Arc<dyn StateComputer>,
    last_committed_round: Round,
}

impl RecoveryManager {
    pub fn new(
        epoch_state: EpochState, network: ConsensusNetworkSender,
        storage: Arc<dyn PersistentLivenessStorage>,
        state_computer: Arc<dyn StateComputer>, last_committed_round: Round,
    ) -> Self {
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
            .verify(&self.epoch_state.verifier())
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
    network: ConsensusNetworkSender,
    txn_manager: Arc<dyn TxnManager>,
    storage: Arc<dyn PersistentLivenessStorage>,
    sync_only: bool,
    tx_sender: mpsc::Sender<(
        SignedTransaction,
        oneshot::Sender<anyhow::Result<SubmissionStatus>>,
    )>,
    chain_id: ChainId,

    is_voting: bool,
    election_control: Arc<AtomicBool>,
    consensus_private_key: Option<ConfigKey<ConsensusPrivateKey>>,
    vrf_private_key: Option<ConfigKey<ConsensusVRFPrivateKey>>,
}

impl RoundManager {
    pub fn new(
        epoch_state: EpochState, block_store: Arc<BlockStore>,
        round_state: RoundState,
        proposer_election: Box<dyn ProposerElection + Send + Sync>,
        proposal_generator: Option<ProposalGenerator>,
        safety_rules: MetricsSafetyRules, network: ConsensusNetworkSender,
        txn_manager: Arc<dyn TxnManager>,
        storage: Arc<dyn PersistentLivenessStorage>, sync_only: bool,
        tx_sender: mpsc::Sender<(
            SignedTransaction,
            oneshot::Sender<anyhow::Result<SubmissionStatus>>,
        )>,
        chain_id: ChainId, is_voting: bool, election_control: Arc<AtomicBool>,
        consensus_private_key: Option<ConfigKey<ConsensusPrivateKey>>,
        vrf_private_key: Option<ConfigKey<ConsensusVRFPrivateKey>>,
    ) -> Self {
        counters::OP_COUNTERS
            .gauge("sync_only")
            .set(sync_only as i64);
        Self {
            epoch_state,
            block_store,
            round_state,
            proposer_election,
            proposal_generator,
            is_voting,
            safety_rules,
            txn_manager,
            network,
            storage,
            sync_only,
            tx_sender,
            chain_id,
            election_control,
            consensus_private_key,
            vrf_private_key,
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
            self.proposer_election.next_round(
                new_round_event.round,
                self.epoch_state.vrf_seed.clone(),
            );
            self.round_state
                .setup_proposal_timeout(self.epoch_state.epoch);
        }

        if let Err(e) = self.broadcast_pivot_decision().await {
            diem_error!("error in broadcasting pivot decision tx: {:?}", e);
        }
        // After the election transaction has been packed and executed,
        // `broadcast_election` will be a no-op.
        if let Err(e) = self.broadcast_election().await {
            diem_error!("error in broadcasting election tx: {:?}", e);
        }

        if self.is_validator() {
            if let Some(ref proposal_generator) = self.proposal_generator {
                let author = proposal_generator.author();

                if self
                    .proposer_election
                    .is_valid_proposer(author, new_round_event.round)
                {
                    let proposal_msg = ConsensusMsg::ProposalMsg(Box::new(
                        self.generate_proposal(new_round_event).await?,
                    ));
                    let mut network = self.network.clone();
                    network.broadcast(proposal_msg, vec![]).await;
                    counters::PROPOSALS_COUNT.inc();
                }
            }
        }
        Ok(())
    }

    pub async fn broadcast_pivot_decision(&mut self) -> anyhow::Result<()> {
        if !self.is_validator() {
            // Not an active validator, so do not need to sign pivot decision.
            return Ok(());
        }
        diem_debug!("broadcast_pivot_decision starts");

        let hqc = self.block_store.highest_quorum_cert();
        let parent_block = hqc.certified_block();
        // TODO(lpl): Check if this may happen.
        if self.block_store.path_from_root(parent_block.id()).is_none() {
            bail!("HQC {} already pruned", parent_block);
        }

        // Sending non-existent H256 (default) will return the latest pivot
        // decision.
        let parent_decision = parent_block
            .pivot_decision()
            .map(|d| d.block_hash)
            .unwrap_or_default();
        let pivot_decision = match self
            .block_store
            .pow_handler
            .next_pivot_decision(parent_decision)
            .await
        {
            Some(res) => res,
            None => {
                // No new pivot decision.
                diem_debug!("No new pivot decision");
                return Ok(());
            }
        };

        let proposal_generator =
            self.proposal_generator.as_ref().expect("checked");
        diem_info!("Broadcast new pivot decision: {:?}", pivot_decision);
        // It's allowed for a node to sign conflict pivot decision,
        // so we do not need to persist this signing event.
        let raw_tx = RawTransaction::new_pivot_decision(
            proposal_generator.author(),
            PivotBlockDecision {
                block_hash: pivot_decision.1,
                height: pivot_decision.0,
            },
            self.chain_id,
        );
        let signed_tx =
            raw_tx.sign(&proposal_generator.private_key)?.into_inner();
        let (tx, rx) = oneshot::channel();
        self.tx_sender.send((signed_tx, tx)).await?;
        // TODO(lpl): Check if we want to wait here.
        rx.await??;
        diem_debug!("broadcast_pivot_decision sends");
        Ok(())
    }

    pub async fn broadcast_election(&mut self) -> anyhow::Result<()> {
        if !self.election_control.load(AtomicOrdering::Relaxed) {
            diem_debug!("Skip election for election_control");
            return Ok(());
        }
        if !self.is_voting {
            // This node does not participate in any signing or voting.
            return Ok(());
        }
        if !self.block_store.pow_handler.is_normal_phase() {
            // Do not start election before PoW enters normal phase so we will
            // not be force retired unexpectedly because we are
            // elected but cannot vote.
            return Ok(());
        }
        if self.vrf_private_key.is_none()
            || self.consensus_private_key.is_none()
        {
            diem_warn!("broadcast_election without keys");
            return Ok(());
        }
        let private_key = self.consensus_private_key.as_ref().unwrap();
        let vrf_private_key = self.vrf_private_key.as_ref().unwrap();
        let author = from_consensus_public_key(
            &private_key.public_key(),
            &vrf_private_key.public_key(),
        );
        diem_debug!("broadcast_election starts");
        let pos_state = self.storage.pos_ledger_db().get_latest_pos_state();
        if let Some(target_term) = pos_state.next_elect_term(&author) {
            let epoch_vrf_seed = pos_state.target_term_seed(target_term);
            let election_payload = ElectionPayload {
                public_key: private_key.public_key(),
                vrf_public_key: vrf_private_key.public_key(),
                target_term,
                vrf_proof: vrf_private_key
                    .private_key()
                    .compute(epoch_vrf_seed.as_slice())
                    .unwrap(),
            };
            let raw_tx = RawTransaction::new_election(
                author,
                election_payload,
                self.chain_id,
            );
            let signed_tx =
                raw_tx.sign(&private_key.private_key())?.into_inner();
            let (tx, rx) = oneshot::channel();
            self.tx_sender.send((signed_tx, tx)).await?;
            // TODO(lpl): Check if we want to wait here.
            rx.await??;
            diem_debug!(
                "broadcast_election sends: target_term={}",
                target_term
            );
        } else {
            diem_debug!("Skip election for elected");
            if let Some(node_data) = pos_state.account_node_data(author) {
                if node_data.lock_status().force_retired().is_some() {
                    warn!("The node stops elections for force retire!");
                }
            }
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
            .generate_proposal(
                new_round_event.round,
                self.epoch_state.verifier().clone(),
            )
            .await?;
        let mut signed_proposal = self.safety_rules.sign_proposal(proposal)?;
        if self.proposer_election.is_random_election() {
            signed_proposal.set_vrf_nonce_and_proof(
                self.proposer_election
                    .gen_vrf_nonce_and_proof(signed_proposal.block_data())
                    .expect("threshold checked in is_valid_proposer"),
            )
        }
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
            if self
                .process_proposal(proposal_msg.clone().take_proposal())
                .await?
            {
                // If a proposal has been received and voted, it will return
                // error or false.
                //
                // 1. For old leader elections where there is only one leader
                // and we vote after receiving the first
                // proposal, the error is returned in
                // `execute_and_vote` because `vote_sent.
                // is_none()` is false. 2. For VRF leader election, we
                // return Ok(false) when we insert a proposal from the same
                // author to proposal_candidates.
                //
                // This ensures that there is no broadcast storm
                // because we only broadcast a proposal when we receive it for
                // the first time.
                // TODO(lpl): Do not send to the sender and the original author.
                let exclude =
                    vec![proposal_msg.proposer(), self.network.author];
                self.network
                    .broadcast(
                        ConsensusMsg::ProposalMsg(Box::new(proposal_msg)),
                        exclude,
                    )
                    .await;
            }
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
    pub async fn sync_up(
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
                .verify(&self.epoch_state().verifier())
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

    /// This can only be used in `EpochManager.start_new_epoch`.
    pub async fn sync_to_ledger_info(
        &mut self, ledger_info: &LedgerInfoWithSignatures,
        peer_id: AccountAddress,
    ) -> Result<()> {
        diem_debug!("sync_to_ledger_info: {:?}", ledger_info);
        let mut retriever = self.create_block_retriever(peer_id);
        if !self
            .block_store
            .block_exists(ledger_info.ledger_info().consensus_block_id())
        {
            let block_for_ledger_info = retriever
                .retrieve_block_for_ledger_info(ledger_info)
                .await?;
            self.block_store
                .insert_quorum_cert(
                    block_for_ledger_info.quorum_cert(),
                    &mut retriever,
                )
                .await?;
            // `insert_quorum_cert` will wait for PoW to initialize if needed,
            // so here we do not need to execute as catch_up_mode
            // again.
            self.block_store.execute_and_insert_block(
                block_for_ledger_info,
                true,
                false,
            )?;
        };
        self.block_store.commit(ledger_info.clone()).await?;
        Ok(())
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
    ) -> anyhow::Result<bool> {
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

    pub async fn process_new_round_timeout(
        &mut self, epoch_round: (u64, Round),
    ) -> anyhow::Result<()> {
        diem_debug!("process_new_round_timeout: round={:?}", epoch_round);
        if epoch_round
            != (self.epoch_state.epoch, self.round_state.current_round())
        {
            return Ok(());
        }
        let round = epoch_round.1;

        match self
            .round_state
            .get_round_certificate(&self.epoch_state.verifier())
        {
            VoteReceptionResult::NewQuorumCertificate(qc) => {
                self.new_qc_aggregated(
                    qc.clone(),
                    qc.ledger_info()
                        .signatures()
                        .keys()
                        .next()
                        .expect("qc formed")
                        .clone(),
                )
                .await?;
            }
            VoteReceptionResult::NewTimeoutCertificate(tc) => {
                self.new_tc_aggregated(tc).await?;
            }
            _ => {
                // No certificate formed. This should not happen.
                anyhow::bail!(
                    "New round timeout without new certificate! round={}",
                    round
                );
            }
        }
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
        &mut self, epoch_round: (u64, Round),
    ) -> anyhow::Result<()> {
        diem_debug!("process_local_timeout: round={:?}", epoch_round);
        if epoch_round
            != (self.epoch_state.epoch, self.round_state.current_round())
        {
            return Ok(());
        }
        let round = epoch_round.1;

        if !self.round_state.process_local_timeout(epoch_round) {
            return Ok(());
        }

        self.network
            .broadcast(
                ConsensusMsg::SyncInfo(Box::new(self.block_store.sync_info())),
                vec![],
            )
            .await;

        match self
            .round_state
            .get_round_certificate(&self.epoch_state.verifier())
        {
            VoteReceptionResult::NewQuorumCertificate(_)
            | VoteReceptionResult::NewTimeoutCertificate(_) => {
                // Certificate formed, so do not send timeout vote.
                return Ok(());
            }
            _ => {
                // No certificate formed, so enter normal timeout processing.
            }
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
        self.network.broadcast(timeout_vote_msg, vec![]).await;
        diem_error!(
            round = round,
            voted = use_last_vote,
            event = LogEvent::Timeout,
        );
        bail!("Round {} timeout, broadcast to all peers", round);
    }

    pub async fn process_proposal_timeout(
        &mut self, epoch_round: (u64, Round),
    ) -> anyhow::Result<()> {
        diem_debug!("process_proposal_timeout: round={:?}", epoch_round);
        if epoch_round
            != (self.epoch_state.epoch, self.round_state.current_round())
        {
            return Ok(());
        }
        let round = epoch_round.1;

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
                    .broadcast(
                        ConsensusMsg::VoteMsg(Box::new(vote_msg)),
                        vec![],
                    )
                    .await;
                Ok(())
            } else {
                // Not a validator, just execute the block and wait for votes.
                self.block_store
                    .execute_and_insert_block(proposal, false, false)
                    .context(
                        "[RoundManager] Failed to execute_and_insert the block",
                    )?;
                Ok(())
            }
        } else {
            debug!("No proposal to vote: round={}", round);
            // No proposal to vote. Send Timeout earlier.
            self.process_local_timeout(epoch_round).await
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
    ///
    /// Return `Ok(true)` if the block should be relayed.
    async fn process_proposal(&mut self, proposal: Block) -> Result<bool> {
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
            if self
                .proposer_election
                .receive_proposal_candidate(&proposal)?
            {
                self.block_store.execute_and_insert_block(
                    proposal.clone(),
                    false,
                    false,
                )?;
                self.proposer_election.set_proposal_candidate(proposal);
                Ok(true)
            } else {
                // This proposal will not be chosen to vote, so we do not need
                // to relay. A proposal received for several
                // times also enters this branch because
                // the vrf_output is the same.
                Ok(false)
            }
        } else {
            bail!("unsupported election rules")
        }
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
            .execute_and_insert_block(proposed_block, false, false)
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
                "[RoundManager] SafetyRules {}Rejected",
                // TODO(lpl): Remove color because `termion` does not support
                // windows. Fg(Red),
                // Fg(Reset),
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
            let relay = self
                .process_vote(vote_msg.vote())
                .await
                .context("[RoundManager] Add a new vote")?;
            if relay {
                let exclude =
                    vec![vote_msg.vote().author(), self.network.author];
                self.network
                    .broadcast(
                        ConsensusMsg::VoteMsg(Box::new(vote_msg)),
                        exclude,
                    )
                    .await;
            }
        }
        Ok(())
    }

    /// Add a vote to the pending votes.
    /// If a new QC / TC is formed then
    /// 1) fetch missing dependencies if required, and then
    /// 2) call process_certificates(), which will start a new round in return.
    ///
    /// Return `Ok(true)` if the vote should be relayed.
    async fn process_vote(&mut self, vote: &Vote) -> anyhow::Result<bool> {
        diem_info!(
            self.new_log(LogEvent::ReceiveVote)
                .remote_peer(vote.author()),
            vote = %vote,
            vote_epoch = vote.vote_data().proposed().epoch(),
            vote_round = vote.vote_data().proposed().round(),
            vote_id = vote.vote_data().proposed().id(),
            vote_state = vote.vote_data().proposed().executed_state_id(),
        );

        // Add the vote and check whether it completes a new QC or a TC
        let mut relay = true;
        match self
            .round_state
            .insert_vote(vote, &self.epoch_state.verifier())
        {
            VoteReceptionResult::NewQuorumCertificate(_)
            | VoteReceptionResult::NewTimeoutCertificate(_) => {
                // Wait for extra time to gather more votes before entering the
                // next round.
                self.round_state
                    .setup_new_round_timeout(self.epoch_state.epoch);
            }
            VoteReceptionResult::VoteAdded(_) => {}
            VoteReceptionResult::DuplicateVote => {
                // Do not relay duplicate votes as we should have relayed it
                // before.
                relay = false;
            }
            VoteReceptionResult::EquivocateVote((vote1, vote2)) => {
                // Attack detected!
                // Construct a transaction to dispute this signer.
                // TODO(lpl): Allow non-committee member to dispute?
                match &self.proposal_generator {
                    Some(proposal_generator) => {
                        ensure!(
                            vote1.author() == vote2.author(),
                            "incorrect author"
                        );
                        ensure!(
                            vote1.vote_data().proposed().round()
                                == vote2.vote_data().proposed().round(),
                            "incorrect round"
                        );
                        diem_warn!("Find Equivocate Vote!!! author={}, vote1={:?}, vote2={:?}", vote.author(), vote1, vote2);
                        let dispute_payload = DisputePayload {
                            address: vote1.author(),
                            bls_pub_key: self
                                .epoch_state
                                .verifier()
                                .get_public_key(&vote1.author())
                                .expect("checked in verify"),
                            vrf_pub_key: self
                                .epoch_state
                                .verifier()
                                .get_vrf_public_key(&vote1.author())
                                .expect("checked in verify")
                                .unwrap(),
                            conflicting_votes: ConflictSignature::Vote((
                                bcs::to_bytes(&vote1).expect("encoding error"),
                                bcs::to_bytes(&vote2).expect("encoding error"),
                            )),
                        };
                        let raw_tx = RawTransaction::new_dispute(
                            proposal_generator.author(),
                            dispute_payload,
                        );
                        let signed_tx = raw_tx
                            .sign(&proposal_generator.private_key)?
                            .into_inner();
                        // TODO(lpl): Track disputed nodes to avoid sending
                        // multiple dispute, and retry if needed?
                        let (tx, rx) = oneshot::channel();
                        self.tx_sender.send((signed_tx, tx)).await?;
                        rx.await??;
                    }
                    None => {}
                }
                bail!("EquivocateVote!")
            }
            // Return error so that duplicate or invalid votes will not be
            // broadcast to others.
            r => bail!("vote not added with result {:?}", r),
        }
        Ok(relay)
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
                if executed_block.block().is_genesis_block() {
                    break;
                }
                id = executed_block.parent_id();
                blocks.push(executed_block.block().clone());
            } else if let Ok(Some(block)) =
                self.block_store.get_ledger_block(&id)
            {
                if block.is_genesis_block() {
                    break;
                }
                id = block.parent_id();
                blocks.push(block);
            } else {
                // TODO(lpl): This error may be needed in the future.
                // status = BlockRetrievalStatus::NotEnoughBlocks;
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
            .send_message_with_peer_id(&request.peer_id, &response)?;
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
    #[allow(unused)]
    pub fn consensus_state(&mut self) -> ConsensusState {
        self.safety_rules.consensus_state().unwrap()
    }

    #[cfg(test)]
    #[allow(unused)]
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
        diem_debug!("Check validator: r={} is_voting={}", r, self.is_voting);
        r && self.is_voting
    }

    /// Return true for blocks that we need to process
    pub fn filter_proposal(&self, p: &ProposalMsg) -> bool {
        self.proposer_election
            .receive_proposal_candidate(p.proposal())
            .unwrap_or(false)
    }

    /// Return true for votes that we need to process
    pub fn filter_vote(&self, v: &VoteMsg) -> bool {
        !self.round_state.vote_received(v.vote())
    }
}

/// The functions used in tests to construct attack cases
impl RoundManager {
    /// Force the node to vote for a proposal without changing its consensus
    /// state. The node will still vote for the correct proposal
    /// independently if that's not disabled.
    pub async fn force_vote_proposal(
        &mut self, block_id: HashValue, author: Author,
        private_key: &ConsensusPrivateKey,
    ) -> Result<()> {
        let proposal = self
            .block_store
            .get_block(block_id)
            .ok_or(anyhow::anyhow!("force sign block not received"))?;
        let vote_proposal = proposal.maybe_signed_vote_proposal().vote_proposal;
        let vote_data =
            SafetyRules::extension_check(&vote_proposal).map_err(|e| {
                anyhow::anyhow!("extension_check error: err={:?}", e)
            })?;
        let ledger_info = SafetyRules::construct_ledger_info(
            vote_proposal.block(),
            vote_data.hash(),
        )
        .map_err(|e| anyhow::anyhow!("extension_check error: err={:?}", e))?;
        let signature = private_key.sign(&ledger_info);
        let vote =
            Vote::new_with_signature(vote_data, author, ledger_info, signature);
        let vote_msg = VoteMsg::new(vote, self.block_store.sync_info());
        diem_debug!("force_vote_proposal: broadcast {:?}", vote_msg);
        self.network
            .broadcast(ConsensusMsg::VoteMsg(Box::new(vote_msg)), vec![])
            .await;
        Ok(())
    }

    /// Force the node to propose a block without changing its consensus
    /// state. The node will still propose a valid block independently if that's
    /// not disabled.
    pub async fn force_propose(
        &mut self, round: Round, parent_block_id: HashValue,
        payload: Vec<TransactionPayload>, private_key: &ConsensusPrivateKey,
    ) -> Result<()> {
        let parent_qc = self
            .block_store
            .get_quorum_cert_for_block(parent_block_id)
            .ok_or(anyhow::anyhow!(
                "no QC for parent: {:?}",
                parent_block_id
            ))?;
        let block_data = self
            .proposal_generator
            .as_ref()
            .ok_or(anyhow::anyhow!("proposal generator is None"))?
            .force_propose(round, parent_qc, payload)?;
        let signature = private_key.sign(&block_data);
        let mut signed_proposal =
            Block::new_proposal_from_block_data_and_signature(
                block_data, signature, None,
            );
        // TODO: This vrf_output is incorrect if we want to propose a block in
        // another epoch.
        signed_proposal.set_vrf_nonce_and_proof(
            self.proposer_election
                .gen_vrf_nonce_and_proof(signed_proposal.block_data())
                .ok_or(anyhow::anyhow!(
                    "The proposer should not propose in this round"
                ))?,
        );
        // TODO: The sync_info here may not be consistent with
        // `signed_proposal`.
        let proposal_msg =
            ProposalMsg::new(signed_proposal, self.block_store.sync_info());
        diem_debug!("force_propose: broadcast {:?}", proposal_msg);
        self.network
            .broadcast(
                ConsensusMsg::ProposalMsg(Box::new(proposal_msg)),
                vec![],
            )
            .await;
        Ok(())
    }

    pub async fn force_sign_pivot_decision(
        &mut self, pivot_decision: PivotBlockDecision,
    ) -> anyhow::Result<()> {
        let proposal_generator = self.proposal_generator.as_ref().ok_or(
            anyhow::anyhow!("Non-validator cannot sign pivot decision"),
        )?;
        diem_info!("force_sign_pivot_decision: {:?}", pivot_decision);
        // It's allowed for a node to sign conflict pivot decision,
        // so we do not need to persist this signing event.
        let raw_tx = RawTransaction::new_pivot_decision(
            proposal_generator.author(),
            pivot_decision,
            self.chain_id,
        );
        let signed_tx =
            raw_tx.sign(&proposal_generator.private_key)?.into_inner();
        let (tx, rx) = oneshot::channel();
        self.tx_sender.send((signed_tx, tx)).await?;
        // TODO(lpl): Check if we want to wait here.
        rx.await??;
        diem_debug!("force_sign_pivot_decision sends");
        Ok(())
    }

    pub fn get_chosen_proposal(&self) -> anyhow::Result<Option<Block>> {
        // This takes out the candidate, so we need to insert it back if it's
        // Some.
        let chosen = self.proposer_election.choose_proposal_to_vote();
        Ok(chosen)
    }

    pub fn start_voting(&mut self, initialize: bool) -> anyhow::Result<()> {
        if !initialize {
            self.safety_rules
                .start_voting(initialize)
                .map_err(anyhow::Error::from)?;
        }
        self.is_voting = true;
        Ok(())
    }

    pub fn stop_voting(&mut self) -> anyhow::Result<()> {
        self.safety_rules
            .stop_voting()
            .map_err(anyhow::Error::from)?;
        self.is_voting = false;
        Ok(())
    }
}
