// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::counters;
use anyhow::ensure;
//use bytes::Bytes;
use super::super::consensus_types::{
    block_retrieval::BlockRetrievalRequest, common::Payload,
    epoch_retrieval::EpochRetrievalRequest, proposal_msg::ProposalMsg,
    sync_info::SyncInfo, vote_msg::VoteMsg,
};
use channel::{self, libra_channel, message_queues::QueueStyle};
use network::{NetworkService, PeerId};
//use futures::{channel::oneshot};
//use libra_logger::prelude::*;
use libra_types::{
    account_address::AccountAddress,
    crypto_proxies::{
        EpochInfo, LedgerInfoWithSignatures, ValidatorChangeProof,
    },
};
/*
use network::{
    proto::{
        ConsensusMsg, ConsensusMsg_oneof, Proposal, RequestBlock, RequestEpoch,
        SyncInfo as SyncInfoProto, VoteMsg as VoteMsgProto,
    },
    validator_network::{ConsensusNetworkEvents, ConsensusNetworkSender, Event, RpcError},
};
*/
use crate::{
    alliance_tree_graph::{
        bft::consensus::consensus_types::proposal_msg::ProposalUncheckedSignatures,
        hsb_sync_protocol::{
            sync_protocol::HotStuffSynchronizationProtocol, HSB_PROTOCOL_ID,
        },
    },
    message::{Message, RequestId},
};
use cfx_types::H256;
use libra_logger::prelude::{security_log, SecurityEvent};
use parking_lot::RwLock;
use std::{cmp::Ordering, sync::Arc};

pub struct NetworkSender<P> {
    pub network: Arc<NetworkService>,
    pub protocol_handler: Arc<HotStuffSynchronizationProtocol<P>>,
}

impl<P: Payload> NetworkSender<P> {
    pub fn new(
        network: Arc<NetworkService>,
        protocol_handler: Arc<HotStuffSynchronizationProtocol<P>>,
    ) -> Self
    {
        NetworkSender {
            network,
            protocol_handler,
        }
    }

    pub fn send_message(
        &self, recipients: Vec<AccountAddress>, msg: &dyn Message,
    ) {
        for peer_address in recipients {
            let peer_hash = H256::from_slice(peer_address.to_vec().as_slice());
            if let Some(peer) = self.protocol_handler.peers.get(&peer_hash) {
                let peer_id = peer.read().get_id();
                self.send_message_with_peer_id(peer_id, msg);
            }
        }
    }

    pub fn send_message_with_peer_id(
        &self, peer_id: PeerId, msg: &dyn Message,
    ) {
        if self
            .network
            .with_context(HSB_PROTOCOL_ID, |io| msg.send(io, peer_id))
            .is_err()
        {
            warn!("Error sending message!");
        }
    }
}

/// The block retrieval request is used internally for implementing RPC: the
/// callback is executed for carrying the response
#[derive(Debug)]
pub struct IncomingBlockRetrievalRequest {
    pub req: BlockRetrievalRequest,
    pub peer_id: PeerId,
    pub request_id: RequestId,
}

/// Just a convenience struct to keep all the network proxy receiving queues in
/// one place. Will be returned by the networking trait upon startup.
pub struct NetworkReceivers<T> {
    pub proposals: libra_channel::Receiver<AccountAddress, ProposalMsg<T>>,
    pub votes: libra_channel::Receiver<AccountAddress, VoteMsg>,
    pub block_retrieval:
        libra_channel::Receiver<AccountAddress, IncomingBlockRetrievalRequest>,
    pub sync_info_msgs:
        libra_channel::Receiver<AccountAddress, (SyncInfo, AccountAddress)>,
    pub epoch_change:
        libra_channel::Receiver<AccountAddress, LedgerInfoWithSignatures>,
    pub different_epoch:
        libra_channel::Receiver<AccountAddress, (u64, AccountAddress)>,
    pub epoch_retrieval: libra_channel::Receiver<
        AccountAddress,
        (EpochRetrievalRequest, AccountAddress),
    >,
}

impl<T> NetworkReceivers<T> {
    pub fn clear_prev_epoch_msgs(&mut self) {
        // clear all the channels that are relevant for the previous epoch event
        // processor
        self.proposals.clear();
        self.votes.clear();
        self.block_retrieval.clear();
        self.sync_info_msgs.clear();
    }
}

pub struct NetworkTask<T> {
    pub epoch_info: Arc<RwLock<EpochInfo>>,
    pub proposal_tx: libra_channel::Sender<AccountAddress, ProposalMsg<T>>,
    pub vote_tx: libra_channel::Sender<AccountAddress, VoteMsg>,
    pub block_request_tx:
        libra_channel::Sender<AccountAddress, IncomingBlockRetrievalRequest>,
    pub sync_info_tx:
        libra_channel::Sender<AccountAddress, (SyncInfo, AccountAddress)>,
    pub epoch_change_tx:
        libra_channel::Sender<AccountAddress, LedgerInfoWithSignatures>,
    pub different_epoch_tx:
        libra_channel::Sender<AccountAddress, (u64, AccountAddress)>,
    pub epoch_retrieval_tx: libra_channel::Sender<
        AccountAddress,
        (EpochRetrievalRequest, AccountAddress),
    >,
    /* all_events: Box<dyn Stream<Item =
     * anyhow::Result<Event<ConsensusMsg>>> + Send + Unpin>, */
}

impl<T: Payload> NetworkTask<T> {
    /// Establishes the initial connections with the peers and returns the
    /// receivers.
    pub fn new(
        epoch_info: Arc<RwLock<EpochInfo>>,
    ) -> (NetworkTask<T>, NetworkReceivers<T>) {
        let (proposal_tx, proposal_rx) = libra_channel::new(
            QueueStyle::LIFO,
            1,
            Some(&counters::PROPOSAL_CHANNEL_MSGS),
        );
        let (vote_tx, vote_rx) = libra_channel::new(
            QueueStyle::LIFO,
            1,
            Some(&counters::VOTES_CHANNEL_MSGS),
        );
        let (block_request_tx, block_request_rx) = libra_channel::new(
            QueueStyle::LIFO,
            1,
            Some(&counters::BLOCK_RETRIEVAL_CHANNEL_MSGS),
        );
        let (sync_info_tx, sync_info_rx) = libra_channel::new(
            QueueStyle::LIFO,
            1,
            Some(&counters::SYNC_INFO_CHANNEL_MSGS),
        );
        let (epoch_change_tx, epoch_change_rx) = libra_channel::new(
            QueueStyle::LIFO,
            1,
            Some(&counters::EPOCH_CHANGE_CHANNEL_MSGS),
        );
        let (different_epoch_tx, different_epoch_rx) =
            libra_channel::new(QueueStyle::LIFO, 1, None);
        let (epoch_retrieval_tx, epoch_retrieval_rx) =
            libra_channel::new(QueueStyle::LIFO, 1, None);
        //let network_events =
        // network_events.map_err(Into::<anyhow::Error>::into);
        // let all_events = Box::new(select(network_events, self_receiver));

        (
            NetworkTask {
                epoch_info,
                proposal_tx,
                vote_tx,
                block_request_tx,
                sync_info_tx,
                epoch_change_tx,
                different_epoch_tx,
                epoch_retrieval_tx,
                //all_events,
            },
            NetworkReceivers {
                proposals: proposal_rx,
                votes: vote_rx,
                block_retrieval: block_request_rx,
                sync_info_msgs: sync_info_rx,
                epoch_change: epoch_change_rx,
                different_epoch: different_epoch_rx,
                epoch_retrieval: epoch_retrieval_rx,
            },
        )
    }

    pub fn epoch(&self) -> u64 { self.epoch_info.read().epoch }

    pub async fn start(self) {
        /*
        use ConsensusMsg_oneof::*;
        while let Some(Ok(message)) = self.all_events.next().await {
            match message {
                Event::Message((peer_id, msg)) => {
                    let msg = match msg.message {
                        Some(msg) => msg,
                        None => {
                            warn!("Unexpected msg from {}: {:?}", peer_id, msg);
                            continue;
                        }
                    };

                    let r = match msg.clone() {
                        Proposal(proposal) => {
                            self.process_proposal(peer_id, proposal).await.map_err(|e| {
                                security_log(SecurityEvent::InvalidConsensusProposal)
                                    .error(&e)
                                    .data(&msg)
                                    .log();
                                e
                            })
                        }
                        VoteMsg(vote_msg) => self.process_vote(peer_id, vote_msg).await,
                        SyncInfo(sync_info) => self.process_sync_info(sync_info, peer_id).await,
                        EpochChange(proof) => self.process_epoch_change(peer_id, proof).await,
                        RequestEpoch(request) => self.process_epoch_request(peer_id, request).await,
                        _ => {
                            warn!("Unexpected msg from {}: {:?}", peer_id, msg);
                            continue;
                        }
                    };
                    if let Err(e) = r {
                        warn!("Failed to process msg {}", e)
                    }
                }
                Event::RpcRequest((peer_id, msg, callback)) => {
                    let r = match msg.message {
                        Some(RequestBlock(request)) => {
                            self.process_request_block(peer_id, request, callback).await
                        }
                        _ => {
                            warn!("Unexpected RPC from {}: {:?}", peer_id, msg);
                            continue;
                        }
                    };
                    if let Err(e) = r {
                        warn!("Failed to process RPC {:?}", e)
                    }
                }
                Event::NewPeer(peer_id) => {
                    debug!("Peer {} connected", peer_id);
                }
                Event::LostPeer(peer_id) => {
                    debug!("Peer {} disconnected", peer_id);
                }
            }
        }
        */
    }

    pub async fn process_proposal(
        &self, peer_id: AccountAddress, proposal: ProposalMsg<T>,
    ) -> anyhow::Result<()> {
        let proposal = ProposalUncheckedSignatures(proposal);
        if proposal.epoch() != self.epoch() {
            debug!(
                "Different epoch in proposal: proposal epoch {}, self epoch {}",
                proposal.epoch(),
                self.epoch()
            );
            return self
                .different_epoch_tx
                .push(peer_id, (proposal.epoch(), peer_id));
        }

        let proposal = proposal
            .validate_signatures(&self.epoch_info.read().verifier)?
            .verify_well_formed()?;
        ensure!(
            proposal.proposal().author() == Some(peer_id),
            "proposal received must be from the sending peer"
        );
        debug!("Received proposal {}", proposal);
        self.proposal_tx.push(peer_id, proposal)
    }

    pub async fn process_vote(
        &self, peer_id: AccountAddress, vote_msg: VoteMsg,
    ) -> anyhow::Result<()> {
        ensure!(
            vote_msg.vote().author() == peer_id,
            "vote received must be from the sending peer"
        );

        if vote_msg.epoch() != self.epoch() {
            return self
                .different_epoch_tx
                .push(peer_id, (vote_msg.epoch(), peer_id));
        }

        debug!("Received {}", vote_msg);
        vote_msg
            .verify(&self.epoch_info.read().verifier)
            .map_err(|e| {
                security_log(SecurityEvent::InvalidConsensusVote)
                    .error(&e)
                    .data(&vote_msg)
                    .log();
                e
            })?;
        self.vote_tx.push(peer_id, vote_msg)
    }

    pub async fn process_epoch_change(
        &self, peer_id: AccountAddress, proof: ValidatorChangeProof,
    ) -> anyhow::Result<()> {
        let msg_epoch = proof.epoch()?;
        match msg_epoch.cmp(&self.epoch()) {
            Ordering::Equal => {
                let rlock = self.epoch_info.read();
                let target_ledger_info = proof.verify(
                    rlock.epoch,
                    &rlock.verifier,
                    true, /* return_first */
                )?;
                debug!(
                    "Received epoch change to {}",
                    target_ledger_info.ledger_info().epoch() + 1
                );
                self.epoch_change_tx.push(peer_id, target_ledger_info)
            }
            Ordering::Less | Ordering::Greater => {
                self.different_epoch_tx.push(peer_id, (msg_epoch, peer_id))
            }
        }
    }
}
