// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{mem::Discriminant, time::Duration};

use anyhow::{anyhow, bail, ensure, format_err};
use serde::{Deserialize, Serialize};

use channel::{self, diem_channel, message_queues::QueueStyle};
use consensus_types::{
    block_retrieval::{BlockRetrievalRequest, BlockRetrievalResponse},
    common::Author,
    epoch_retrieval::EpochRetrievalRequest,
    proposal_msg::ProposalMsg,
    sync_info::SyncInfo,
    vote_msg::VoteMsg,
};
use diem_logger::prelude::*;
use diem_metrics::monitor;
use diem_types::{
    account_address::AccountAddress, epoch_change::EpochChangeProof,
    validator_verifier::ValidatorVerifier,
};
use network::node_table::NodeId;

use crate::{
    message::RequestId,
    pos::protocol::{
        message::{
            block_retrieval::BlockRetrievalRpcRequest,
            block_retrieval_response::BlockRetrievalRpcResponse,
        },
        network_sender::NetworkSender,
    },
};

use super::counters;

/// Network type for consensus
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ConsensusMsg {
    /// RPC to get a chain of block of the given length starting from the given
    /// block id.
    BlockRetrievalRequest(Box<BlockRetrievalRequest>),
    /// Carries the returned blocks and the retrieval status.
    BlockRetrievalResponse(Box<BlockRetrievalResponse>),
    /// Request to get a EpochChangeProof from current_epoch to target_epoch
    EpochRetrievalRequest(Box<EpochRetrievalRequest>),
    /// ProposalMsg contains the required information for the proposer election
    /// protocol to make its choice (typically depends on round and
    /// proposer info).
    ProposalMsg(Box<ProposalMsg>),
    /// This struct describes basic synchronization metadata.
    SyncInfo(Box<SyncInfo>),
    /// A vector of LedgerInfo with contiguous increasing epoch numbers to
    /// prove a sequence of epoch changes from the first LedgerInfo's
    /// epoch.
    EpochChangeProof(Box<EpochChangeProof>),
    /// VoteMsg is the struct that is ultimately sent by the voter in response
    /// for receiving a proposal.
    VoteMsg(Box<VoteMsg>),
}

/// The block retrieval request is used internally for implementing RPC: the
/// callback is executed for carrying the response
#[derive(Debug)]
pub struct IncomingBlockRetrievalRequest {
    pub req: BlockRetrievalRequest,
    pub peer_id: NodeId,
    pub request_id: RequestId,
}

/// Just a convenience struct to keep all the network proxy receiving queues in
/// one place. Will be returned by the NetworkTask upon startup.
pub struct NetworkReceivers {
    /// Provide a LIFO buffer for each (Author, MessageType) key
    pub consensus_messages: diem_channel::Receiver<
        (AccountAddress, Discriminant<ConsensusMsg>),
        (AccountAddress, ConsensusMsg),
    >,
    pub block_retrieval:
        diem_channel::Receiver<AccountAddress, IncomingBlockRetrievalRequest>,
}

/// Implements the actual networking support for all consensus messaging.
#[derive(Clone)]
pub struct ConsensusNetworkSender {
    pub author: Author,
    network_sender: NetworkSender,
    validators: ValidatorVerifier,
}

impl ConsensusNetworkSender {
    pub fn new(
        author: Author, network_sender: NetworkSender,
        validators: ValidatorVerifier,
    ) -> Self {
        ConsensusNetworkSender {
            author,
            network_sender,
            validators,
        }
    }

    pub fn network_sender(&self) -> &NetworkSender { &self.network_sender }

    /// Tries to retrieve num of blocks backwards starting from id from the
    /// given peer: the function returns a future that is fulfilled with
    /// BlockRetrievalResponse.
    pub async fn request_block(
        &mut self, retrieval_request: BlockRetrievalRequest, from: Author,
        timeout: Duration,
    ) -> anyhow::Result<BlockRetrievalResponse> {
        ensure!(from != self.author, "Retrieve block from self");

        let peer_hash = self
            .network_sender
            .protocol_handler
            .pos_peer_mapping
            .read()
            .get(&from)
            .cloned()
            .ok_or(anyhow!(
                "request_block: recipient {:?} has been removed",
                from
            ))?;
        let peer_state =
            self.network_sender.protocol_handler.peers.get(&peer_hash);
        if peer_state.is_none() {
            bail!("peer not found");
        }
        let peer_state = peer_state.unwrap();
        let peer_id = peer_state.read().get_id().clone();

        let request = BlockRetrievalRpcRequest {
            request_id: 0,
            request: retrieval_request.clone(),
            is_empty: false,
            response_tx: None,
            timeout,
        };

        let rpc_response = monitor!(
            "block_retrieval",
            self.network_sender
                .send_rpc(Some(peer_id), Box::new(request))
                .await
                .map_err(|_| { format_err!("rpc call failed") })?
        );
        let response = match rpc_response
            .as_any()
            .downcast_ref::<BlockRetrievalRpcResponse>()
        {
            Some(r) => r.clone(),
            None => {
                bail!("response downcast failed");
            }
        };

        response
            .response
            .verify(
                retrieval_request.block_id(),
                retrieval_request.num_blocks(),
                &self.validators,
            )
            .map_err(|e| {
                diem_error!(
                    request_block_response = response,
                    error = ?e,
                );
                e
            })?;

        Ok(response.response)
    }

    /// Tries to send the given msg to all the participants.
    ///
    /// The future is fulfilled as soon as the message put into the mpsc channel
    /// to network internal(to provide back pressure), it does not indicate
    /// the message is delivered or sent out. It does not give indication
    /// about when the message is delivered to the recipients, as well as
    /// there is no indication about the network failures.
    pub async fn broadcast(
        &mut self, msg: ConsensusMsg, exclude: Vec<AccountAddress>,
    ) {
        if !exclude.contains(&self.author) {
            if let Err(err) = self
                .network_sender
                .send_self_msg(self.author, msg.clone())
                .await
            {
                diem_error!("Error broadcasting to self: {:?}", err);
            }
        }

        /*
        // Get the list of validators excluding our own account address. Note
        // the ordering is not important in this case.
        let self_author = self.author;
        let other_validators = self
            .validators
            .get_ordered_account_addresses_iter()
            .filter(|author| author != &self_author);
        let mut public_keys = vec![];
        for account in other_validators {
            public_keys.push(self.validators.get_public_key(&account).unwrap());
        }

        // Broadcast message over direct-send to all other validators.
        if let Err(err) = self
            .network_sender
            .send_to_many(public_keys.into_iter(), &msg)
        {
            diem_error!(error = ?err, "Error broadcasting message");
        }
         */
        // TODO(lpl): It may be sufficient to broadcast some messages to only
        // validators.
        if let Err(err) = self.network_sender.send_to_others(&msg, &exclude) {
            diem_error!(error = ?err, "Error broadcasting message");
        }
    }

    // This is unused because we always broadcast votes now.
    // It may be needed when non-voter nodes do not receive votes anymore.
    #[allow(unused)]
    /// Sends the vote to the chosen recipients (typically that would be the
    /// recipients that we believe could serve as proposers in the next
    /// round). The recipients on the receiving end are going to be notified
    /// about a new vote in the vote queue.
    ///
    /// The future is fulfilled as soon as the message put into the mpsc channel
    /// to network internal(to provide back pressure), it does not indicate
    /// the message is delivered or sent out. It does not give indication
    /// about when the message is delivered to the recipients, as well as
    /// there is no indication about the network failures.
    pub async fn send_vote(&self, vote_msg: VoteMsg, recipients: Vec<Author>) {
        let mut network_sender = self.network_sender.clone();
        let msg = ConsensusMsg::VoteMsg(Box::new(vote_msg));
        for peer in recipients {
            if self.author == peer {
                if let Err(err) =
                    network_sender.send_self_msg(self.author, msg.clone()).await
                {
                    diem_error!(error = ?err, "Error delivering a self vote");
                }
                continue;
            }
            if let Err(e) = network_sender.send_to(peer, &msg) {
                diem_error!(
                    remote_peer = peer,
                    error = ?e, "Failed to send a vote to peer",
                );
            }
        }
    }

    /// Sends the given sync info to the given author.
    /// The future is fulfilled as soon as the message is added to the internal
    /// network channel (does not indicate whether the message is delivered
    /// or sent out).
    pub fn send_sync_info(&self, sync_info: SyncInfo, recipient: Author) {
        let msg = ConsensusMsg::SyncInfo(Box::new(sync_info));
        let mut network_sender = self.network_sender.clone();
        if let Err(e) = network_sender.send_to(recipient, &msg) {
            diem_warn!(
                remote_peer = recipient,
                error = "Failed to send a sync info msg to peer {:?}",
                "{:?}",
                e
            );
        }
    }
}

/// Consensus network task
pub struct NetworkTask {
    /// consensus message sender
    pub consensus_messages_tx: diem_channel::Sender<
        (AccountAddress, Discriminant<ConsensusMsg>),
        (AccountAddress, ConsensusMsg),
    >,
    /// block retrieval message sender
    pub block_retrieval_tx:
        diem_channel::Sender<AccountAddress, IncomingBlockRetrievalRequest>,
}

impl NetworkTask {
    /// Establishes the initial connections with the peers and returns the
    /// receivers.
    pub fn new() -> (NetworkTask, NetworkReceivers) {
        let (consensus_messages_tx, consensus_messages) = diem_channel::new(
            QueueStyle::LIFO,
            1,
            Some(&counters::CONSENSUS_CHANNEL_MSGS),
        );
        let (block_retrieval_tx, block_retrieval) = diem_channel::new(
            QueueStyle::LIFO,
            1,
            Some(&counters::BLOCK_RETRIEVAL_CHANNEL_MSGS),
        );
        (
            NetworkTask {
                consensus_messages_tx,
                block_retrieval_tx,
            },
            NetworkReceivers {
                consensus_messages,
                block_retrieval,
            },
        )
    }

    /// start
    pub async fn start(self) {}
}
