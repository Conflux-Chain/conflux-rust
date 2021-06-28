// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Interface between Consensus and Network layers.

use crate::{
    message::Message,
    pos::protocol::{
        request_manager::Request,
        sync_protocol::{HotStuffSynchronizationProtocol, RpcResponse},
        HSB_PROTOCOL_ID,
    },
};
use anyhow::{format_err, Context};
use cfx_types::H256;
use consensus_types::{
    block_retrieval::{BlockRetrievalRequest, BlockRetrievalResponse},
    epoch_retrieval::EpochRetrievalRequest,
    proposal_msg::ProposalMsg,
    sync_info::SyncInfo,
    vote_msg::VoteMsg,
};
use diem_crypto::ed25519::Ed25519PublicKey;
use diem_types::{
    account_address::AccountAddress, epoch_change::EpochChangeProof,
    validator_config::ConsensusPublicKey, PeerId,
};
use futures::channel::oneshot;
use network::{node_table::NodeId, NetworkService};
use serde::{Deserialize, Serialize};
use std::{mem::discriminant, sync::Arc};

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

/// The interface from Consensus to Networking layer.
///
/// This is a thin wrapper around a `NetworkSender<ConsensusMsg>`, so it is easy
/// to clone and send off to a separate task. For example, the rpc requests
/// return Futures that encapsulate the whole flow, from sending the request to
/// remote, to finally receiving the response and deserializing. It therefore
/// makes the most sense to make the rpc call on a separate async task, which
/// requires the `ConsensusNetworkSender` to be `Clone` and `Send`.
#[derive(Clone)]
pub struct ConsensusNetworkSender {
    /// network service
    pub network: Arc<NetworkService>,
    /// hotstuff protoal handler
    pub protocol_handler: Arc<HotStuffSynchronizationProtocol>,
}

impl ConsensusNetworkSender {
    /// Send a single message to the destination peer using the
    /// `CONSENSUS_DIRECT_SEND_PROTOCOL` ProtocolId.
    pub fn send_to(
        &mut self, recipient: ConsensusPublicKey, msg: &dyn Message,
    ) -> Result<(), anyhow::Error> {
        if let Some(peer_hash) = self
            .protocol_handler
            .pos_peer_mapping
            .read()
            .get(&recipient)
        {
            if let Some(peer) = self.protocol_handler.peers.get(peer_hash) {
                let peer_id = peer.read().get_id();
                self.send_message_with_peer_id(&peer_id, msg);
            } else {
                warn!("peer_hash {:?} does not exist", peer_hash);
            }
        } else {
            warn!("recipient {:?} has been removed", recipient)
        }
        Ok(())
    }

    /// Send a single message to the destination peers using the
    /// `CONSENSUS_DIRECT_SEND_PROTOCOL` ProtocolId.
    pub fn send_to_many(
        &mut self, recipients: impl Iterator<Item = ConsensusPublicKey>,
        msg: &dyn Message,
    ) -> Result<(), anyhow::Error>
    {
        for recipient in recipients {
            self.send_to(recipient, msg)?;
        }
        Ok(())
    }

    /// Send a RPC to the destination peer using the `CONSENSUS_RPC_PROTOCOL`
    /// ProtocolId.
    pub async fn send_rpc(
        &self, recipient: Option<NodeId>, mut request: Box<dyn Request>,
    ) -> Result<Box<dyn RpcResponse>, anyhow::Error> {
        let (res_tx, res_rx) = oneshot::channel();
        self.network
            .with_context(
                self.protocol_handler.clone(),
                HSB_PROTOCOL_ID,
                |io| {
                    request.set_response_notification(res_tx);
                    self.protocol_handler
                        .request_manager
                        .request_with_delay(io, request, recipient, None)
                },
            )
            .map_err(|_| format_err!("send rpc failed"))?;
        Ok(res_rx.await?.map_err(|_| format_err!("rpc call failed"))?)
    }

    /// Send msg to self
    pub async fn send_self_msg(
        &self, self_author: AccountAddress, msg: ConsensusMsg,
    ) -> anyhow::Result<(), anyhow::Error> {
        self.protocol_handler
            .network_task
            .consensus_messages_tx
            .push((self_author, discriminant(&msg)), (self_author, msg))
    }

    /// Send msg to peer
    pub fn send_message_with_peer_id(
        &self, peer_id: &NodeId, msg: &dyn Message,
    ) {
        if self
            .network
            .with_context(
                self.protocol_handler.clone(),
                HSB_PROTOCOL_ID,
                |io| msg.send(io, peer_id),
            )
            .is_err()
        {
            warn!("Error sending message!");
        }
    }
}
