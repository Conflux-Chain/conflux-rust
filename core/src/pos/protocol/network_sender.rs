// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use std::{mem::discriminant, sync::Arc};

use anyhow::format_err;
use futures::channel::oneshot;

use diem_types::account_address::AccountAddress;
use network::{node_table::NodeId, NetworkService};

use crate::{
    message::Message,
    pos::{
        consensus::network::ConsensusMsg,
        protocol::{
            request_manager::Request,
            sync_protocol::{HotStuffSynchronizationProtocol, RpcResponse},
            HSB_PROTOCOL_ID,
        },
    },
};

/// The interface from Consensus to Networking layer.
///
/// This is a thin wrapper around a `NetworkSender<ConsensusMsg>`, so it is easy
/// to clone and send off to a separate task. For example, the rpc requests
/// return Futures that encapsulate the whole flow, from sending the request to
/// remote, to finally receiving the response and deserializing. It therefore
/// makes the most sense to make the rpc call on a separate async task, which
/// requires the `NetworkSender` to be `Clone` and `Send`.
#[derive(Clone)]
pub struct NetworkSender {
    /// network service
    pub network: Arc<NetworkService>,
    /// hotstuff protocol handler
    pub protocol_handler: Arc<HotStuffSynchronizationProtocol>,
}

impl NetworkSender {
    /// Send a single message to the destination peer using the
    /// `CONSENSUS_DIRECT_SEND_PROTOCOL` ProtocolId.
    pub fn send_to(
        &mut self, recipient: AccountAddress, msg: &dyn Message,
    ) -> Result<(), anyhow::Error> {
        if let Some(peer_hash) = self
            .protocol_handler
            .pos_peer_mapping
            .read()
            .get(&recipient)
        {
            if let Some(peer) = self.protocol_handler.peers.get(peer_hash) {
                let peer_id = peer.read().get_id();
                self.send_message_with_peer_id(&peer_id, msg)?;
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
        &mut self, recipients: impl Iterator<Item = AccountAddress>,
        msg: &dyn Message,
    ) -> Result<(), anyhow::Error> {
        for recipient in recipients {
            self.send_to(recipient, msg)?;
        }
        Ok(())
    }

    /// Send a msg to all connected PoS nodes. They may or may not be
    /// validators.
    pub fn send_to_others(
        &mut self, msg: &dyn Message, exclude: &Vec<AccountAddress>,
    ) -> Result<(), anyhow::Error> {
        // The node itself is not included in pos_peer_mapping.
        for (node_id, peer_hash) in
            self.protocol_handler.pos_peer_mapping.read().iter()
        {
            if exclude.contains(node_id) {
                continue;
            }
            if let Some(peer) = self.protocol_handler.peers.get(peer_hash) {
                let peer_id = peer.read().get_id();
                self.send_message_with_peer_id(&peer_id, msg)?;
            } else {
                warn!("peer_hash {:?} does not exist", peer_hash);
            }
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
            .map_err(|e| format_err!("send rpc failed: err={:?}", e))?;
        Ok(res_rx
            .await?
            .map_err(|e| format_err!("rpc call failed: err={:?}", e))?)
    }

    /// Send msg to self
    pub async fn send_self_msg(
        &self, self_author: AccountAddress, msg: ConsensusMsg,
    ) -> anyhow::Result<(), anyhow::Error> {
        self.protocol_handler
            .consensus_network_task
            .consensus_messages_tx
            .push((self_author, discriminant(&msg)), (self_author, msg))
    }

    /// Send msg to peer
    pub fn send_message_with_peer_id(
        &self, peer_id: &NodeId, msg: &dyn Message,
    ) -> anyhow::Result<(), anyhow::Error> {
        self.network
            .with_context(
                self.protocol_handler.clone(),
                HSB_PROTOCOL_ID,
                |io| msg.send(io, peer_id),
            )
            .map_err(|e| format_err!("context failed: {:#}", e))?
            .map_err(|e| format_err!("send message failed: {:#}", e))?;
        Ok(())
    }
}
