// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use std::{collections::HashMap, fmt::Debug, mem::discriminant, sync::Arc};

use keccak_hash::keccak;
use parking_lot::RwLock;
use serde::Deserialize;

use cfx_types::H256;
use consensus_types::{
    epoch_retrieval::EpochRetrievalRequest, proposal_msg::ProposalMsg,
    sync_info::SyncInfo, vote_msg::VoteMsg,
};
use diem_types::{
    account_address::{from_consensus_public_key, AccountAddress},
    epoch_change::EpochChangeProof,
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
};
use io::TimerToken;
use network::{
    node_table::NodeId, service::ProtocolVersion, NetworkContext,
    NetworkProtocolHandler, NetworkService, UpdateNodeOperation,
};

use crate::{
    message::{Message, MsgId},
    pos::{
        consensus::network::{
            ConsensusMsg, NetworkTask as ConsensusNetworkTask,
        },
        mempool::network::{MempoolSyncMsg, NetworkTask as MempoolNetworkTask},
        protocol::{
            message::{
                block_retrieval::BlockRetrievalRpcRequest,
                block_retrieval_response::BlockRetrievalRpcResponse, msgid,
            },
            network_event::NetworkEvent,
            request_manager::{
                request_handler::AsAny, RequestManager, RequestMessage,
            },
        },
    },
    sync::{Error, ProtocolConfiguration, CHECK_RPC_REQUEST_TIMER},
};

use super::{HSB_PROTOCOL_ID, HSB_PROTOCOL_VERSION};

#[derive(Default)]
pub struct PeerState {
    id: NodeId,
    peer_hash: H256,
    // TODO(lpl): Only keep AccountAddress?
    pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
}

impl PeerState {
    pub fn new(
        id: NodeId, peer_hash: H256,
        pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    ) -> Self {
        Self {
            id,
            peer_hash,
            pos_public_key,
        }
    }

    pub fn set_pos_public_key(
        &mut self,
        pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    ) {
        self.pos_public_key = pos_public_key
    }

    pub fn get_id(&self) -> NodeId { self.id }
}

#[derive(Default)]
pub struct Peers(RwLock<HashMap<H256, Arc<RwLock<PeerState>>>>);

impl Peers {
    pub fn new() -> Peers { Self::default() }

    pub fn get(&self, peer: &H256) -> Option<Arc<RwLock<PeerState>>> {
        self.0.read().get(peer).cloned()
    }

    pub fn insert(
        &self, peer: H256, id: NodeId,
        pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    ) {
        self.0.write().entry(peer).or_insert(Arc::new(RwLock::new(
            PeerState::new(id, peer, pos_public_key),
        )));
    }

    pub fn len(&self) -> usize { self.0.read().len() }

    pub fn is_empty(&self) -> bool { self.0.read().is_empty() }

    pub fn contains(&self, peer: &H256) -> bool {
        self.0.read().contains_key(peer)
    }

    pub fn remove(&self, peer: &H256) -> Option<Arc<RwLock<PeerState>>> {
        self.0.write().remove(peer)
    }

    pub fn all_peers_satisfying<F>(&self, mut predicate: F) -> Vec<H256>
    where F: FnMut(&mut PeerState) -> bool {
        self.0
            .read()
            .iter()
            .filter_map(|(id, state)| {
                if predicate(&mut *state.write()) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn fold<B, F>(&self, init: B, f: F) -> B
    where F: FnMut(B, &Arc<RwLock<PeerState>>) -> B {
        self.0.write().values().fold(init, f)
    }
}

pub struct Context<'a> {
    pub io: &'a dyn NetworkContext,
    pub peer: NodeId,
    pub peer_hash: H256,
    pub manager: &'a HotStuffSynchronizationProtocol,
}

impl<'a> Context<'a> {
    pub fn match_request(
        &self, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        self.manager
            .request_manager
            .match_request(self.io, &self.peer, request_id)
    }

    pub fn send_response(&self, response: &dyn Message) -> Result<(), Error> {
        response.send(self.io, &self.peer)?;
        Ok(())
    }

    pub fn get_peer_account_address(&self) -> Result<AccountAddress, Error> {
        let k = self.get_pos_public_key().ok_or(Error::UnknownPeer)?;
        Ok(from_consensus_public_key(&k.0, &k.1))
    }

    fn get_pos_public_key(
        &self,
    ) -> Option<(ConsensusPublicKey, ConsensusVRFPublicKey)> {
        self.manager
            .peers
            .get(&self.peer_hash)
            .as_ref()?
            .read()
            .pos_public_key
            .clone()
    }
}

pub struct HotStuffSynchronizationProtocol {
    pub protocol_config: ProtocolConfiguration,
    pub own_node_hash: H256,
    pub peers: Arc<Peers>,
    pub request_manager: Arc<RequestManager>,
    pub consensus_network_task: ConsensusNetworkTask,
    pub mempool_network_task: MempoolNetworkTask,
    pub pos_peer_mapping: RwLock<HashMap<AccountAddress, H256>>,
}

impl HotStuffSynchronizationProtocol {
    pub fn new(
        own_node_hash: H256, consensus_network_task: ConsensusNetworkTask,
        mempool_network_task: MempoolNetworkTask,
        protocol_config: ProtocolConfiguration,
    ) -> Self {
        let request_manager = Arc::new(RequestManager::new(&protocol_config));
        HotStuffSynchronizationProtocol {
            protocol_config,
            own_node_hash,
            peers: Arc::new(Peers::new()),
            request_manager,
            consensus_network_task,
            mempool_network_task,
            pos_peer_mapping: RwLock::new(Default::default()),
        }
    }

    pub fn with_peers(
        protocol_config: ProtocolConfiguration, own_node_hash: H256,
        consensus_network_task: ConsensusNetworkTask,
        mempool_network_task: MempoolNetworkTask, peers: Arc<Peers>,
    ) -> Self {
        let request_manager = Arc::new(RequestManager::new(&protocol_config));
        HotStuffSynchronizationProtocol {
            protocol_config,
            own_node_hash,
            peers,
            request_manager,
            consensus_network_task,
            mempool_network_task,
            pos_peer_mapping: RwLock::new(Default::default()),
        }
    }

    pub fn register(
        self: Arc<Self>, network: Arc<NetworkService>,
    ) -> Result<(), String> {
        network
            .register_protocol(self, HSB_PROTOCOL_ID, HSB_PROTOCOL_VERSION)
            .map_err(|e| {
                format!(
                    "failed to register HotStuffSynchronizationProtocol: {:?}",
                    e
                )
            })
    }

    pub fn remove_expired_flying_request(&self, io: &dyn NetworkContext) {
        self.request_manager.process_timeout_requests(io);
        self.request_manager.resend_waiting_requests(io);
    }

    /// In the event two peers simultaneously dial each other we need to be able
    /// to do tie-breaking to determine which connection to keep and which
    /// to drop in a deterministic way. One simple way is to compare our
    /// local PeerId with that of the remote's PeerId and
    /// keep the connection where the peer with the greater PeerId is the
    /// dialer.
    ///
    /// Returns `true` if the existing connection should be dropped and `false`
    /// if the new connection should be dropped.
    fn simultaneous_dial_tie_breaking(
        own_peer_id: H256, remote_peer_id: H256, existing_origin: bool,
        new_origin: bool,
    ) -> bool {
        match (existing_origin, new_origin) {
            // If the remote dials while an existing connection is open, the
            // older connection is dropped.
            (false /* in-bound */, false /* in-bound */) => true,
            (false /* in-bound */, true /* out-bound */) => {
                remote_peer_id < own_peer_id
            }
            (true /* out-bound */, false /* in-bound */) => {
                own_peer_id < remote_peer_id
            }
            // We should never dial the same peer twice, but if we do drop the
            // new connection
            (true /* out-bound */, true /* out-bound */) => false,
        }
    }

    fn handle_error(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, e: Error,
    ) {
        let mut disconnect = true;
        let mut warn = false;
        let reason = format!("{}", e);
        let error_reason = format!("{:?}", e);
        let mut op = None;

        // NOTE, DO NOT USE WILDCARD IN THE FOLLOWING MATCH STATEMENT!
        // COMPILER WILL HELP TO FIND UNHANDLED ERROR CASES.
        match e {
            Error::InvalidBlock => op = Some(UpdateNodeOperation::Demotion),
            Error::InvalidGetBlockTxn(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            Error::InvalidStatus(_) => op = Some(UpdateNodeOperation::Failure),
            Error::InvalidMessageFormat => {
                op = Some(UpdateNodeOperation::Remove)
            }
            Error::UnknownPeer => {
                warn = false;
                op = Some(UpdateNodeOperation::Failure)
            }
            // TODO handle the unexpected response case (timeout or real invalid
            // message type)
            Error::UnexpectedResponse => disconnect = true,
            Error::RequestNotFound => {
                warn = false;
                disconnect = false;
            }
            Error::InCatchUpMode(_) => {
                disconnect = false;
                warn = false;
            }
            Error::TooManyTrans => {}
            Error::InvalidTimestamp => op = Some(UpdateNodeOperation::Demotion),
            Error::InvalidSnapshotManifest(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            Error::InvalidSnapshotChunk(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            Error::AlreadyThrottled(_) => {
                op = Some(UpdateNodeOperation::Remove)
            }
            Error::EmptySnapshotChunk => disconnect = false,
            Error::Throttled(_, msg) => {
                disconnect = false;

                if let Err(e) = msg.send(io, peer) {
                    error!("failed to send throttled packet: {:?}", e);
                    disconnect = true;
                }
            }
            Error::Decoder(_) => op = Some(UpdateNodeOperation::Remove),
            Error::Io(_) => disconnect = false,
            Error::Network(kind) => match kind.0 {
                network::ErrorKind::AddressParse => disconnect = false,
                network::ErrorKind::AddressResolve(_) => disconnect = false,
                network::ErrorKind::Auth => disconnect = false,
                network::ErrorKind::BadProtocol => {
                    op = Some(UpdateNodeOperation::Remove)
                }
                network::ErrorKind::BadAddr => disconnect = false,
                network::ErrorKind::Decoder(_) => {
                    op = Some(UpdateNodeOperation::Remove)
                }
                network::ErrorKind::Expired => disconnect = false,
                network::ErrorKind::Disconnect(_) => disconnect = false,
                network::ErrorKind::InvalidNodeId => disconnect = false,
                network::ErrorKind::OversizedPacket => disconnect = false,
                network::ErrorKind::Io(_) => disconnect = false,
                network::ErrorKind::Throttling(_) => disconnect = false,
                network::ErrorKind::SocketIo(_) => {
                    op = Some(UpdateNodeOperation::Failure)
                }
                network::ErrorKind::Msg(_) => {
                    op = Some(UpdateNodeOperation::Failure)
                }
                network::ErrorKind::__Nonexhaustive {} => {
                    op = Some(UpdateNodeOperation::Failure)
                }
                network::ErrorKind::MessageDeprecated { .. } => {
                    op = Some(UpdateNodeOperation::Failure)
                }
                network::ErrorKind::SendUnsupportedMessage { .. } => {
                    op = Some(UpdateNodeOperation::Failure)
                }
            },
            Error::Storage(_) => {}
            Error::Msg(_) => op = Some(UpdateNodeOperation::Failure),
            // Error::__Nonexhaustive {} => {
            //     op = Some(UpdateNodeOperation::Failure)
            // }
            Error::InternalError(_) => {}
            Error::RpcTimeout => {}
            Error::RpcCancelledByDisconnection => {}
            Error::UnexpectedMessage(_) => {
                op = Some(UpdateNodeOperation::Remove)
            }
            Error::NotSupported(_) => disconnect = false,
        }

        if warn {
            warn!(
                "Error while handling message, peer={}, msgid={:?}, error={}",
                peer, msg_id, error_reason
            );
        } else {
            debug!(
                "Minor error while handling message, peer={}, msgid={:?}, error={}",
                peer, msg_id, error_reason
            );
        }

        if disconnect {
            io.disconnect_peer(peer, op, reason.as_str());
        }
    }

    fn dispatch_message(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId,
        msg: &[u8],
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        let peer_hash = if !io.is_peer_self(peer) {
            if *peer == NodeId::default() {
                return Err(Error::UnknownPeer.into());
            }
            let peer_hash = keccak(peer);
            if !self.peers.contains(&peer_hash) {
                return Err(Error::UnknownPeer.into());
            }
            peer_hash
        } else {
            self.own_node_hash.clone()
        };

        let ctx = Context {
            peer_hash,
            peer: *peer,
            io,
            manager: self,
        };

        if !handle_serialized_message(msg_id, &ctx, msg)? {
            warn!("Unknown message: peer={:?} msgid={:?}", peer, msg_id);
            let reason =
                format!("unknown sync protocol message id {:?}", msg_id);
            io.disconnect_peer(
                peer,
                Some(UpdateNodeOperation::Remove),
                reason.as_str(),
            );
        }

        Ok(())
    }
}

pub fn handle_serialized_message(
    id: MsgId, ctx: &Context, msg: &[u8],
) -> Result<bool, Error> {
    match id {
        msgid::PROPOSAL => handle_message::<ProposalMsg>(ctx, msg)?,
        msgid::VOTE => handle_message::<VoteMsg>(ctx, msg)?,
        msgid::SYNC_INFO => handle_message::<SyncInfo>(ctx, msg)?,
        msgid::BLOCK_RETRIEVAL => {
            handle_message::<BlockRetrievalRpcRequest>(ctx, msg)?
        }
        msgid::BLOCK_RETRIEVAL_RESPONSE => {
            handle_message::<BlockRetrievalRpcResponse>(ctx, msg)?
        }
        msgid::EPOCH_RETRIEVAL => {
            handle_message::<EpochRetrievalRequest>(ctx, msg)?
        }
        msgid::EPOCH_CHANGE => handle_message::<EpochChangeProof>(ctx, msg)?,
        msgid::CONSENSUS_MSG => handle_message::<ConsensusMsg>(ctx, msg)?,
        msgid::MEMPOOL_SYNC_MSG => handle_message::<MempoolSyncMsg>(ctx, msg)?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn handle_message<'a, M>(ctx: &Context, msg: &'a [u8]) -> Result<(), Error>
where M: Deserialize<'a> + Handleable + Message {
    let msg: M = bcs::from_bytes(msg)?;
    let msg_id = msg.msg_id();
    let msg_name = msg.msg_name();
    let req_id = msg.get_request_id();

    trace!(
        "handle sync protocol message, peer = {:?}, id = {}, name = {}, request_id = {:?}",
        ctx.peer_hash, msg_id, msg_name, req_id,
    );

    // FIXME: add throttling.

    if let Err(e) = msg.handle(ctx) {
        info!(
            "failed to handle sync protocol message, peer = {}, id = {}, name = {}, request_id = {:?}, error_kind = {:?}",
            ctx.peer, msg_id, msg_name, req_id, e,
        );

        return Err(e);
    }

    Ok(())
}

impl NetworkProtocolHandler for HotStuffSynchronizationProtocol {
    fn minimum_supported_version(&self) -> ProtocolVersion {
        ProtocolVersion(0)
    }

    fn initialize(&self, io: &dyn NetworkContext) {
        io.register_timer(
            CHECK_RPC_REQUEST_TIMER,
            self.protocol_config.check_request_period,
        )
        .expect("Error registering check rpc request timer");
    }

    fn on_message(&self, io: &dyn NetworkContext, peer: &NodeId, raw: &[u8]) {
        let len = raw.len();
        if len < 2 {
            // Empty message.
            return self.handle_error(
                io,
                peer,
                msgid::INVALID,
                Error::InvalidMessageFormat.into(),
            );
        }

        let msg_id = raw[len - 1];
        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);

        let msg = &raw[0..raw.len() - 1];
        self.dispatch_message(io, peer, msg_id.into(), msg)
            .unwrap_or_else(|e| self.handle_error(io, peer, msg_id.into(), e));
    }

    fn on_peer_connected(
        &self, io: &dyn NetworkContext, node_id: &NodeId,
        _peer_protocol_version: ProtocolVersion,
        pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    ) {
        // TODO(linxi): maintain peer protocol version
        let new_originated = io.get_peer_connection_origin(node_id);
        if new_originated.is_none() {
            debug!("Peer does not exist when just connected");
            return;
        }
        let new_originated = new_originated.unwrap();
        let peer_hash = keccak(node_id);

        let add_new_peer = if let Some(old_peer) = self.peers.remove(&peer_hash)
        {
            let old_peer_id = &old_peer.read().id;
            let old_originated = io.get_peer_connection_origin(old_peer_id);
            if old_originated.is_none() {
                debug!("Old session does not exist.");
                true
            } else {
                let old_originated = old_originated.unwrap();
                if Self::simultaneous_dial_tie_breaking(
                    self.own_node_hash.clone(),
                    peer_hash.clone(),
                    old_originated,
                    new_originated,
                ) {
                    // Drop the existing connection and replace it with the new
                    // connection.
                    io.disconnect_peer(
                        old_peer_id,
                        Some(UpdateNodeOperation::Failure),
                        "remove old peer connection",
                    );
                    true
                } else {
                    // Drop the new connection.
                    false
                }
            }
        } else {
            true
        };

        if add_new_peer {
            self.peers.insert(peer_hash.clone(), *node_id, None);
            if let Some(state) = self.peers.get(&peer_hash) {
                let mut state = state.write();
                state.id = *node_id;
                state.peer_hash = peer_hash;
                self.request_manager.on_peer_connected(node_id);
            } else {
                warn!(
                    "PeerState is missing for peer: peer_hash={:?}",
                    peer_hash
                );
            }
        } else {
            io.disconnect_peer(
                node_id,
                Some(UpdateNodeOperation::Failure),
                "remove new peer connection",
            );
        }

        if let Some(public_key) = pos_public_key {
            self.pos_peer_mapping.write().insert(
                from_consensus_public_key(&public_key.0, &public_key.1),
                peer_hash,
            );
            if add_new_peer {
                let event = NetworkEvent::PeerConnected;
                if let Err(e) = self
                    .mempool_network_task
                    .network_events_tx
                    .push((*node_id, discriminant(&event)), (*node_id, event))
                {
                    warn!("error sending PeerConnected: e={:?}", e);
                }
            }
            if let Some(state) = self.peers.get(&peer_hash) {
                state.write().set_pos_public_key(Some(public_key));
            } else {
                warn!(
                    "PeerState is missing for peer: peer_hash={:?}",
                    peer_hash
                );
            }
        } else {
            info!(
                "pos public key is not provided for peer peer_hash={:?}",
                peer_hash
            );
        }

        debug!(
            "hsb on_peer_connected: peer {:?}, peer_hash {:?}, peer count {}",
            node_id,
            peer_hash,
            self.peers.len()
        );
    }

    fn on_peer_disconnected(&self, io: &dyn NetworkContext, peer: &NodeId) {
        let peer_hash = keccak(*peer);
        if let Some(peer_state) = self.peers.remove(&peer_hash) {
            if let Some(pos_public_key) = &peer_state.read().pos_public_key {
                self.pos_peer_mapping.write().remove(
                    &from_consensus_public_key(
                        &pos_public_key.0,
                        &pos_public_key.1,
                    ),
                );
            }
        }
        // notify pos mempool
        let event = NetworkEvent::PeerDisconnected;
        if let Err(e) = self
            .mempool_network_task
            .network_events_tx
            .push((*peer, discriminant(&event)), (*peer, event))
        {
            warn!("error sending PeerDisconnected: e={:?}", e);
        }

        self.request_manager.on_peer_disconnected(io, peer);
        debug!(
            "hsb on_peer_disconnected: peer={}, peer count {}",
            peer,
            self.peers.len()
        );
    }

    fn on_timeout(&self, io: &dyn NetworkContext, timer: TimerToken) {
        trace!("hsb protocol timeout: timer={:?}", timer);
        match timer {
            CHECK_RPC_REQUEST_TIMER => {
                self.remove_expired_flying_request(io);
            }
            _ => warn!("hsb protocol: unknown timer {} triggered.", timer),
        }
    }

    fn send_local_message(&self, _io: &dyn NetworkContext, _message: Vec<u8>) {
        todo!()
    }

    fn on_work_dispatch(&self, _io: &dyn NetworkContext, _work_type: u8) {
        todo!()
    }
}

pub trait Handleable {
    fn handle(self, ctx: &Context) -> Result<(), Error>;
}

pub trait RpcResponse: Send + Sync + Debug + AsAny {}

impl From<bcs::Error> for Error {
    fn from(_: bcs::Error) -> Self { Error::InvalidMessageFormat.into() }
}

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        Error::InternalError(format!("{}", error)).into()
    }
}
