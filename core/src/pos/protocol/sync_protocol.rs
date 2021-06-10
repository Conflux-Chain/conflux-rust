// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use super::{HSB_PROTOCOL_ID, HSB_PROTOCOL_VERSION};
use crate::{
    message::{GetMaybeRequestId, Message, MsgId},
    pos::{
        consensus::network::NetworkTask,
        protocol::{
            message::{block_retrieval::BlockRetrievalRpcRequest, msgid},
            request_manager::{
                request_handler::AsAny, RequestManager, RequestMessage,
            },
        },
    },
    sync::{Error, ErrorKind, CHECK_RPC_REQUEST_TIMER},
};

use crate::{
    pos::{
        consensus::network_interface::ConsensusMsg,
        protocol::message::block_retrieval_response::BlockRetrievalRpcResponse,
    },
    sync::ProtocolConfiguration,
};
use cfx_types::H256;
use consensus_types::{
    epoch_retrieval::EpochRetrievalRequest, proposal_msg::ProposalMsg,
    sync_info::SyncInfo, vote_msg::VoteMsg,
};
use diem_crypto::ed25519::Ed25519PublicKey;
use diem_types::epoch_change::EpochChangeProof;
use io::TimerToken;
use keccak_hash::keccak;
use network::{
    node_table::NodeId, service::ProtocolVersion, NetworkContext,
    NetworkProtocolHandler, NetworkService, UpdateNodeOperation,
};
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use std::{cmp::Eq, collections::HashMap, fmt::Debug, hash::Hash, sync::Arc};

#[derive(Default)]
pub struct PeerState {
    id: NodeId,
    peer_hash: H256,
    pos_public_key: Option<Ed25519PublicKey>,
}

impl PeerState {
    pub fn new(
        id: NodeId, peer_hash: H256, pos_public_key: Option<Ed25519PublicKey>,
    ) -> Self {
        Self {
            id,
            peer_hash,
            pos_public_key,
        }
    }

    pub fn set_pos_public_key(
        &mut self, pos_public_key: Option<Ed25519PublicKey>,
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
        &self, peer: H256, id: NodeId, pos_public_key: Option<Ed25519PublicKey>,
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
}

pub struct HotStuffSynchronizationProtocol {
    pub protocol_config: ProtocolConfiguration,
    pub own_node_hash: H256,
    pub peers: Arc<Peers>,
    pub request_manager: Arc<RequestManager>,
    pub network_task: NetworkTask,
    pub pos_peer_mapping: RwLock<HashMap<Ed25519PublicKey, H256>>,
}

impl HotStuffSynchronizationProtocol {
    pub fn new(
        own_node_hash: H256, network_task: NetworkTask,
        protocol_config: ProtocolConfiguration,
    ) -> Self
    {
        let request_manager = Arc::new(RequestManager::new(&protocol_config));
        HotStuffSynchronizationProtocol {
            protocol_config,
            own_node_hash,
            peers: Arc::new(Peers::new()),
            request_manager,
            network_task,
            pos_peer_mapping: RwLock::new(Default::default()),
        }
    }

    pub fn with_peers(
        protocol_config: ProtocolConfiguration, own_node_hash: H256,
        network_task: NetworkTask, peers: Arc<Peers>,
    ) -> Self
    {
        let request_manager = Arc::new(RequestManager::new(&protocol_config));
        HotStuffSynchronizationProtocol {
            protocol_config,
            own_node_hash,
            peers,
            request_manager,
            network_task,
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
    ) -> bool
    {
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
        warn!(
            "Error while handling message, peer={}, msgid={:?}, error={:?}",
            peer, msg_id, e
        );

        let mut disconnect = true;
        let mut warn = false;
        let reason = format!("{}", e.0);
        let error_reason = format!("{:?}", e);
        let mut op = None;

        // NOTE, DO NOT USE WILDCARD IN THE FOLLOWING MATCH STATEMENT!
        // COMPILER WILL HELP TO FIND UNHANDLED ERROR CASES.
        match e.0 {
            ErrorKind::InvalidBlock => op = Some(UpdateNodeOperation::Demotion),
            ErrorKind::InvalidGetBlockTxn(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::InvalidStatus(_) => {
                op = Some(UpdateNodeOperation::Failure)
            }
            ErrorKind::InvalidMessageFormat => {
                op = Some(UpdateNodeOperation::Remove)
            }
            ErrorKind::UnknownPeer => op = Some(UpdateNodeOperation::Failure),
            // TODO handle the unexpected response case (timeout or real invalid
            // message type)
            ErrorKind::UnexpectedResponse => disconnect = true,
            ErrorKind::RequestNotFound => disconnect = false,
            ErrorKind::InCatchUpMode(_) => {
                disconnect = false;
                warn = false;
            }
            ErrorKind::TooManyTrans => {}
            ErrorKind::InvalidTimestamp => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::InvalidSnapshotManifest(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::InvalidSnapshotChunk(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::AlreadyThrottled(_) => {
                op = Some(UpdateNodeOperation::Remove)
            }
            ErrorKind::EmptySnapshotChunk => disconnect = false,
            ErrorKind::Throttled(_, msg) => {
                disconnect = false;

                if let Err(e) = msg.send(io, peer) {
                    error!("failed to send throttled packet: {:?}", e);
                    disconnect = true;
                }
            }
            ErrorKind::Decoder(_) => op = Some(UpdateNodeOperation::Remove),
            ErrorKind::Io(_) => disconnect = false,
            ErrorKind::Network(kind) => match kind {
                network::ErrorKind::AddressParse => disconnect = false,
                network::ErrorKind::AddressResolve(_) => disconnect = false,
                network::ErrorKind::Auth => disconnect = false,
                network::ErrorKind::BadProtocol => {
                    op = Some(UpdateNodeOperation::Remove)
                }
                network::ErrorKind::BadAddr => disconnect = false,
                network::ErrorKind::Decoder => {
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
            ErrorKind::Storage(_) => {}
            ErrorKind::Msg(_) => op = Some(UpdateNodeOperation::Failure),
            ErrorKind::__Nonexhaustive {} => {
                op = Some(UpdateNodeOperation::Failure)
            }
            ErrorKind::InternalError(_) => {}
            ErrorKind::RpcTimeout => {}
            ErrorKind::RpcCancelledByDisconnection => {}
            ErrorKind::UnexpectedMessage(_) => {
                op = Some(UpdateNodeOperation::Remove)
            }
            ErrorKind::NotSupported(_) => disconnect = false,
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
    ) -> Result<(), Error>
    {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        let peer_hash = if !io.is_peer_self(peer) {
            if *peer == NodeId::default() {
                return Err(ErrorKind::UnknownPeer.into());
            }
            let peer_hash = keccak(peer);
            if !self.peers.contains(&peer_hash) {
                return Err(ErrorKind::UnknownPeer.into());
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
            ctx.peer, msg_id, msg_name, req_id, e.0,
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
                ErrorKind::InvalidMessageFormat.into(),
            );
        }

        let msg_id = raw[len - 1];
        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);

        let msg = &raw[0..raw.len() - 1];
        self.dispatch_message(io, peer, msg_id.into(), msg)
            .unwrap_or_else(|e| self.handle_error(io, peer, msg_id.into(), e));
    }

    fn on_peer_connected(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        _peer_protocol_version: ProtocolVersion,
        pos_public_key: Option<Ed25519PublicKey>,
    )
    {
        // TODO(linxi): maintain peer protocol version
        let new_originated = io.get_peer_connection_origin(peer);
        if new_originated.is_none() {
            debug!("Peer does not exist when just connected");
            return;
        }
        let new_originated = new_originated.unwrap();
        let peer_hash = keccak(peer);

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
            self.peers.insert(peer_hash.clone(), *peer, None);
            let peer_state =
                self.peers.get(&peer_hash).expect("peer not found");
            let mut peer_state = peer_state.write();
            peer_state.id = *peer;
            peer_state.peer_hash = peer_hash;
            self.request_manager.on_peer_connected(peer);
        } else {
            io.disconnect_peer(
                peer,
                Some(UpdateNodeOperation::Failure),
                "remove new peer connection",
            );
        }

        if let Some(public_key) = pos_public_key {
            self.pos_peer_mapping
                .write()
                .insert(public_key.clone(), peer_hash);
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
                "pos public key is not provided for peerL peer_hash={:?}",
                peer_hash
            );
        }

        info!(
            "hsb on_peer_connected: peer {:?}, peer_hash {:?}, peer count {}",
            peer,
            peer_hash,
            self.peers.len()
        );
    }

    fn on_peer_disconnected(&self, io: &dyn NetworkContext, peer: &NodeId) {
        let peer_hash = keccak(*peer);
        self.peers.remove(&peer_hash);
        self.request_manager.on_peer_disconnected(io, peer);
        info!(
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
    fn from(_: bcs::Error) -> Self { ErrorKind::InvalidMessageFormat.into() }
}

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        ErrorKind::InternalError(format!("{}", error)).into()
    }
}
