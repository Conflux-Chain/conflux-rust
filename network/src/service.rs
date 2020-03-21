// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::DisconnectReason;
use crate::{
    discovery::{Discovery, DISCOVER_NODES_COUNT},
    handshake::BYPASS_CRYPTOGRAPHY,
    io::*,
    ip_utils::{map_external_address, select_public_address},
    node_database::NodeDatabase,
    node_table::*,
    session::{self, Session, SessionData, SessionDetails},
    session_manager::SessionManager,
    Capability, Error, ErrorKind, HandlerWorkType, IpFilter,
    NetworkConfiguration, NetworkContext as NetworkContextTrait,
    NetworkIoMessage, NetworkProtocolHandler, PeerId, PeerInfo, ProtocolId,
    UpdateNodeOperation, NODE_TAG_ARCHIVE, NODE_TAG_NODE_TYPE,
};
use cfx_bytes::Bytes;
use keccak_hash::keccak;
use keylib::{sign, Generator, KeyPair, Random, Secret};
use mio::{tcp::*, udp::*, *};
use parity_path::restrict_permissions_owner;
use parking_lot::{Mutex, RwLock};
use priority_send_queue::SendQueuePriority;
use std::{
    cmp::{min, Ordering},
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{atomic::Ordering as AtomicOrdering, Arc},
    time::{Duration, Instant},
};

const NULL: usize = !0;

const MAX_SESSIONS: usize = 2048;

const DEFAULT_PORT: u16 = 32323;

const FIRST_SESSION: StreamToken = 0;
const LAST_SESSION: StreamToken = FIRST_SESSION + MAX_SESSIONS - 1;
const SYS_TIMER: TimerToken = LAST_SESSION + 1;
const TCP_ACCEPT: StreamToken = SYS_TIMER + 1;
const HOUSEKEEPING: TimerToken = SYS_TIMER + 2;
const UDP_MESSAGE: StreamToken = SYS_TIMER + 3;
const DISCOVERY_REFRESH: TimerToken = SYS_TIMER + 4;
const FAST_DISCOVERY_REFRESH: TimerToken = SYS_TIMER + 5;
const DISCOVERY_ROUND: TimerToken = SYS_TIMER + 6;
const NODE_TABLE: TimerToken = SYS_TIMER + 7;
const SEND_DELAYED_MESSAGES: TimerToken = SYS_TIMER + 8;
const CHECK_SESSIONS: TimerToken = SYS_TIMER + 9;
const HANDLER_TIMER: TimerToken = LAST_SESSION + 256;
const STOP_NET_POLL: TimerToken = HANDLER_TIMER + 1;

pub const DEFAULT_HOUSEKEEPING_TIMEOUT: Duration = Duration::from_secs(2);
// for DISCOVERY_REFRESH TimerToken
pub const DEFAULT_DISCOVERY_REFRESH_TIMEOUT: Duration =
    Duration::from_secs(120);
// for FAST_DISCOVERY_REFRESH TimerToken
pub const DEFAULT_FAST_DISCOVERY_REFRESH_TIMEOUT: Duration =
    Duration::from_secs(10);
// for DISCOVERY_ROUND TimerToken
pub const DEFAULT_DISCOVERY_ROUND_TIMEOUT: Duration =
    Duration::from_millis(500);
// The ticker interval for NODE_TABLE, i.e., how often the program will refresh
// the NODE_TABLE.
pub const DEFAULT_NODE_TABLE_TIMEOUT: Duration = Duration::from_secs(300);
// The lifetime threshold of the connection for promoting a peer from untrusted
// to trusted.
pub const DEFAULT_CONNECTION_LIFETIME_FOR_PROMOTION: Duration =
    Duration::from_secs(3 * 24 * 3600);
const DEFAULT_CHECK_SESSIONS_TIMEOUT: Duration = Duration::from_secs(10);

pub const MAX_DATAGRAM_SIZE: usize = 1280;

pub const UDP_PROTOCOL_DISCOVERY: u8 = 1;

pub struct Datagram {
    pub payload: Bytes,
    pub address: SocketAddr,
}

pub struct UdpChannel {
    pub send_queue: VecDeque<Datagram>,
}

impl UdpChannel {
    pub fn new() -> UdpChannel {
        UdpChannel {
            send_queue: VecDeque::new(),
        }
    }

    pub fn any_sends_queued(&self) -> bool { !self.send_queue.is_empty() }

    pub fn dequeue_send(&mut self) -> Option<Datagram> {
        self.send_queue.pop_front()
    }

    pub fn requeue_send(&mut self, datagram: Datagram) {
        self.send_queue.push_front(datagram)
    }
}

pub struct UdpIoContext<'a> {
    pub channel: &'a RwLock<UdpChannel>,
    pub node_db: &'a RwLock<NodeDatabase>,
}

impl<'a> UdpIoContext<'a> {
    pub fn new(
        channel: &'a RwLock<UdpChannel>, node_db: &'a RwLock<NodeDatabase>,
    ) -> UdpIoContext<'a> {
        UdpIoContext { channel, node_db }
    }

    pub fn send(&self, payload: Bytes, address: SocketAddr) {
        self.channel
            .write()
            .send_queue
            .push_back(Datagram { payload, address });
    }
}

/// NetworkService implements the P2P communication between different nodes. It
/// manages connections between peers, including accepting new peers or dropping
/// existing peers. Inside NetworkService, it has an IoService event loop with a
/// thread pool.
pub struct NetworkService {
    pub io_service: Option<IoService<NetworkIoMessage>>,
    pub inner: Option<Arc<NetworkServiceInner>>,
    network_poll: Arc<Poll>,
    config: NetworkConfiguration,
}

impl NetworkService {
    pub fn new(config: NetworkConfiguration) -> NetworkService {
        NetworkService {
            io_service: None,
            inner: None,
            network_poll: Arc::new(Poll::new().unwrap()),
            config,
        }
    }

    pub fn is_consortium(&self) -> bool { self.config.is_consortium }

    pub fn update_validator_info(&self, validator_set: HashSet<NodeId>) {
        if let Some(ref inner) = self.inner {
            inner.update_validator_info(validator_set)
        }
    }

    pub fn start_io_service(&mut self) -> Result<(), Error> {
        let raw_io_service =
            IoService::<NetworkIoMessage>::start(self.network_poll.clone())?;
        self.io_service = Some(raw_io_service);

        if self.inner.is_none() {
            if self.config.test_mode {
                BYPASS_CRYPTOGRAPHY.store(true, AtomicOrdering::Relaxed);
            }

            let inner = Arc::new(match self.config.test_mode {
                true => NetworkServiceInner::new_with_latency(&self.config)?,
                false => NetworkServiceInner::new(&self.config)?,
            });
            self.io_service
                .as_ref()
                .unwrap()
                .register_handler(inner.clone())?;
            self.inner = Some(inner);
        }
        Ok(())
    }

    pub fn start_network_poll(&self) -> Result<(), Error> {
        let handler = self.inner.as_ref().unwrap().clone();
        let main_event_loop_channel =
            self.io_service.as_ref().unwrap().channel();
        self.io_service
            .as_ref()
            .expect("Already set")
            .start_network_poll(
                self.network_poll.clone(),
                handler,
                main_event_loop_channel,
                MAX_SESSIONS,
                STOP_NET_POLL,
            );
        Ok(())
    }

    /// Create and start the event loop inside the NetworkService
    pub fn start(&mut self) -> Result<(), Error> {
        let raw_io_service =
            IoService::<NetworkIoMessage>::start(self.network_poll.clone())?;
        self.io_service = Some(raw_io_service);

        if self.inner.is_none() {
            if self.config.test_mode {
                BYPASS_CRYPTOGRAPHY.store(true, AtomicOrdering::Relaxed);
            }

            let inner = Arc::new(match self.config.test_mode {
                true => NetworkServiceInner::new_with_latency(&self.config)?,
                false => NetworkServiceInner::new(&self.config)?,
            });
            self.io_service
                .as_ref()
                .unwrap()
                .register_handler(inner.clone())?;
            self.inner = Some(inner);
        }

        let handler = self.inner.as_ref().unwrap().clone();
        let main_event_loop_channel =
            self.io_service.as_ref().unwrap().channel();
        self.io_service
            .as_ref()
            .expect("Already set")
            .start_network_poll(
                self.network_poll.clone(),
                handler,
                main_event_loop_channel,
                MAX_SESSIONS,
                STOP_NET_POLL,
            );
        Ok(())
    }

    /// Add a P2P peer to the client as a trusted node
    pub fn add_peer(&self, node: NodeEntry) -> Result<(), Error> {
        if let Some(ref x) = self.inner {
            x.node_db.write().insert_trusted(node);
            Ok(())
        } else {
            Err("Network service not started yet!".into())
        }
    }

    /// Drop a P2P peer from the client
    pub fn drop_peer(&self, node: NodeEntry) -> Result<(), Error> {
        if let Some(ref x) = self.inner {
            x.drop_node(node.id)
        } else {
            Err("Network service not started yet!".into())
        }
    }

    /// Get the local address of the client
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.as_ref().map(|inner_ref| inner_ref.local_addr())
    }

    /// Register a new protocol handler
    pub fn register_protocol(
        &self, handler: Arc<dyn NetworkProtocolHandler + Sync>,
        protocol: ProtocolId, versions: &[u8],
    ) -> Result<(), Error>
    {
        self.io_service.as_ref().unwrap().send_message(
            NetworkIoMessage::AddHandler {
                handler,
                protocol,
                versions: versions.to_vec(),
            },
        )?;
        Ok(())
    }

    /// Executes action in the network context
    pub fn with_context<F, R>(
        &self, protocol: ProtocolId, action: F,
    ) -> Result<R, String>
    where F: FnOnce(&NetworkContext) -> R {
        let io = IoContext::new(self.io_service.as_ref().unwrap().channel(), 0);
        match self.inner {
            Some(ref inner) => Ok(inner.with_context(protocol, &io, action)),
            None => Err("Network service not started yet!".to_owned().into()),
        }
    }

    /// Return the current connected peers
    pub fn get_peer_info(&self) -> Option<Vec<PeerInfo>> {
        self.inner.as_ref().map(|inner| inner.get_peer_info())
    }

    /// Sign a challenge to provide self NodeId
    pub fn sign_challenge(&self, challenge: Vec<u8>) -> Result<Vec<u8>, Error> {
        let hash = keccak(challenge);
        if let Some(ref inner) = self.inner {
            let signature = match sign(inner.metadata.keys.secret(), &hash) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Error signing hello packet");
                    return Err(Error::from(e));
                }
            };
            Ok(signature[..].to_owned())
        } else {
            Err("Network service not started yet!".into())
        }
    }

    pub fn net_key_pair(&self) -> Result<KeyPair, Error> {
        if let Some(ref inner) = self.inner {
            Ok(inner.metadata.keys.clone())
        } else {
            Err("Network service not started yet!".into())
        }
    }

    pub fn add_latency(
        &self, id: NodeId, latency_ms: f64,
    ) -> Result<(), Error> {
        if let Some(ref inner) = self.inner {
            inner.add_latency(id, latency_ms)
        } else {
            Err("Network service not started yet!".into())
        }
    }

    pub fn get_node(&self, id: &NodeId) -> Option<(bool, Node)> {
        let inner = self.inner.as_ref()?;
        let node_db = inner.node_db.read();
        let (trusted, node) = node_db.get_with_trusty(id)?;
        Some((trusted, node.clone()))
    }

    pub fn get_detailed_sessions(
        &self, node_id: Option<NodeId>,
    ) -> Option<Vec<SessionDetails>> {
        let inner = self.inner.as_ref()?;
        match node_id {
            None => Some(
                inner
                    .sessions
                    .all()
                    .iter()
                    .map(|s| s.read().details())
                    .collect(),
            ),
            Some(id) => {
                let session = inner.sessions.get_by_id(&id)?;
                let details = session.read().details();
                Some(vec![details])
            }
        }
    }

    pub fn disconnect_node(
        &self, id: &NodeId, op: Option<UpdateNodeOperation>,
    ) -> Option<usize> {
        let inner = self.inner.as_ref()?;
        let peer = inner.sessions.get_index_by_id(id)?;
        let io = IoContext::new(self.io_service.as_ref()?.channel(), 0);
        inner.kill_connection(
            peer,
            &io,
            true,
            op,
            "disconnect requested", // reason
        );
        Some(peer)
    }

    pub fn save_node_db(&self) {
        if let Some(inner) = &self.inner {
            inner.node_db.write().save();
        }
    }
}

type SharedSession = Arc<RwLock<Session>>;

pub struct HostMetadata {
    pub network_id: u64,
    /// Our private and public keys.
    pub keys: KeyPair,
    pub capabilities: RwLock<Vec<Capability>>,
    pub local_address: SocketAddr,
    /// Local address + discovery port
    pub local_endpoint: NodeEndpoint,
    /// Public address + discovery port
    pub public_endpoint: NodeEndpoint,
}

impl HostMetadata {
    pub(crate) fn secret(&self) -> &Secret { self.keys.secret() }

    pub(crate) fn id(&self) -> &NodeId { self.keys.public() }
}

#[derive(Copy, Clone)]
struct ProtocolTimer {
    pub protocol: ProtocolId,
    pub token: TimerToken, // Handler level token
}

/// The inner implementation of NetworkService. Note that all accesses to the
/// RWLocks of the fields have to follow the defined order to avoid race
pub struct NetworkServiceInner {
    pub sessions: SessionManager,
    pub metadata: HostMetadata,
    pub config: NetworkConfiguration,
    udp_socket: Mutex<UdpSocket>,
    tcp_listener: Mutex<TcpListener>,
    udp_channel: RwLock<UdpChannel>,
    discovery: Mutex<Option<Discovery>>,
    handlers:
        RwLock<HashMap<ProtocolId, Arc<dyn NetworkProtocolHandler + Sync>>>,
    timers: RwLock<HashMap<TimerToken, ProtocolTimer>>,
    timer_counter: RwLock<usize>,
    pub node_db: RwLock<NodeDatabase>,
    reserved_nodes: RwLock<HashSet<NodeId>>,
    dropped_nodes: RwLock<HashSet<StreamToken>>,

    is_consortium: bool,
    validator_set: RwLock<HashSet<NodeId>>,
    unconnected_validators: RwLock<HashSet<NodeId>>,

    /// Delayed message queue and corresponding latency
    delayed_queue: Option<DelayedQueue>,
}

struct DelayedQueue {
    queue: Mutex<BinaryHeap<DelayMessageContext>>,
    latencies: RwLock<HashMap<NodeId, Duration>>,
}

impl DelayedQueue {
    fn new() -> Self {
        DelayedQueue {
            queue: Mutex::new(BinaryHeap::new()),
            latencies: RwLock::new(HashMap::new()),
        }
    }

    fn send_delayed_messages(&self, network_service: &NetworkServiceInner) {
        let context = self.queue.lock().pop().unwrap();
        let r = context.session.write().send_packet(
            &context.io,
            Some(context.protocol),
            session::PACKET_USER,
            context.msg,
            context.priority,
        );
        match r {
            Ok(_) => {}
            Err(Error(ErrorKind::Expired, _)) => {
                // If a connection is set expired, it should have been killed
                // before, and the stored `context.peer` may have been reused by
                // another connection, so we cannot kill it again
                info!(
                    "Error sending delayed message to expired connection {:?}",
                    context.peer
                );
            }
            Err(e) => {
                info!(
                    "Error sending delayed message: peer={:?} err={:?}",
                    context.peer, e
                );
                network_service.kill_connection(
                    context.peer,
                    &context.io,
                    true,
                    Some(UpdateNodeOperation::Failure),
                    "failed to send delayed message", // reason
                );
            }
        };
    }
}

impl NetworkServiceInner {
    pub fn new(
        config: &NetworkConfiguration,
    ) -> Result<NetworkServiceInner, Error> {
        let mut listen_address = match config.listen_address {
            None => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                DEFAULT_PORT,
            )),
            Some(addr) => addr,
        };

        let keys = if let Some(ref secret) = config.use_secret {
            KeyPair::from_secret(secret.clone())?
        } else {
            config
                .config_path
                .clone()
                .and_then(|ref p| load_key(Path::new(&p)))
                .map_or_else(
                    || {
                        let key = Random
                            .generate()
                            .expect("Error generating random key pair");
                        if let Some(path) = config.config_path.clone() {
                            save_key(Path::new(&path), key.secret());
                        }
                        key
                    },
                    |s| {
                        KeyPair::from_secret(s)
                            .expect("Error creating node secret key")
                    },
                )
        };

        debug!("Self node id: {:?}", *keys.public());

        let tcp_listener = TcpListener::bind(&listen_address)?;
        listen_address = SocketAddr::new(
            listen_address.ip(),
            tcp_listener.local_addr()?.port(),
        );
        debug!("Listening at {:?}", listen_address);
        let udp_port = config.udp_port.unwrap_or_else(|| listen_address.port());
        let local_endpoint = NodeEndpoint {
            address: listen_address,
            udp_port,
        };
        let mut udp_addr = local_endpoint.address;
        udp_addr.set_port(local_endpoint.udp_port);
        let udp_socket =
            UdpSocket::bind(&udp_addr).expect("Error binding UDP socket");

        let public_address = config.public_address;
        let public_endpoint = match public_address {
            None => {
                let public_address =
                    select_public_address(local_endpoint.address.port());
                let public_endpoint = NodeEndpoint {
                    address: public_address,
                    udp_port: local_endpoint.udp_port,
                };
                if config.nat_enabled {
                    match map_external_address(&local_endpoint) {
                        Some(endpoint) => {
                            info!(
                                "NAT mapped to external address {}",
                                endpoint.address
                            );
                            endpoint
                        }
                        None => public_endpoint,
                    }
                } else {
                    public_endpoint
                }
            }
            Some(addr) => NodeEndpoint {
                address: addr,
                udp_port: local_endpoint.udp_port,
            },
        };

        let allow_ips = config.ip_filter.clone();
        let discovery = {
            if config.discovery_enabled {
                Some(Discovery::new(&keys, public_endpoint.clone(), allow_ips))
            } else {
                None
            }
        };

        let nodes_path = config.config_path.clone();

        let mut inner = NetworkServiceInner {
            metadata: HostMetadata {
                network_id: config.id,
                keys,
                capabilities: RwLock::new(Vec::new()),
                local_address: listen_address,
                local_endpoint,
                public_endpoint,
            },
            config: config.clone(),
            udp_channel: RwLock::new(UdpChannel::new()),
            discovery: Mutex::new(discovery),
            udp_socket: Mutex::new(udp_socket),
            tcp_listener: Mutex::new(tcp_listener),
            sessions: SessionManager::new(
                FIRST_SESSION,
                MAX_SESSIONS,
                config.max_incoming_peers,
                &config.session_ip_limit_config,
            ),
            handlers: RwLock::new(HashMap::new()),
            timers: RwLock::new(HashMap::new()),
            timer_counter: RwLock::new(HANDLER_TIMER),
            node_db: RwLock::new(NodeDatabase::new(
                nodes_path,
                config.subnet_quota,
            )),
            reserved_nodes: RwLock::new(HashSet::new()),
            dropped_nodes: RwLock::new(HashSet::new()),
            is_consortium: config.is_consortium,
            validator_set: RwLock::new(HashSet::new()),
            unconnected_validators: RwLock::new(HashSet::new()),
            delayed_queue: None,
        };

        for n in &config.boot_nodes {
            inner.add_boot_node(n);
        }

        let reserved_nodes = config.reserved_nodes.clone();
        for n in reserved_nodes {
            if let Err(e) = inner.add_reserved_node(&n) {
                debug!("Error parsing node id: {}: {:?}", n, e);
            }
        }

        Ok(inner)
    }

    pub fn update_validator_info(&self, new_validator_set: HashSet<NodeId>) {
        let mut validator_set = self.validator_set.write();
        let mut unconnected_validators = self.unconnected_validators.write();

        validator_set.clear();
        validator_set.extend(new_validator_set);

        let mut unconnected_non_validators = HashSet::new();
        for unconnected in unconnected_validators.iter() {
            if !validator_set.contains(unconnected) {
                unconnected_non_validators.insert(*unconnected);
            }
        }

        for unconnected in unconnected_non_validators.iter() {
            unconnected_validators.remove(unconnected);
        }

        let self_id = self.metadata.id().clone();
        for validator in validator_set.iter() {
            if *validator == self_id {
                continue;
            }

            if !self.sessions.contains_node(validator) {
                unconnected_validators.insert(*validator);
            }
        }
    }

    pub fn new_with_latency(
        config: &NetworkConfiguration,
    ) -> Result<NetworkServiceInner, Error> {
        let r = NetworkServiceInner::new(config);
        if r.is_err() {
            return r;
        }
        let mut inner = r.unwrap();
        inner.delayed_queue = Some(DelayedQueue::new());
        Ok(inner)
    }

    pub fn add_latency(
        &self, peer: NodeId, latency_ms: f64,
    ) -> Result<(), Error> {
        match self.delayed_queue {
            Some(ref queue) => {
                let mut latencies = queue.latencies.write();
                latencies
                    .insert(peer, Duration::from_millis(latency_ms as u64));
                Ok(())
            }
            None => Err(
                "conflux not in test mode, and does not support add_latency"
                    .into(),
            ),
        }
    }

    pub fn get_ip_filter(&self) -> &IpFilter { &self.config.ip_filter }

    fn add_boot_node(&self, id: &str) {
        match Node::from_str(id) {
            Err(e) => {
                debug!("Could not add node {}: {:?}", id, e);
            }
            Ok(n) => {
                self.node_db.write().insert_trusted(NodeEntry {
                    id: n.id,
                    endpoint: n.endpoint,
                });
            }
        }
    }

    fn add_reserved_node(&mut self, id: &str) -> Result<(), Error> {
        let n = Node::from_str(id)?;
        self.node_db.write().insert_trusted(NodeEntry {
            id: n.id.clone(),
            endpoint: n.endpoint.clone(),
        });
        self.reserved_nodes.write().insert(n.id);
        Ok(())
    }

    fn initialize_udp_protocols(
        &self, io: &IoContext<NetworkIoMessage>,
    ) -> Result<(), Error> {
        // Initialize discovery
        if let Some(discovery) = self.discovery.lock().as_mut() {
            let allow_ips = self.config.ip_filter.clone();
            let nodes = self
                .node_db
                .read()
                .sample_trusted_nodes(DISCOVER_NODES_COUNT, &allow_ips);
            discovery.try_ping_nodes(
                &UdpIoContext::new(&self.udp_channel, &self.node_db),
                nodes,
            );
            io.register_timer(
                FAST_DISCOVERY_REFRESH,
                self.config.fast_discovery_refresh_timeout,
            )?;
            io.register_timer(
                DISCOVERY_REFRESH,
                self.config.discovery_refresh_timeout,
            )?;
            io.register_timer(
                DISCOVERY_ROUND,
                self.config.discovery_round_timeout,
            )?;
        }
        io.register_timer(NODE_TABLE, self.config.node_table_timeout)?;
        io.register_timer(CHECK_SESSIONS, DEFAULT_CHECK_SESSIONS_TIMEOUT)?;

        Ok(())
    }

    fn try_promote_untrusted(&self) {
        // Get NodeIds from incoming connections
        let mut incoming_ids: Vec<NodeId> = Vec::new();
        for s in self.sessions.all() {
            if let Some(s) = s.try_read() {
                if s.is_ready() && !s.metadata.originated && !s.expired() {
                    // is live incoming connection
                    if let Some(id) = s.metadata.id {
                        incoming_ids.push(id);
                    }
                }
            }
        }

        // Check each live connection for its lifetime.
        // Promote the peers with live connection for a threshold period
        self.node_db.write().promote(
            incoming_ids,
            self.config.connection_lifetime_for_promotion,
        );
    }

    pub fn local_addr(&self) -> SocketAddr { self.metadata.local_address }

    fn drop_node(&self, local_id: NodeId) -> Result<(), Error> {
        let removed_node = self.node_db.write().remove(&local_id);

        if let Some(node) = removed_node {
            if let Some(stream_token) = node.stream_token {
                let mut wd = self.dropped_nodes.write();
                wd.insert(stream_token);
            }
        }

        Ok(())
    }

    fn has_enough_outgoing_peers(
        &self, tag: Option<(&str, &str)>, max: usize,
    ) -> bool {
        let count = match tag {
            Some((k, v)) => self.sessions.count_with_tag(&k.into(), &v.into()),
            None => self.sessions.stat().1, // egress count
        };

        count >= max
    }

    fn on_housekeeping(&self, io: &IoContext<NetworkIoMessage>) {
        if self.is_consortium {
            self.connect_validators(io);
        } else {
            self.connect_peers(io);
        }
        self.drop_peers(io);
    }

    fn connect_validators(&self, io: &IoContext<NetworkIoMessage>) {
        let self_id = self.metadata.id().clone();

        let unconnected_validators = self.unconnected_validators.read();
        for unconnected in unconnected_validators.iter() {
            if !self.sessions.contains_node(unconnected)
                && *unconnected != self_id
            {
                self.connect_peer(unconnected, io);
            }
        }
    }

    // Connect to all reserved and trusted peers if not yet
    fn connect_peers(&self, io: &IoContext<NetworkIoMessage>) {
        if self.metadata.capabilities.read().is_empty() {
            return;
        }

        let self_id = self.metadata.id().clone();

        let sampled_archive_nodes = self.sample_archive_nodes();

        let (handshake_count, egress_count, ingress_count) =
            self.sessions.stat();
        let samples;
        {
            let egress_attempt_count = if self.config.max_outgoing_peers
                > egress_count + sampled_archive_nodes.len()
            {
                self.config.max_outgoing_peers
                    - egress_count
                    - sampled_archive_nodes.len()
            } else {
                0
            };
            samples = self.node_db.read().sample_trusted_node_ids(
                egress_attempt_count as u32,
                &self.config.ip_filter,
            );
        }

        let reserved_nodes = self.reserved_nodes.read();
        // Try to connect all reserved peers and trusted peers
        let nodes = reserved_nodes
            .iter()
            .cloned()
            .chain(sampled_archive_nodes)
            .chain(samples);

        let max_handshakes_per_round = self.config.max_handshakes / 2;
        let mut started: usize = 0;
        for id in nodes
            .filter(|id| !self.sessions.contains_node(id) && *id != self_id)
            .take(min(
                max_handshakes_per_round,
                self.config.max_handshakes - handshake_count,
            ))
        {
            self.connect_peer(&id, io);
            started += 1;
        }
        debug!(
            "Connecting peers: {} sessions, {} pending + {} started",
            egress_count + ingress_count,
            handshake_count,
            started
        );
        if egress_count + ingress_count == 0 {
            warn!(
                "No peers connected at this moment, {} pending + {} started",
                handshake_count, started
            );
        }
    }

    /// Sample archive nodes for outgoing connections if not enough.
    fn sample_archive_nodes(&self) -> HashSet<NodeId> {
        if self.config.max_outgoing_peers_archive == 0 {
            return HashSet::new();
        }

        let key: String = NODE_TAG_NODE_TYPE.into();
        let value: String = NODE_TAG_ARCHIVE.into();
        let archive_sessions = self.sessions.count_with_tag(&key, &value);

        if archive_sessions >= self.config.max_outgoing_peers_archive {
            return HashSet::new();
        }

        self.node_db.read().sample_trusted_node_ids_with_tag(
            (self.config.max_outgoing_peers_archive - archive_sessions) as u32,
            &key,
            &value,
        )
    }

    // Kill connections of all dropped peers
    fn drop_peers(&self, io: &IoContext<NetworkIoMessage>) {
        {
            if self.dropped_nodes.read().len() == 0 {
                return;
            }
        }

        let mut w = self.dropped_nodes.write();
        for token in w.iter() {
            self.kill_connection(
                *token,
                io,
                true,
                Some(UpdateNodeOperation::Failure),
                "peer dropped in manual", // reason
            );
        }
        w.clear();
    }

    fn connect_peer(&self, id: &NodeId, io: &IoContext<NetworkIoMessage>) {
        if self.sessions.contains_node(id) {
            trace!("Abort connect. Node already connected");
            return;
        }

        let (socket, address) = {
            let address = {
                // outgoing connection must pick node from trusted node table
                if let Some(node) = self.node_db.read().get(id, true) {
                    node.endpoint.address
                } else {
                    debug!("Abort connect. Node expired");
                    return;
                }
            };

            if !self.sessions.is_ip_allowed(&address.ip()) {
                debug!("cannot create outgoing connection to node, id = {:?}, address = {:?}", id, address);
                return;
            }

            match TcpStream::connect(&address) {
                Ok(socket) => {
                    trace!("{}: connecting to {:?}", id, address);
                    (socket, address)
                }
                Err(e) => {
                    self.node_db.write().note_failure(
                        id, true, /* by_connection */
                        true, /* trusted_only */
                    );
                    debug!(
                        "{}: can't connect o address {:?} {:?}",
                        id, address, e
                    );
                    return;
                }
            }
        };

        if let Err(e) = self.create_connection(socket, address, Some(id), io) {
            self.node_db.write().note_failure(
                id, true, /* by_connection */
                true, /* trusted_only */
            );
            debug!("Can't create connection: {:?}", e);
        }
    }

    pub fn get_peer_info(&self) -> Vec<PeerInfo> {
        debug!("get_peer_info: enter");

        let mut peers = Vec::with_capacity(self.sessions.count());
        debug!("get_peer_info: {} sessions in total", peers.capacity());

        for session in self.sessions.all() {
            let sess = session.read();
            if !sess.expired() {
                peers.push(PeerInfo {
                    id: sess.token(),
                    nodeid: sess.id().unwrap_or(&NodeId::default()).clone(),
                    addr: sess.address(),
                    caps: sess.metadata.peer_capabilities.clone(),
                });
            }
        }

        debug!("get_peer_info: leave, {} peers retrieved", peers.len());

        peers
    }

    pub fn get_peer_node_id(&self, peer: PeerId) -> NodeId {
        match self.sessions.get(peer) {
            Some(session) => {
                let sess = session.read();
                sess.id().unwrap_or(&NodeId::default()).clone()
            }
            None => NodeId::default(),
        }
    }

    pub fn get_peer_connection_origin(&self, peer: PeerId) -> Option<bool> {
        match self.sessions.get(peer) {
            Some(session) => {
                let sess = session.read();
                Some(sess.originated())
            }
            None => None,
        }
    }

    fn start(&self, io: &IoContext<NetworkIoMessage>) -> Result<(), Error> {
        self.initialize_udp_protocols(io)?;
        io.register_stream(UDP_MESSAGE)?;
        io.register_stream(TCP_ACCEPT)?;
        Ok(())
    }

    // This function can be invoked in either of 2 cases:
    // 1. proactively connect to a peer;
    // 2. passively connected by a peer;
    fn create_connection(
        &self, socket: TcpStream, address: SocketAddr, id: Option<&NodeId>,
        io: &IoContext<NetworkIoMessage>,
    ) -> Result<(), Error>
    {
        match self.sessions.create(socket, address, id, io, self) {
            Ok(token) => {
                debug!("new session created, token = {}, address = {:?}, id = {:?}", token, address, id);
                if let Some(id) = id {
                    // This is an outgoing connection.
                    // Outgoing connection must pick node from trusted node
                    // table
                    self.node_db.write().note_success(id, Some(token), true);
                }
                io.register_stream(token).map(|_| ()).map_err(Into::into)
            }
            Err(reason) => {
                debug!("failed to create session, reason = {}, address = {:?}, id = {:?}", reason, address, id);
                Ok(())
            }
        }
    }

    fn connection_closed(
        &self, stream: StreamToken, io: &IoContext<NetworkIoMessage>,
    ) {
        trace!("Connection closed: {}", stream);
        self.kill_connection(
            stream,
            io,
            true,
            Some(UpdateNodeOperation::Failure),
            "connection closed", // reason
        );
    }

    fn session_readable(
        &self, stream: StreamToken, io: &IoContext<NetworkIoMessage>,
    ) {
        // We check dropped_nodes first to make sure we stop processing
        // communications from any dropped peers
        let to_drop = { self.dropped_nodes.read().contains(&stream) };
        self.drop_peers(io);
        if to_drop {
            return;
        }

        let mut ready_protocols: Vec<ProtocolId> = Vec::new();
        let mut messages: Vec<(ProtocolId, Vec<u8>)> = Vec::new();
        let mut kill = false;

        // if let Some(session) = session.clone()
        if let Some(session) = self.sessions.get(stream) {
            loop {
                let mut sess = session.write();
                let data = sess.readable(io, self);
                match data {
                    Ok(SessionData::Ready) => {
                        //let mut sess = session.lock();
                        for (protocol, _) in self.handlers.read().iter() {
                            if sess.have_capability(*protocol) {
                                ready_protocols.push(*protocol);
                            }
                        }
                    }
                    Ok(SessionData::Message { data, protocol }) => {
                        match self.handlers.read().get(&protocol) {
                            None => warn!(
                                "No handler found for protocol: {:?}",
                                protocol
                            ),
                            Some(_) => messages.push((protocol, data)),
                        }
                    }
                    Ok(SessionData::None) => break,
                    Ok(SessionData::Continue) => {}
                    Err(Error(kind, _)) => {
                        debug!("Failed to read session data, error kind = {:?}, session = {:?}", kind, *sess);
                        kill = true;
                        break;
                    }
                }
            }
        }

        if kill {
            self.kill_connection(
                stream,
                io,
                true,
                Some(UpdateNodeOperation::Failure),
                "session readable error", // reason
            );
        }

        if !ready_protocols.is_empty() {
            {
                let handlers = self.handlers.read();
                for protocol in ready_protocols {
                    if let Some(handler) = handlers.get(&protocol).clone() {
                        debug!("session handshaked, token = {}", stream);
                        handler.on_peer_connected(
                            &NetworkContext::new(io, protocol, self),
                            stream,
                        );
                    }
                }
            }

            if self.is_consortium {
                let validator_set = self.validator_set.read();
                let mut unconnected_validators =
                    self.unconnected_validators.write();
                let node_id = self.get_peer_node_id(stream);
                if validator_set.contains(&node_id) {
                    unconnected_validators.remove(&node_id);
                }
            }
        }

        for (protocol, data) in messages {
            io.handle(
                stream,
                0, /* We only have one handler for the execution event_loop,
                    * so the handler_id is always 0 */
                NetworkIoMessage::HandleProtocolMessage {
                    protocol,
                    peer: stream,
                    data,
                },
            )
            .expect("Fail to send NetworkIoMessage::HandleNetworkWork");
        }
    }

    fn session_writable(
        &self, stream: StreamToken, io: &IoContext<NetworkIoMessage>,
    ) {
        // We check dropped_nodes first to make sure we stop processing
        // communications from any dropped peers
        let to_drop = { self.dropped_nodes.read().contains(&stream) };
        if to_drop {
            self.drop_peers(io);
        }

        if let Some(session) = self.sessions.get(stream) {
            let mut sess = session.write();
            if let Err(e) = sess.writable(io) {
                trace!("{}: Session write error: {:?}", stream, e);
            }
            if sess.done() {
                io.deregister_stream(stream).unwrap_or_else(|e| {
                    debug!("Error deregistering stream: {:?}", e)
                });
            }
        }
    }

    fn accept(&self, io: &IoContext<NetworkIoMessage>) {
        trace!("Accepting incoming connection");
        loop {
            let (socket, address) = match self.tcp_listener.lock().accept() {
                Ok((sock, addr)) => (sock, addr),
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        debug!("Error accepting connection: {:?}", e);
                    }
                    break;
                }
            };

            if let Err(e) = self.create_connection(socket, address, None, io) {
                debug!("Can't accept connection: {:?}", e);
            }
        }
    }

    fn kill_connection(
        &self, token: StreamToken, io: &IoContext<NetworkIoMessage>,
        remote: bool, op: Option<UpdateNodeOperation>, reason: &str,
    )
    {
        let mut to_disconnect: Vec<ProtocolId> = Vec::new();
        let mut failure_id = None;
        let mut deregister = false;
        let node_id = self.get_peer_node_id(token);

        if let FIRST_SESSION..=LAST_SESSION = token {
            if let Some(session) = self.sessions.get(token) {
                let mut sess = session.write();
                if !sess.expired() {
                    if sess.is_ready() {
                        for (p, _) in self.handlers.read().iter() {
                            if sess.have_capability(*p) {
                                to_disconnect.push(*p);
                                sess.send_disconnect(DisconnectReason::Custom(
                                    reason.into(),
                                ));
                            }
                        }
                    }
                    sess.set_expired();
                }
                deregister = remote || sess.done();
                failure_id = sess.id().cloned();
                debug!(
                    "kill connection, deregister = {}, reason = {:?}, session = {:?}, op = {:?}",
                    deregister, reason, *sess, op
                );
            }
        }

        if let Some(id) = failure_id {
            if remote {
                if let Some(op) = op {
                    match op {
                        UpdateNodeOperation::Failure => {
                            self.node_db.write().note_failure(
                                &id, true,  /* by_connection */
                                false, /* trusted_only */
                            );
                        }
                        UpdateNodeOperation::Demotion => {
                            self.node_db.write().demote(&id);
                            self.node_db.write().note_failure(
                                &id, true,  /* by_connection */
                                false, /* trusted_only */
                            );
                        }
                        UpdateNodeOperation::Remove => {
                            self.node_db.write().set_blacklisted(&id);
                        }
                    }
                }
            }
        }

        for p in to_disconnect {
            if let Some(h) = self.handlers.read().get(&p).clone() {
                h.on_peer_disconnected(
                    &NetworkContext::new(io, p, self),
                    token,
                );
            }
        }

        if deregister {
            io.deregister_stream(token).unwrap_or_else(|e| {
                debug!("Error deregistering stream {:?}", e);
            });

            if self.is_consortium {
                let validator_set = self.validator_set.read();
                let mut unconnected_validators =
                    self.unconnected_validators.write();
                if validator_set.contains(&node_id) {
                    unconnected_validators.insert(node_id);
                }
            }
        }
    }

    pub fn with_context<F, R>(
        &self, protocol: ProtocolId, io: &IoContext<NetworkIoMessage>,
        action: F,
    ) -> R
    where
        F: FnOnce(&NetworkContext) -> R,
    {
        let context = NetworkContext::new(io, protocol, self);
        action(&context)
    }

    fn udp_readable(&self, io: &IoContext<NetworkIoMessage>) {
        let udp_socket = self.udp_socket.lock();
        let writable;
        {
            let udp_channel = self.udp_channel.read();
            writable = udp_channel.any_sends_queued();
        }

        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        match udp_socket.recv_from(&mut buf) {
            Ok(Some((len, address))) => self
                .on_udp_packet(&buf[0..len], address)
                .unwrap_or_else(|e| {
                    debug!("Error processing UDP packet: {:?}", e);
                }),
            Ok(_) => {}
            Err(e) => {
                debug!("Error reading UDP socket: {:?}", e);
            }
        };

        let new_writable;
        {
            let udp_channel = self.udp_channel.read();
            new_writable = udp_channel.any_sends_queued();
        }

        // Check whether on_udp_packet produces new to-be-sent messages.
        // If it does, we might need to change monitor interest to All if
        // it is only Readable.
        if writable != new_writable {
            io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
                debug!("Error updating UDP registration: {:?}", e)
            });
        }
    }

    fn udp_writable(&self, io: &IoContext<NetworkIoMessage>) {
        let udp_socket = self.udp_socket.lock();
        let mut udp_channel = self.udp_channel.write();
        while let Some(data) = udp_channel.dequeue_send() {
            match udp_socket.send_to(&data.payload, &data.address) {
                Ok(Some(size)) if size == data.payload.len() => {}
                Ok(Some(_)) => {
                    warn!("UDP sent incomplete datagram");
                }
                Ok(None) => {
                    udp_channel.requeue_send(data);
                    return;
                }
                Err(e) => {
                    debug!(
                        "UDP send error: {:?}, address: {:?}",
                        e, &data.address
                    );
                    return;
                }
            }
        }
        // look at whether the monitor interest can be set as Readable.
        io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
            debug!("Error updating UDP registration: {:?}", e)
        });
    }

    fn on_udp_packet(
        &self, packet: &[u8], from: SocketAddr,
    ) -> Result<(), Error> {
        if packet.is_empty() {
            return Ok(());
        }

        let res = match packet[0] {
            UDP_PROTOCOL_DISCOVERY => {
                if let Some(discovery) = self.discovery.lock().as_mut() {
                    discovery.on_packet(
                        &UdpIoContext::new(&self.udp_channel, &self.node_db),
                        &packet[1..],
                        from,
                    )?;
                    Ok(())
                } else {
                    warn!("Discovery is not ready. Drop the message!");
                    Ok(())
                }
            }
            _ => {
                warn!("Unknown UDP protocol. Simply drops the message!");
                Ok(())
            }
        };
        res
    }

    fn on_check_sessions(&self, io: &IoContext<NetworkIoMessage>) {
        let mut disconnect_peers = Vec::new();

        for session in self.sessions.all() {
            if let Some(sess) = session.try_read() {
                if let (true, op) = sess.check_timeout() {
                    disconnect_peers.push((sess.token(), op));
                }
            }
        }

        for (token, op) in disconnect_peers {
            self.kill_connection(
                token,
                io,
                true,
                op,
                "session timeout", // reason
            );
        }
    }
}

impl IoHandler<NetworkIoMessage> for NetworkServiceInner {
    fn initialize(&self, io: &IoContext<NetworkIoMessage>) {
        io.register_timer(HOUSEKEEPING, self.config.housekeeping_timeout)
            .expect("Error registering housekeeping timer");
        io.message(NetworkIoMessage::Start).unwrap_or_else(|e| {
            warn!("Error sending IO notification: {:?}", e)
        });
        self.on_housekeeping(io);
    }

    fn stream_hup(
        &self, io: &IoContext<NetworkIoMessage>, stream: StreamToken,
    ) {
        trace!("Hup: {}", stream);
        match stream {
            FIRST_SESSION..=LAST_SESSION => self.connection_closed(stream, io),
            _ => warn!("Unexpected hup"),
        }
    }

    fn stream_readable(
        &self, io: &IoContext<NetworkIoMessage>, stream: StreamToken,
    ) {
        match stream {
            FIRST_SESSION..=LAST_SESSION => self.session_readable(stream, io),
            TCP_ACCEPT => self.accept(io),
            UDP_MESSAGE => self.udp_readable(io),
            _ => panic!("Received unknown readable token"),
        }
    }

    fn stream_writable(
        &self, io: &IoContext<NetworkIoMessage>, stream: StreamToken,
    ) {
        match stream {
            FIRST_SESSION..=LAST_SESSION => self.session_writable(stream, io),
            UDP_MESSAGE => self.udp_writable(io),
            _ => panic!("Received unknown writable token"),
        }
    }

    fn timeout(&self, io: &IoContext<NetworkIoMessage>, token: TimerToken) {
        match token {
            FIRST_SESSION..=LAST_SESSION => {
                debug!("Connection timeout: {}", token);
                self.kill_connection(
                    token,
                    io,
                    true,
                    Some(UpdateNodeOperation::Failure),
                    "handshake timeout", // reason
                );
            }
            HOUSEKEEPING => self.on_housekeeping(io),
            DISCOVERY_REFRESH => {
                // Run the _slow_ discovery if enough peers are connected
                let disc_general = self.has_enough_outgoing_peers(
                    None,
                    self.config.max_outgoing_peers,
                );
                let disc_archive = self.has_enough_outgoing_peers(
                    Some((NODE_TAG_NODE_TYPE, NODE_TAG_ARCHIVE)),
                    self.config.max_outgoing_peers_archive,
                );
                if disc_general || disc_archive {
                    self.discovery.lock().as_mut().map(|d| {
                        d.disc_option.general = disc_general;
                        d.disc_option.archive = disc_archive;
                        d.refresh();
                    });
                    io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
                        debug!("Error updating discovery registration: {:?}", e)
                    });
                }
            }
            FAST_DISCOVERY_REFRESH => {
                // Run the fast discovery if not enough peers are connected
                let disc_general = !self.has_enough_outgoing_peers(
                    None,
                    self.config.max_outgoing_peers,
                );
                let disc_archive = !self.has_enough_outgoing_peers(
                    Some((NODE_TAG_NODE_TYPE, NODE_TAG_ARCHIVE)),
                    self.config.max_outgoing_peers_archive,
                );
                if disc_general || disc_archive {
                    self.discovery.lock().as_mut().map(|d| {
                        d.disc_option.general = disc_general;
                        d.disc_option.archive = disc_archive;
                        d.refresh();
                    });
                    io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
                        debug!("Error updating discovery registration: {:?}", e)
                    });
                }
            }
            DISCOVERY_ROUND => {
                if let Some(d) = self.discovery.lock().as_mut() {
                    d.round(&UdpIoContext::new(
                        &self.udp_channel,
                        &self.node_db,
                    ))
                }
                io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
                    debug!("Error updating discovery registration: {:?}", e)
                });
            }
            NODE_TABLE => {
                trace!("Refreshing node table");
                self.try_promote_untrusted();
                self.node_db.write().save();
            }
            CHECK_SESSIONS => self.on_check_sessions(io),
            SEND_DELAYED_MESSAGES => {
                if let Some(ref queue) = self.delayed_queue {
                    queue.send_delayed_messages(self);
                }
            }
            _ => match self.timers.read().get(&token).cloned() {
                Some(timer) => {
                    match self.handlers.read().get(&timer.protocol).cloned() {
                        None => warn!(
                            "No handler found for protocol: {:?}",
                            timer.protocol
                        ),
                        Some(h) => {
                            h.on_timeout(
                                &NetworkContext::new(io, timer.protocol, self),
                                timer.token,
                            );
                        }
                    }
                }
                None => {
                    warn!("Unknown timer token: {}", token);
                } // timer is not registered through us
            },
        }
    }

    fn message(
        &self, io: &IoContext<NetworkIoMessage>, message: &NetworkIoMessage,
    ) {
        match *message {
            NetworkIoMessage::Start => self.start(io).unwrap_or_else(|e| {
                warn!("Error starting network service: {:?}", e)
            }),
            NetworkIoMessage::AddHandler {
                ref handler,
                ref protocol,
                ref versions,
            } => {
                let h = handler.clone();
                h.initialize(&NetworkContext::new(io, *protocol, self));
                self.handlers.write().insert(*protocol, h);
                let mut caps = self.metadata.capabilities.write();
                for &version in versions {
                    caps.push(Capability {
                        protocol: *protocol,
                        version,
                    });
                }
            }
            NetworkIoMessage::AddTimer {
                ref protocol,
                ref delay,
                ref token,
            } => {
                let handler_token = {
                    let mut timer_counter = self.timer_counter.write();
                    let counter = &mut *timer_counter;
                    let handler_token = *counter;
                    *counter += 1;
                    handler_token
                };
                self.timers.write().insert(
                    handler_token,
                    ProtocolTimer {
                        protocol: *protocol,
                        token: *token,
                    },
                );
                io.register_timer(handler_token, *delay)
                    .unwrap_or_else(|e| {
                        debug!("Error registering timer {}: {:?}", token, e)
                    });
            }
            NetworkIoMessage::DispatchWork {
                ref protocol,
                ref work_type,
            } => {
                if let Some(handler) = self.handlers.read().get(protocol) {
                    handler.on_work_dispatch(
                        &NetworkContext::new(io, *protocol, self),
                        *work_type,
                    );
                } else {
                    warn!("Work is dispatched to unknown handler");
                }
            }
            NetworkIoMessage::HandleProtocolMessage {
                ref protocol,
                ref peer,
                ref data,
            } => {
                if let Some(handler) = self.handlers.read().get(protocol) {
                    handler.on_message(
                        &NetworkContext::new(io, *protocol, self),
                        *peer,
                        data,
                    );
                } else {
                    warn!("Work is handled by unknown handler");
                }
            }
        }
    }

    fn register_stream(
        &self, stream: StreamToken, reg: Token, event_loop: &Poll,
    ) {
        match stream {
            FIRST_SESSION..=LAST_SESSION => {
                if let Some(session) = self.sessions.get(stream) {
                    session
                        .write()
                        .register_socket(reg, event_loop)
                        .expect("Error registering socket");
                }
            }
            TCP_ACCEPT => {
                event_loop
                    .register(
                        &*self.tcp_listener.lock(),
                        Token(TCP_ACCEPT),
                        Ready::all(),
                        PollOpt::edge(),
                    )
                    .expect("Error registering stream");
            }
            UDP_MESSAGE => {
                event_loop
                    .register(
                        &*self.udp_socket.lock(),
                        reg,
                        Ready::all(),
                        PollOpt::edge(),
                    )
                    .expect("Error registering UDP socket");
            }
            _ => warn!("Unexpected stream registeration"),
        }
    }

    fn deregister_stream(&self, stream: StreamToken, event_loop: &Poll) {
        match stream {
            FIRST_SESSION..=LAST_SESSION => {
                if let Some(session) = self.sessions.get(stream) {
                    let sess = session.write();
                    if sess.expired() {
                        sess.deregister_socket(event_loop)
                            .expect("Error deregistering socket");
                        if let Some(node_id) = sess.id() {
                            self.node_db.write().note_failure(
                                node_id, true,  /* by_connection */
                                false, /* trusted_only */
                            );
                        }
                        self.sessions.remove(&*sess);
                        debug!("Removed session: {:?}", *sess);
                    }
                }
            }
            _ => warn!("Unexpected stream deregistration"),
        }
    }

    fn update_stream(
        &self, stream: StreamToken, reg: Token, event_loop: &Poll,
    ) {
        match stream {
            FIRST_SESSION..=LAST_SESSION => {
                if let Some(session) = self.sessions.get(stream) {
                    session
                        .write()
                        .update_socket(reg, event_loop)
                        .expect("Error updating socket");
                }
            }
            TCP_ACCEPT => event_loop
                .reregister(
                    &*self.tcp_listener.lock(),
                    Token(TCP_ACCEPT),
                    Ready::all(),
                    PollOpt::edge(),
                )
                .expect("Error reregistering stream"),
            UDP_MESSAGE => {
                let udp_socket = self.udp_socket.lock();
                let udp_channel = self.udp_channel.read();

                let registration = if udp_channel.any_sends_queued() {
                    Ready::readable() | Ready::writable()
                } else {
                    Ready::readable()
                };
                event_loop
                    .reregister(
                        &*udp_socket,
                        reg,
                        registration,
                        PollOpt::edge(),
                    )
                    .expect("Error reregistering UDP socket");
            }
            _ => warn!("Unexpected stream update"),
        }
    }
}

struct DelayMessageContext {
    ts: Instant,
    io: IoContext<NetworkIoMessage>,
    protocol: ProtocolId,
    session: SharedSession,
    peer: PeerId,
    msg: Vec<u8>,
    priority: SendQueuePriority,
}

impl DelayMessageContext {
    pub fn new(
        ts: Instant, io: IoContext<NetworkIoMessage>, protocol: ProtocolId,
        session: SharedSession, peer: PeerId, msg: Vec<u8>,
        priority: SendQueuePriority,
    ) -> Self
    {
        DelayMessageContext {
            ts,
            io,
            protocol,
            session,
            peer,
            msg,
            priority,
        }
    }
}

impl Ord for DelayMessageContext {
    fn cmp(&self, other: &Self) -> Ordering { other.ts.cmp(&self.ts) }
}

impl PartialOrd for DelayMessageContext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.ts.partial_cmp(&self.ts)
    }
}

impl Eq for DelayMessageContext {}

impl PartialEq for DelayMessageContext {
    fn eq(&self, other: &Self) -> bool { self.ts == other.ts }
}

pub struct NetworkContext<'a> {
    io: &'a IoContext<NetworkIoMessage>,
    protocol: ProtocolId,
    network_service: &'a NetworkServiceInner,
}

impl<'a> NetworkContext<'a> {
    pub fn new(
        io: &'a IoContext<NetworkIoMessage>, protocol: ProtocolId,
        network_service: &'a NetworkServiceInner,
    ) -> NetworkContext<'a>
    {
        NetworkContext {
            io,
            protocol,
            network_service,
        }
    }
}

impl<'a> NetworkContextTrait for NetworkContext<'a> {
    fn get_peer_node_id(&self, peer: PeerId) -> NodeId {
        self.network_service.get_peer_node_id(peer)
    }

    fn get_protocol(&self) -> ProtocolId { self.protocol.clone() }

    fn get_peer_connection_origin(&self, peer: PeerId) -> Option<bool> {
        self.network_service.get_peer_connection_origin(peer)
    }

    fn send(
        &self, peer: PeerId, msg: Vec<u8>, priority: SendQueuePriority,
    ) -> Result<(), Error> {
        if peer == NULL {
            let protocol_handler = self
                .network_service
                .handlers
                .read()
                .get(&self.protocol)
                .unwrap()
                .clone();

            protocol_handler.send_local_message(self, msg);
            return Ok(());
        }

        let session = self.network_service.sessions.get(peer);
        trace!("Sending {} bytes to {}", msg.len(), peer);
        if let Some(session) = session {
            let latency =
                self.network_service.delayed_queue.as_ref().and_then(|q| {
                    session
                        .write()
                        .metadata
                        .id
                        .and_then(|id| q.latencies.read().get(&id).copied())
                });
            match latency {
                Some(latency) => {
                    let q =
                        self.network_service.delayed_queue.as_ref().unwrap();
                    let mut queue = q.queue.lock();
                    let ts_to_send = Instant::now() + latency;
                    queue.push(DelayMessageContext::new(
                        ts_to_send,
                        self.io.clone(),
                        self.protocol,
                        session,
                        peer,
                        msg,
                        priority,
                    ));
                    self.io.register_timer_once_nocancel(
                        SEND_DELAYED_MESSAGES,
                        latency,
                    )?;
                    trace!("register delayed timer delay:{:?} ts_to_send:{:?} length:{}", latency, ts_to_send, queue.len());
                }
                None => {
                    session.write().send_packet(
                        self.io,
                        Some(self.protocol),
                        session::PACKET_USER,
                        msg,
                        priority,
                    )?;
                }
            }
            // TODO: Handle result from send_packet()
        }
        Ok(())
    }

    fn disconnect_peer(
        &self, peer: PeerId, op: Option<UpdateNodeOperation>, reason: &str,
    ) {
        self.network_service
            .kill_connection(peer, self.io, true, op, reason);
    }

    fn register_timer(
        &self, token: TimerToken, delay: Duration,
    ) -> Result<(), Error> {
        self.io
            .message(NetworkIoMessage::AddTimer {
                token,
                delay,
                protocol: self.protocol,
            })
            .unwrap_or_else(|e| {
                warn!("Error sending network IO message: {:?}", e)
            });
        Ok(())
    }

    fn dispatch_work(&self, work_type: HandlerWorkType) {
        self.io
            .message(NetworkIoMessage::DispatchWork {
                protocol: self.protocol,
                work_type,
            })
            .expect("Error sending network IO message");
    }

    fn insert_peer_node_tag(&self, peer: PeerId, key: &str, value: &str) {
        let id = self.network_service.get_peer_node_id(peer);
        self.network_service.node_db.write().set_tag(id, key, value);
        self.network_service
            .sessions
            .add_tag(peer, key.into(), value.into());
    }
}

fn save_key(path: &Path, key: &Secret) {
    let mut path_buf = PathBuf::from(path);
    if let Err(e) = fs::create_dir_all(path_buf.as_path()) {
        warn!("Error creating key directory: {:?}", e);
        return;
    };
    path_buf.push("key");
    let path = path_buf.as_path();
    let mut file = match fs::File::create(&path) {
        Ok(file) => file,
        Err(e) => {
            warn!("Error creating key file: {:?}", e);
            return;
        }
    };
    if let Err(e) = restrict_permissions_owner(path, true, false) {
        warn!("Failed to modify permissions of the file ({})", e);
    }
    if let Err(e) = file.write(&key.to_hex().into_bytes()) {
        warn!("Error writing key file: {:?}", e);
    }
}

fn load_key(path: &Path) -> Option<Secret> {
    let mut path_buf = PathBuf::from(path);
    path_buf.push("key");
    let mut file = match fs::File::open(path_buf.as_path()) {
        Ok(file) => file,
        Err(e) => {
            debug!("failed to open key file: {:?}", e);
            return None;
        }
    };
    let mut buf = String::new();
    match file.read_to_string(&mut buf) {
        Ok(_) => {}
        Err(e) => {
            warn!("Error reading key file: {:?}", e);
            return None;
        }
    }
    match Secret::from_str(&buf) {
        Ok(key) => Some(key),
        Err(e) => {
            warn!("Error parsing key file: {:?}", e);
            None
        }
    }
}
