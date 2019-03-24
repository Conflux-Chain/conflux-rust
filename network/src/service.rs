// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    discovery::{Discovery, DISCOVER_NODES_COUNT},
    io::*,
    ip_utils::{map_external_address, select_public_address},
    node_table::*,
    session::{self, Session, SessionData},
    Capability, DisconnectReason, Error, IpFilter, NetworkConfiguration,
    NetworkContext as NetworkContextTrait, NetworkIoMessage,
    NetworkProtocolHandler, PeerId, PeerInfo, ProtocolId,
};
use cfx_bytes::Bytes;
use keccak_hash::keccak;
use keylib::{sign, Generator, KeyPair, Random, Secret};
use mio::{deprecated::EventLoop, tcp::*, udp::*, *};
use parity_path::restrict_permissions_owner;
use parking_lot::{Mutex, RwLock};
use std::{
    cmp::{min, Ordering},
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

type Slab<T> = ::slab::Slab<T, usize>;

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
const HANDLER_TIMER: TimerToken = LAST_SESSION + 256;

pub const DEFAULT_HOUSEKEEPING_TIMEOUT: Duration = Duration::from_secs(1);
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
    pub trusted_nodes: &'a RwLock<NodeTable>,
    pub untrusted_nodes: &'a RwLock<NodeTable>,
}

impl<'a> UdpIoContext<'a> {
    pub fn new(
        channel: &'a RwLock<UdpChannel>, trusted_nodes: &'a RwLock<NodeTable>,
        untrusted_nodes: &'a RwLock<NodeTable>,
    ) -> UdpIoContext<'a>
    {
        UdpIoContext {
            channel,
            trusted_nodes,
            untrusted_nodes,
        }
    }

    pub fn send(&self, payload: Bytes, address: SocketAddr) {
        self.channel
            .write()
            .send_queue
            .push_back(Datagram { payload, address });
    }

    // Discover trusted peer from discovery protocol.
    pub fn discover_trusted_node(&self, node: &NodeEntry) {
        let mut trusted = self.trusted_nodes.write();
        let mut untrusted = self.untrusted_nodes.write();

        if trusted.contains(&node.id) {
            trusted.note_success(&node.id, false, None);
            debug_assert!(!untrusted.contains(&node.id));
        } else {
            let mut trusted_node = Node::new(node.id, node.endpoint.clone());
            trusted_node.last_contact = Some(NodeContact::success());
            if let Some(removed_node) = untrusted.remove_with_id(&node.id) {
                trusted_node.last_connected = removed_node.last_connected;
                trusted_node.stream_token = removed_node.stream_token;
            }
            trusted.add_node(trusted_node, false);
        }
    }
}

/// NetworkService implements the P2P communication between different nodes. It
/// manages connections between peers, including accepting new peers or dropping
/// existing peers. Inside NetworkService, it has an IoService event loop with a
/// thread pool.
pub struct NetworkService {
    io_service: Option<IoService<NetworkIoMessage>>,
    inner: Option<Arc<NetworkServiceInner>>,
    config: NetworkConfiguration,
}

impl NetworkService {
    pub fn new(config: NetworkConfiguration) -> NetworkService {
        NetworkService {
            io_service: None,
            inner: None,
            config,
        }
    }

    /// Create and start the event loop inside the NetworkService
    pub fn start(&mut self) -> Result<(), Error> {
        let raw_io_service = IoService::<NetworkIoMessage>::start()?;
        self.io_service = Some(raw_io_service);

        if self.inner.is_none() {
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

    /// Add a P2P peer to the client as a trusted node
    pub fn add_peer(&self, node: NodeEntry) -> Result<(), Error> {
        if let Some(ref x) = self.inner {
            x.add_trusted_node_with_entry(node);
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
        &self, handler: Arc<NetworkProtocolHandler + Sync>,
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
    pub fn with_context<F>(&self, protocol: ProtocolId, action: F)
    where F: FnOnce(&NetworkContext) {
        let io = IoContext::new(self.io_service.as_ref().unwrap().channel(), 0);
        if let Some(ref inner) = self.inner {
            inner.with_context(protocol, &io, action);
        };
    }

    /// Return the current connected peers
    pub fn get_peer_info(&self) -> Option<Vec<PeerInfo>> {
        self.inner.as_ref().map(|inner| inner.get_peer_info())
    }

    /// Sign a challenge to provide self NodeId
    pub fn sign_challenge(&self, challenge: Vec<u8>) -> Result<Vec<u8>, Error> {
        let hash = keccak(challenge);
        if let Some(ref inner) = self.inner {
            let signature =
                match sign(inner.metadata.read().keys.secret(), &hash) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(target: "network", "Error signing hello packet");
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
            Ok(inner.metadata.read().keys.clone())
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
}

type SharedSession = Arc<RwLock<Session>>;

pub struct HostMetadata {
    #[allow(unused)]
    /// Our private and public keys.
    pub keys: KeyPair,
    pub capabilities: Vec<Capability>,
    pub local_address: SocketAddr,
    /// Local address + discovery port
    pub local_endpoint: NodeEndpoint,
    /// Public address + discovery port
    pub public_endpoint: NodeEndpoint,
}

impl HostMetadata {
    pub(crate) fn id(&self) -> &NodeId { self.keys.public() }
}

#[derive(Copy, Clone)]
struct ProtocolTimer {
    pub protocol: ProtocolId,
    pub token: TimerToken, // Handler level token
}

/// The inner implementation of NetworkService. Note that all accesses to the
/// RWLocks of the fields have to follow the defined order to avoid race
#[allow(dead_code)]
pub struct NetworkServiceInner {
    sessions: Arc<RwLock<Slab<SharedSession>>>,
    pub metadata: RwLock<HostMetadata>,
    pub config: NetworkConfiguration,
    udp_socket: Mutex<UdpSocket>,
    tcp_listener: Mutex<TcpListener>,
    udp_channel: RwLock<UdpChannel>,
    discovery: Mutex<Option<Discovery>>,
    handlers: RwLock<HashMap<ProtocolId, Arc<NetworkProtocolHandler + Sync>>>,
    timers: RwLock<HashMap<TimerToken, ProtocolTimer>>,
    timer_counter: RwLock<usize>,
    /// Two disk backed table storing the trusted and untrusted nodes
    pub trusted_nodes: RwLock<NodeTable>,
    pub untrusted_nodes: RwLock<NodeTable>,
    reserved_nodes: RwLock<HashSet<NodeId>>,
    nodes: RwLock<HashMap<NodeId, NodeEntry>>,
    dropped_nodes: RwLock<HashSet<StreamToken>>,

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
        if context
            .session
            .write()
            .send_packet(
                &context.io,
                Some(context.protocol),
                session::PACKET_USER,
                &context.msg,
            )
            .is_err()
        {
            debug!("Error sending delayed message");
            network_service.kill_connection(context.peer, &context.io);
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
        debug!(target: "network", "Listening at {:?}", listen_address);
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

        let inner = NetworkServiceInner {
            metadata: RwLock::new(HostMetadata {
                keys,
                capabilities: Vec::new(),
                local_address: listen_address,
                local_endpoint,
                public_endpoint,
            }),
            config: config.clone(),
            udp_channel: RwLock::new(UdpChannel::new()),
            discovery: Mutex::new(discovery),
            udp_socket: Mutex::new(udp_socket),
            tcp_listener: Mutex::new(tcp_listener),
            sessions: Arc::new(RwLock::new(Slab::new_starting_at(
                FIRST_SESSION,
                LAST_SESSION,
            ))),
            handlers: RwLock::new(HashMap::new()),
            timers: RwLock::new(HashMap::new()),
            timer_counter: RwLock::new(HANDLER_TIMER),
            trusted_nodes: RwLock::new(NodeTable::new(
                nodes_path.clone(),
                true,
            )),
            untrusted_nodes: RwLock::new(NodeTable::new(nodes_path, false)),
            reserved_nodes: RwLock::new(HashSet::new()),
            nodes: RwLock::new(HashMap::new()),
            dropped_nodes: RwLock::new(HashSet::new()),
            delayed_queue: None,
        };

        for n in &config.boot_nodes {
            inner.add_trusted_node(n);
        }

        let reserved_nodes = config.reserved_nodes.clone();
        for n in reserved_nodes {
            if let Err(e) = inner.add_reserved_node(&n) {
                debug!(target: "network", "Error parsing node id: {}: {:?}", n, e);
            }
        }

        Ok(inner)
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

    pub fn add_trusted_node(&self, id: &str) {
        match Node::from_str(id) {
            Err(e) => {
                debug!(target: "network", "Could not add node {}: {:?}", id, e);
            }
            Ok(n) => {
                self.add_trusted_node_with_entry(NodeEntry {
                    id: n.id,
                    endpoint: n.endpoint.clone(),
                });
            }
        }
    }

    pub fn add_trusted_node_with_entry(&self, entry: NodeEntry) {
        let mut trusted = self.trusted_nodes.write();
        let mut untrusted = self.untrusted_nodes.write();

        if !trusted.contains(&entry.id) {
            let mut trusted_node = Node::new(entry.id, entry.endpoint.clone());
            if let Some(removed_node) = untrusted.remove_with_id(&entry.id) {
                trusted_node.last_connected = removed_node.last_connected;
                trusted_node.stream_token = removed_node.stream_token;
                trusted_node.last_contact = removed_node.last_contact;
            }
            trusted.add_node(trusted_node, false);
        } else {
            debug_assert!(!untrusted.contains(&entry.id));
        }
    }

    pub fn add_reserved_node(&self, id: &str) -> Result<(), Error> {
        let n = Node::from_str(id)?;
        self.add_trusted_node_with_entry(NodeEntry {
            id: n.id,
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
                .trusted_nodes
                .read()
                .sample_nodes(DISCOVER_NODES_COUNT, &allow_ips);
            discovery.try_ping_nodes(
                &UdpIoContext::new(
                    &self.udp_channel,
                    &self.trusted_nodes,
                    &self.untrusted_nodes,
                ),
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

        Ok(())
    }

    fn note_failure(&self, id: &NodeId, by_connection: bool) {
        {
            let mut trusted_nodes = self.trusted_nodes.write();
            if trusted_nodes.contains(id) {
                trusted_nodes.note_failure(id, by_connection);
            }
        }
        {
            let mut untrusted_nodes = self.untrusted_nodes.write();
            if untrusted_nodes.contains(id) {
                untrusted_nodes.note_failure(id, by_connection);
            }
        }
    }

    fn note_trusted_failure(&self, id: &NodeId, by_connection: bool) {
        let mut trusted_nodes = self.trusted_nodes.write();
        if trusted_nodes.contains(id) {
            trusted_nodes.note_failure(id, by_connection);
        }
    }

    fn try_promote_untrusted(&self) {
        // Get NodeIds from incoming connections
        let mut incoming_ids: Vec<NodeId> = Vec::new();
        for s in self.sessions.read().iter() {
            if let Some(ref s) = s.try_read() {
                if s.is_ready() && !s.metadata.originated {
                    // is live incoming connection
                    if let Some(id) = s.metadata.id {
                        incoming_ids.push(id);
                    }
                }
            }
        }
        // Check each live connection for its lifetime.
        // Promote the peers with live connection for a threshold period
        let mut trusted = self.trusted_nodes.write();
        let mut untrusted = self.untrusted_nodes.write();
        for id in incoming_ids.iter() {
            if trusted.contains(id) {
                debug_assert!(!untrusted.contains(id));
                continue;
            } else {
                let mut last_connected = None;
                if let Some(node) = untrusted.get(id) {
                    last_connected = node.last_connected;
                }

                if let Some(c) = last_connected {
                    if c.success_for_duration(
                        self.config.connection_lifetime_for_promotion,
                    ) {
                        let removed_node =
                            untrusted.remove_with_id(id).unwrap();
                        trusted.add_node(removed_node, false);
                    }
                }
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.metadata.read().local_address
    }

    fn drop_node(&self, local_id: NodeId) -> Result<(), Error> {
        let mut tn = self.trusted_nodes.write();
        let mut utn = self.untrusted_nodes.write();
        let stream_token = {
            if let Some(node) = tn.remove_with_id(&local_id) {
                node.stream_token.clone()
            } else if let Some(node) = utn.remove_with_id(&local_id) {
                node.stream_token.clone()
            } else {
                None
            }
        };

        if let Some(stream_token) = stream_token {
            let mut wd = self.dropped_nodes.write();
            wd.insert(stream_token);
        }

        Ok(())
    }

    fn has_enough_outgoing_peers(&self) -> bool {
        let (_, egress_count, _) = self.session_count();
        return egress_count >= self.config.max_outgoing_peers as usize;
    }

    fn on_housekeeping(&self, io: &IoContext<NetworkIoMessage>) {
        self.connect_peers(io);
        self.drop_peers(io);
    }

    // Connect to all reserved and trusted peers if not yet
    fn connect_peers(&self, io: &IoContext<NetworkIoMessage>) {
        let meta = self.metadata.read();
        if meta.capabilities.is_empty() {
            return;
        }

        let self_id = *meta.id();
        let max_outgoing_peers = self.config.max_outgoing_peers;
        //let max_incoming_peers = self.config.max_incoming_peers;
        let max_handshakes = self.config.max_handshakes;
        let allow_ips = self.config.ip_filter.clone();

        let (handshake_count, egress_count, ingress_count) =
            self.session_count();
        let samples;
        {
            let trusted_nodes = self.trusted_nodes.read();
            let egress_attempt_count = max_outgoing_peers - egress_count as u32;
            samples =
                trusted_nodes.sample_node_ids(egress_attempt_count, &allow_ips);
        }
        let reserved_nodes = self.reserved_nodes.read();
        // Try to connect all reserved peers and trusted peers
        let nodes = reserved_nodes.iter().cloned().chain(samples);

        let max_handshakes_per_round = max_handshakes / 2;
        let mut started: usize = 0;
        for id in nodes
            .filter(|id| !self.have_session(id) && *id != self_id)
            .take(min(
                max_handshakes_per_round as usize,
                max_handshakes as usize - handshake_count,
            ))
        {
            self.connect_peer(&id, io);
            started += 1;
        }
        debug!(target: "network", "Connecting peers: {} sessions, {} pending + {} started", egress_count + ingress_count, handshake_count, started);
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
            self.kill_connection(*token, io);
        }
        w.clear();
    }

    // returns (handshakes, egress, ingress)
    fn session_count(&self) -> (usize, usize, usize) {
        let mut handshakes = 0;
        let mut egress = 0;
        let mut ingress = 0;
        for s in self.sessions.read().iter() {
            match s.try_read() {
                Some(ref s) if s.is_ready() && s.metadata.originated => {
                    egress += 1
                }
                Some(ref s) if s.is_ready() && !s.metadata.originated => {
                    ingress += 1
                }
                _ => handshakes += 1,
            }
        }
        (handshakes, egress, ingress)
    }

    fn have_session(&self, id: &NodeId) -> bool {
        self.sessions
            .read()
            .iter()
            .any(|sess| sess.read().metadata.id == Some(*id))
    }

    fn connect_peer(&self, id: &NodeId, io: &IoContext<NetworkIoMessage>) {
        if self.have_session(id) {
            trace!(target: "network", "Abort connect. Node already connected");
            return;
        }

        let (socket, address) = {
            let address = {
                // outgoing connection must pick node from trusted node table
                let nodes = self.trusted_nodes.read();
                if let Some(node) = nodes.get(id) {
                    node.endpoint.address
                } else {
                    debug!(target: "network", "Abort connect. Node expired");
                    return;
                }
            };
            match TcpStream::connect(&address) {
                Ok(socket) => {
                    trace!(target: "network", "{}: connecting to {:?}", id, address);
                    (socket, address)
                }
                Err(e) => {
                    self.note_trusted_failure(id, true);
                    debug!(target: "network", "{}: can't connect o address {:?} {:?}", id, address, e);
                    return;
                }
            }
        };

        if let Err(e) = self.create_connection(socket, address, Some(id), io) {
            self.note_trusted_failure(id, true);
            debug!(target: "network", "Can't create connection: {:?}", e);
        }
    }

    pub fn get_peer_info(&self) -> Vec<PeerInfo> {
        let sessions = self.sessions.read();
        let sessions = &*sessions;

        let mut peers = Vec::with_capacity(sessions.count());
        for i in (0..MAX_SESSIONS).map(|x| x + FIRST_SESSION) {
            let session = sessions.get(i);
            if session.is_some() {
                let sess = session.unwrap().read();
                peers.push(PeerInfo {
                    id: i,
                    nodeid: sess.id().unwrap_or(&NodeId::default()).clone(),
                    addr: sess.address(),
                    caps: sess.metadata.peer_capabilities.clone(),
                })
            }
        }
        peers
    }

    pub fn get_peer_node_id(&self, peer: PeerId) -> NodeId {
        let sessions = self.sessions.read();
        let session = sessions.get(peer);
        if session.is_some() {
            let sess = session.unwrap().read();
            sess.id().unwrap_or(&NodeId::default()).clone()
        } else {
            NodeId::default()
        }
    }

    #[allow(unused)]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        let sessions = self.sessions.read();
        let sessions = &*sessions;

        let mut peers = Vec::with_capacity(sessions.count());
        for i in (0..MAX_SESSIONS).map(|x| x + FIRST_SESSION) {
            if sessions.get(i).is_some() {
                peers.push(i);
            }
        }
        peers
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
        let mut sessions = self.sessions.write();

        let token = sessions.insert_with_opt(|token| {
            trace!(target: "network", "{}: Initiating session", token);
            match Session::new(
                io,
                socket,
                address,
                id,
                token,
                self,
            ) {
                Ok(sess) => Some(Arc::new(RwLock::new(sess))),
                Err(e) => {
                    debug!(target: "network", "Error creating session: {:?}", e);
                    None
                }
            }
        });
        match token {
            Some(token) => {
                if let Some(id) = id {
                    // This is an outgoing connection.
                    // Outgoing connection must pick node from trusted node
                    // table
                    self.trusted_nodes.write().note_success(
                        id,
                        true,
                        Some(token),
                    );
                }
                io.register_stream(token).map(|_| ()).map_err(Into::into)
            }
            None => {
                debug!(target: "network", "Max sessions reached");
                Ok(())
            }
        }
    }

    fn connection_closed(
        &self, stream: StreamToken, io: &IoContext<NetworkIoMessage>,
    ) {
        trace!(target: "network", "Connection closed: {}", stream);
        self.kill_connection(stream, io);
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
        let session = self.sessions.read().get(stream).cloned();

        // if let Some(session) = session.clone()
        if let Some(session) = session {
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
                            None => {
                                warn!(target: "network", "No handler found for protocol: {:?}", protocol)
                            }
                            Some(_) => messages.push((protocol, data)),
                        }
                    }
                    Ok(SessionData::Continue) => (),
                    Ok(SessionData::None) => break,
                    Err(_) => {
                        //let sess = session.lock();
                        kill = true;
                        break;
                    }
                }
            }
        }

        if kill {
            self.kill_connection(stream, io);
        }

        let handlers = self.handlers.read();
        if !ready_protocols.is_empty() {
            for protocol in ready_protocols {
                if let Some(handler) = handlers.get(&protocol).clone() {
                    debug!(
                        "Network Service: {}: peer {} connected",
                        self.local_addr(),
                        stream
                    );
                    handler.on_peer_connected(
                        &NetworkContext::new(io, protocol, self),
                        stream,
                    );
                }
            }
        }
        for (protocol, data) in messages {
            if let Some(handler) = handlers.get(&protocol).clone() {
                handler.on_message(
                    &NetworkContext::new(io, protocol, self),
                    stream,
                    &data,
                );
            }
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

        let session = self.sessions.read().get(stream).cloned();

        if let Some(session) = session {
            let mut sess = session.write();
            if let Err(e) = sess.writable(io) {
                trace!(target: "network", "{}: Session write error: {:?}", stream, e);
            }
            if sess.done() {
                io.deregister_stream(stream).unwrap_or_else(|e| {
                    debug!("Error deregistering stream: {:?}", e)
                });
            }
        }
    }

    fn accept(&self, io: &IoContext<NetworkIoMessage>) {
        trace!(target: "network", "Accepting incoming connection");
        loop {
            let (socket, address) = match self.tcp_listener.lock().accept() {
                Ok((sock, addr)) => (sock, addr),
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        debug!(target: "network", "Error accepting connection: {:?}", e);
                    }
                    break;
                }
            };
            if let Err(e) = self.create_connection(socket, address, None, io) {
                debug!(target: "netweork", "Can't accept connection: {:?}", e);
            }
        }
    }

    fn kill_connection(
        &self, token: StreamToken, io: &IoContext<NetworkIoMessage>,
    ) {
        let mut to_disconnect: Vec<ProtocolId> = Vec::new();
        let mut deregister = false;

        if let FIRST_SESSION...LAST_SESSION = token {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.get(token).cloned() {
                let mut sess = session.write();
                if !sess.expired() {
                    if sess.is_ready() {
                        for (p, _) in self.handlers.read().iter() {
                            if sess.have_capability(*p) {
                                to_disconnect.push(*p);
                            }
                        }
                    }
                    sess.set_expired();
                }
                deregister = sess.done();
                debug!("deregister stream {}? {}", token, deregister);
            }
        }
        for p in to_disconnect {
            if let Some(h) = self.handlers.read().get(&p).clone() {
                debug!("{}: peer {} disconnected", self.local_addr(), token);
                h.on_peer_disconnected(
                    &NetworkContext::new(io, p, self),
                    token,
                );
            }
        }
        if deregister {
            io.deregister_stream(token).unwrap_or_else(|e| {
                debug!("Error deregistering stream {:?}", e);
            })
        }
    }

    pub fn with_context<F>(
        &self, protocol: ProtocolId, io: &IoContext<NetworkIoMessage>,
        action: F,
    ) where
        F: FnOnce(&NetworkContext),
    {
        let context = NetworkContext::new(io, protocol, self);
        action(&context);
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
			Ok(Some((len, address))) => self.on_udp_packet(&buf[0..len], address).unwrap_or_else(|e| {
				debug!(target: "network", "Error processing UDP packet: {:?}", e);
			}),
			Ok(_) => {},
			Err(e) => {
				debug!(target: "network", "Error reading UDP socket: {:?}", e);
			},
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
            io.update_registration(UDP_MESSAGE)
                .unwrap_or_else(|e| {
                    debug!(target: "network", "Error updating UDP registration: {:?}", e)
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
                    warn!(target: "network", "UDP sent incomplete datagram");
                }
                Ok(None) => {
                    udp_channel.requeue_send(data);
                    return;
                }
                Err(e) => {
                    debug!(target: "network", "UDP send error: {:?}, address: {:?}", e, &data.address);
                    return;
                }
            }
        }
        // look at whether the monitor interest can be set as Readable.
        io.update_registration(UDP_MESSAGE)
			.unwrap_or_else(|e| {
				debug!(target: "network", "Error updating UDP registration: {:?}", e)
			});
    }

    fn on_udp_packet(
        &self, packet: &[u8], from: SocketAddr,
    ) -> Result<(), Error> {
        if packet.len() == 0 {
            return Ok(());
        }

        let res = match packet[0] {
            UDP_PROTOCOL_DISCOVERY => {
                if let Some(discovery) = self.discovery.lock().as_mut() {
                    discovery.on_packet(
                        &UdpIoContext::new(
                            &self.udp_channel,
                            &self.trusted_nodes,
                            &self.untrusted_nodes,
                        ),
                        &packet[1..],
                        from,
                    )?;
                    Ok(())
                } else {
                    warn!(target: "network", "Discovery is not ready. Drop the message!");
                    Ok(())
                }
            }
            _ => {
                warn!(target: "network", "Unknown UDP protocol. Simply drops the message!");
                Ok(())
            }
        };
        res
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
        trace!(target: "network", "Hup: {}", stream);
        match stream {
            FIRST_SESSION...LAST_SESSION => self.connection_closed(stream, io),
            _ => warn!(target: "network", "Unexpected hup"),
        }
    }

    fn stream_readable(
        &self, io: &IoContext<NetworkIoMessage>, stream: StreamToken,
    ) {
        match stream {
            FIRST_SESSION...LAST_SESSION => self.session_readable(stream, io),
            TCP_ACCEPT => self.accept(io),
            UDP_MESSAGE => self.udp_readable(io),
            _ => panic!("Received unknown readable token"),
        }
    }

    fn stream_writable(
        &self, io: &IoContext<NetworkIoMessage>, stream: StreamToken,
    ) {
        match stream {
            FIRST_SESSION...LAST_SESSION => self.session_writable(stream, io),
            UDP_MESSAGE => self.udp_writable(io),
            _ => panic!("Received unknown writable token"),
        }
    }

    fn timeout(&self, io: &IoContext<NetworkIoMessage>, token: TimerToken) {
        match token {
            HOUSEKEEPING => self.on_housekeeping(io),
            DISCOVERY_REFRESH => {
                // Run the _slow_ discovery if enough peers are connected
                if self.has_enough_outgoing_peers() {
                    self.discovery.lock().as_mut().map(|d| d.refresh());
                    io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
                        debug!("Error updating discovery registration: {:?}", e)
                    });
                }
            }
            FAST_DISCOVERY_REFRESH => {
                // Run the fast discovery if not enough peers are connected
                if !self.has_enough_outgoing_peers() {
                    self.discovery.lock().as_mut().map(|d| d.refresh());
                    io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
                        debug!("Error updating discovery registration: {:?}", e)
                    });
                }
            }
            DISCOVERY_ROUND => {
                self.discovery.lock().as_mut().map(|d| {
                    d.round(&UdpIoContext::new(
                        &self.udp_channel,
                        &self.trusted_nodes,
                        &self.untrusted_nodes,
                    ))
                });
                io.update_registration(UDP_MESSAGE).unwrap_or_else(|e| {
                    debug!("Error updating discovery registration: {:?}", e)
                });
            }
            NODE_TABLE => {
                trace!(target: "network", "Refreshing node table");
                self.try_promote_untrusted();
                self.trusted_nodes.write().save();
                self.trusted_nodes.write().clear_useless();
                self.untrusted_nodes.write().save();
                self.untrusted_nodes.write().clear_useless();
            }
            SEND_DELAYED_MESSAGES => {
                if let Some(ref queue) = self.delayed_queue {
                    queue.send_delayed_messages(self);
                }
            }
            _ => match self.timers.read().get(&token).cloned() {
                Some(timer) => {
                    match self.handlers.read().get(&timer.protocol).cloned() {
                        None => {
                            warn!(target: "network", "No handler found for protocol: {:?}", timer.protocol)
                        }
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
                let mut metadata = self.metadata.write();
                for &version in versions {
                    metadata.capabilities.push(Capability {
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
            NetworkIoMessage::Disconnect(ref peer) => {
                let session = self.sessions.read().get(*peer).cloned();
                if let Some(session) = session {
                    session
                        .write()
                        .disconnect(io, DisconnectReason::DisconnectRequested);
                }
                trace!(target: "network", "Disconnect requested {}", peer);
                self.kill_connection(*peer, io);
            } //_ => {}
        }
    }

    fn register_stream(
        &self, stream: StreamToken, reg: Token,
        event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
    )
    {
        match stream {
            FIRST_SESSION...LAST_SESSION => {
                let session = self.sessions.read().get(stream).cloned();
                if let Some(session) = session {
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

    fn deregister_stream(
        &self, stream: StreamToken,
        event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
    )
    {
        match stream {
            FIRST_SESSION...LAST_SESSION => {
                let mut sessions = self.sessions.write();
                if let Some(session) = sessions.get(stream).cloned() {
                    let sess = session.write();
                    if sess.expired() {
                        sess.deregister_socket(event_loop)
                            .expect("Error deregistering socket");
                        if let Some(node_id) = sess.id() {
                            self.note_failure(node_id, true);
                        }
                        debug!("Remove session {}", stream);
                        sessions.remove(stream);
                    }
                }
            }
            _ => warn!("Unexpected stream deregistration"),
        }
    }

    fn update_stream(
        &self, stream: StreamToken, reg: Token,
        event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
    )
    {
        match stream {
            FIRST_SESSION...LAST_SESSION => {
                let session = self.sessions.read().get(stream).cloned();
                if let Some(session) = session {
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
}

impl DelayMessageContext {
    pub fn new(
        ts: Instant, io: IoContext<NetworkIoMessage>, protocol: ProtocolId,
        session: SharedSession, peer: PeerId, msg: Vec<u8>,
    ) -> Self
    {
        DelayMessageContext {
            ts,
            io,
            protocol,
            session,
            peer,
            msg,
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
    fn new(
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

    fn send(&self, peer: PeerId, msg: Vec<u8>) -> Result<(), Error> {
        let sessions = self.network_service.sessions.read();
        let session = sessions.get(peer);
        trace!(target: "network", "Sending {} bytes to {}", msg.len(), peer);
        if let Some(session) = session {
            let latency =
                self.network_service
                    .delayed_queue
                    .as_ref()
                    .map_or(None, |q| {
                        session.write().metadata.id.map_or(None, |id| {
                            q.latencies
                                .read()
                                .get(&id)
                                .map(|latency| latency.clone())
                        })
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
                        (*session).clone(),
                        peer,
                        msg,
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
                        &msg,
                    )?;
                }
            }
            // TODO: Handle result from send_packet()
        }
        Ok(())
    }

    fn disconnect_peer(&self, peer: PeerId) {
        self.network_service.kill_connection(peer, self.io);
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
        warn!(target: "network", "Failed to modify permissions of the file ({})", e);
    }
    if let Err(e) = file.write(&key.hex().into_bytes()[2..]) {
        warn!("Error writing key file: {:?}", e);
    }
}

fn load_key(path: &Path) -> Option<Secret> {
    let mut path_buf = PathBuf::from(path);
    path_buf.push("key");
    let mut file = match fs::File::open(path_buf.as_path()) {
        Ok(file) => file,
        Err(e) => {
            debug!("Error opening key file: {:?}", e);
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
