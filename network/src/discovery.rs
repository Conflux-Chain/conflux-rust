// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hash::keccak,
    node_database::NodeDatabase,
    node_table::{NodeId, *},
    service::{UdpIoContext, MAX_DATAGRAM_SIZE, UDP_PROTOCOL_DISCOVERY},
    DiscoveryConfiguration, Error, ErrorKind, IpFilter, ThrottlingReason,
    NODE_TAG_ARCHIVE, NODE_TAG_NODE_TYPE,
};
use cfx_bytes::Bytes;
use cfx_types::{H256, H520};
use cfxkey::{recover, sign, KeyPair, Secret};
use rlp::{Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use throttling::time_window_bucket::TimeWindowBucket;

const DISCOVER_PROTOCOL_VERSION: u32 = 1;

const DISCOVERY_MAX_STEPS: u16 = 4; // Max iterations of discovery. (discover)

const PACKET_PING: u8 = 1;
const PACKET_PONG: u8 = 2;
const PACKET_FIND_NODE: u8 = 3;
const PACKET_NEIGHBOURS: u8 = 4;

struct PingRequest {
    // Time when the request was sent
    sent_at: Instant,
    // The node to which the request was sent
    node: NodeEntry,
    // The hash sent in the Ping request
    echo_hash: H256,
}

struct FindNodeRequest {
    // Time when the request was sent
    sent_at: Instant,
    // Number of neighbor chunks for the response
    num_chunks: usize,
    // Number of received chunks for the response
    received_chunks: HashSet<usize>,
}

impl Default for FindNodeRequest {
    fn default() -> Self {
        FindNodeRequest {
            sent_at: Instant::now(),
            num_chunks: 0,
            received_chunks: HashSet::new(),
        }
    }
}

impl FindNodeRequest {
    fn is_completed(&self) -> bool {
        self.num_chunks > 0 && self.num_chunks == self.received_chunks.len()
    }
}

#[allow(dead_code)]
pub struct Discovery {
    id: NodeId,
    id_hash: H256,
    secret: Secret,
    public_endpoint: NodeEndpoint,
    discovery_initiated: bool,
    discovery_round: Option<u16>,
    discovery_nodes: HashSet<NodeId>,
    in_flight_pings: HashMap<NodeId, PingRequest>,
    in_flight_find_nodes: HashMap<NodeId, FindNodeRequest>,
    check_timestamps: bool,
    adding_nodes: Vec<NodeEntry>,
    ip_filter: IpFilter,
    pub disc_option: DiscoveryOption,

    // Limits the response for PING/FIND_NODE packets
    ping_throttling: TimeWindowBucket<IpAddr>,
    find_nodes_throttling: TimeWindowBucket<IpAddr>,

    config: DiscoveryConfiguration,
}

impl Discovery {
    pub fn new(
        key: &KeyPair, public: NodeEndpoint, ip_filter: IpFilter,
        config: DiscoveryConfiguration,
    ) -> Discovery
    {
        Discovery {
            id: key.public().clone(),
            id_hash: keccak(key.public()),
            secret: key.secret().clone(),
            public_endpoint: public,
            discovery_initiated: false,
            discovery_round: None,
            discovery_nodes: HashSet::new(),
            in_flight_pings: HashMap::new(),
            in_flight_find_nodes: HashMap::new(),
            check_timestamps: true,
            adding_nodes: Vec::new(),
            ip_filter,
            disc_option: DiscoveryOption {
                general: true,
                archive: false,
            },
            ping_throttling: TimeWindowBucket::new(
                config.throttling_interval,
                config.throttling_limit_ping,
            ),
            find_nodes_throttling: TimeWindowBucket::new(
                config.throttling_interval,
                config.throttling_limit_find_nodes,
            ),
            config,
        }
    }

    fn is_allowed(&self, entry: &NodeEntry) -> bool {
        entry.endpoint.is_allowed(&self.ip_filter) && entry.id != self.id
    }

    pub fn try_ping_nodes(
        &mut self, uio: &UdpIoContext, nodes: Vec<NodeEntry>,
    ) {
        for node in nodes {
            self.try_ping(uio, node);
        }
    }

    fn try_ping(&mut self, uio: &UdpIoContext, node: NodeEntry) {
        if !self.is_allowed(&node) {
            trace!("Node {:?} not allowed", node);
            return;
        }
        if self.in_flight_pings.contains_key(&node.id)
            || self.in_flight_find_nodes.contains_key(&node.id)
        {
            trace!("Node {:?} in flight requests", node);
            return;
        }
        if self.adding_nodes.iter().any(|n| n.id == node.id) {
            trace!("Node {:?} in adding nodes", node);
            return;
        }

        if self.in_flight_pings.len() < self.config.max_nodes_ping {
            self.ping(uio, &node).unwrap_or_else(|e| {
                warn!("Error sending Ping packet: {:?}", e);
            });
        } else {
            self.adding_nodes.push(node);
        }
    }

    fn ping(
        &mut self, uio: &UdpIoContext, node: &NodeEntry,
    ) -> Result<(), Error> {
        let mut rlp = RlpStream::new_list(4);
        rlp.append(&DISCOVER_PROTOCOL_VERSION);
        self.public_endpoint.to_rlp_list(&mut rlp);
        node.endpoint.to_rlp_list(&mut rlp);
        rlp.append(&self.config.expire_timestamp());
        let hash = self.send_packet(
            uio,
            PACKET_PING,
            &node.endpoint.udp_address(),
            &rlp.drain(),
        )?;

        self.in_flight_pings.insert(
            node.id.clone(),
            PingRequest {
                sent_at: Instant::now(),
                node: node.clone(),
                echo_hash: hash,
            },
        );

        trace!("Sent Ping to {:?} ; node_id={:#x}", &node.endpoint, node.id);
        Ok(())
    }

    fn send_packet(
        &mut self, uio: &UdpIoContext, packet_id: u8, address: &SocketAddr,
        payload: &[u8],
    ) -> Result<H256, Error>
    {
        let packet = assemble_packet(packet_id, payload, &self.secret)?;
        let hash = H256::from_slice(&packet[1..=32]);
        self.send_to(uio, packet, address.clone());
        Ok(hash)
    }

    fn send_to(
        &mut self, uio: &UdpIoContext, payload: Bytes, address: SocketAddr,
    ) {
        uio.send(payload, address);
    }

    pub fn on_packet(
        &mut self, uio: &UdpIoContext, packet: &[u8], from: SocketAddr,
    ) -> Result<(), Error> {
        // validate packet
        if packet.len() < 32 + 65 + 4 + 1 {
            return Err(ErrorKind::BadProtocol.into());
        }

        let hash_signed = keccak(&packet[32..]);
        if hash_signed[..] != packet[0..32] {
            return Err(ErrorKind::BadProtocol.into());
        }

        let signed = &packet[(32 + 65)..];
        let signature = H520::from_slice(&packet[32..(32 + 65)]);
        let node_id = recover(&signature.into(), &keccak(signed))?;

        let packet_id = signed[0];
        let rlp = Rlp::new(&signed[1..]);
        match packet_id {
            PACKET_PING => {
                self.on_ping(uio, &rlp, &node_id, &from, hash_signed.as_bytes())
            }
            PACKET_PONG => self.on_pong(uio, &rlp, &node_id, &from),
            PACKET_FIND_NODE => self.on_find_node(uio, &rlp, &node_id, &from),
            PACKET_NEIGHBOURS => self.on_neighbours(uio, &rlp, &node_id, &from),
            _ => {
                debug!("Unknown UDP packet: {}", packet_id);
                Ok(())
            }
        }
    }

    /// Validate that given timestamp is in within one second of now or in the
    /// future
    fn check_timestamp(&self, timestamp: u64) -> Result<(), Error> {
        let secs_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.check_timestamps && timestamp < secs_since_epoch {
            debug!("Expired packet");
            return Err(ErrorKind::Expired.into());
        }
        Ok(())
    }

    fn on_ping(
        &mut self, uio: &UdpIoContext, rlp: &Rlp, node_id: &NodeId,
        from: &SocketAddr, echo_hash: &[u8],
    ) -> Result<(), Error>
    {
        trace!("Got Ping from {:?}", &from);

        if !self.ping_throttling.try_acquire(from.ip()) {
            return Err(ErrorKind::Throttling(
                ThrottlingReason::PacketThrottled("PING"),
            )
            .into());
        }

        let ping_from = NodeEndpoint::from_rlp(&rlp.at(1)?)?;
        let ping_to = NodeEndpoint::from_rlp(&rlp.at(2)?)?;
        let timestamp: u64 = rlp.val_at(3)?;
        self.check_timestamp(timestamp)?;

        let mut response = RlpStream::new_list(3);
        let pong_to = NodeEndpoint {
            address: from.clone(),
            udp_port: ping_from.udp_port,
        };
        // Here the PONG's `To` field should be the node we are
        // sending the request to
        // WARNING: this field _should not be used_, but old Parity versions
        // use it in order to get the node's address.
        // So this is a temporary fix so that older Parity versions don't brake
        // completely.
        ping_to.to_rlp_list(&mut response);
        // pong_to.to_rlp_list(&mut response);

        response.append(&echo_hash);
        response.append(&self.config.expire_timestamp());
        self.send_packet(uio, PACKET_PONG, from, &response.drain())?;

        let entry = NodeEntry {
            id: node_id.clone(),
            endpoint: pong_to,
        };
        // TODO handle the error before sending pong
        if !entry.endpoint.is_valid() {
            debug!("Got bad address: {:?}", entry);
        } else if !self.is_allowed(&entry) {
            debug!("Address not allowed: {:?}", entry);
        } else {
            uio.node_db
                .write()
                .note_success(node_id, None, false /* trusted_only */);
        }
        Ok(())
    }

    fn on_pong(
        &mut self, uio: &UdpIoContext, rlp: &Rlp, node_id: &NodeId,
        from: &SocketAddr,
    ) -> Result<(), Error>
    {
        trace!("Got Pong from {:?} ; node_id={:#x}", &from, node_id);
        let _pong_to = NodeEndpoint::from_rlp(&rlp.at(0)?)?;
        let echo_hash: H256 = rlp.val_at(1)?;
        let timestamp: u64 = rlp.val_at(2)?;
        self.check_timestamp(timestamp)?;

        let expected_node = match self.in_flight_pings.entry(*node_id) {
            Entry::Occupied(entry) => {
                let expected_node = {
                    let request = entry.get();
                    if request.echo_hash != echo_hash {
                        debug!("Got unexpected Pong from {:?} ; packet_hash={:#x} ; expected_hash={:#x}", &from, request.echo_hash, echo_hash);
                        None
                    } else {
                        Some(request.node.clone())
                    }
                };

                if expected_node.is_some() {
                    entry.remove();
                }
                expected_node
            }
            Entry::Vacant(_) => None,
        };

        if let Some(node) = expected_node {
            uio.node_db.write().insert_with_conditional_promotion(node);
            Ok(())
        } else {
            debug!("Got unexpected Pong from {:?} ; request not found", &from);
            Ok(())
        }
    }

    fn on_find_node(
        &mut self, uio: &UdpIoContext, rlp: &Rlp, _node: &NodeId,
        from: &SocketAddr,
    ) -> Result<(), Error>
    {
        trace!("Got FindNode from {:?}", &from);

        if !self.find_nodes_throttling.try_acquire(from.ip()) {
            return Err(ErrorKind::Throttling(
                ThrottlingReason::PacketThrottled("FIND_NODES"),
            )
            .into());
        }

        let msg: FindNodeMessage = rlp.as_val()?;
        self.check_timestamp(msg.expire_timestamp)?;
        let neighbors = msg.sample(
            &*uio.node_db.read(),
            &self.ip_filter,
            self.config.discover_node_count,
        )?;

        trace!("Sample {} Neighbours for {:?}", neighbors.len(), &from);

        let chunk_size = (MAX_DATAGRAM_SIZE - (1 + 109)) / 90;
        let chunks = NeighborsChunkMessage::chunks(neighbors, chunk_size);

        for chunk in &chunks {
            self.send_packet(uio, PACKET_NEIGHBOURS, from, &chunk.rlp_bytes())?;
        }

        trace!("Sent {} Neighbours chunks to {:?}", chunks.len(), &from);
        Ok(())
    }

    fn on_neighbours(
        &mut self, uio: &UdpIoContext, rlp: &Rlp, node_id: &NodeId,
        from: &SocketAddr,
    ) -> Result<(), Error>
    {
        let mut entry = match self.in_flight_find_nodes.entry(*node_id) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => {
                debug!("Got unexpected Neighbors from {:?} ; couldn't find node_id={:#x}", &from, node_id);
                return Ok(());
            }
        };

        let msg: NeighborsChunkMessage = rlp.as_val()?;
        let request = entry.get_mut();

        if !msg.update(request)? {
            return Ok(());
        }

        if request.is_completed() {
            entry.remove();
        }

        trace!("Got {} Neighbours from {:?}", msg.neighbors.len(), &from);

        for node in msg.neighbors {
            if !node.endpoint.is_valid() {
                debug!("Bad address: {:?}", node.endpoint);
                continue;
            }
            if node.id == self.id {
                continue;
            }
            if !self.is_allowed(&node) {
                debug!("Address not allowed: {:?}", node);
                continue;
            }
            self.try_ping(uio, node);
        }

        Ok(())
    }

    /// Starts the discovery process at round 0
    fn start(&mut self) {
        trace!("Starting discovery");
        self.discovery_round = Some(0);
        self.discovery_nodes.clear();
    }

    /// Complete the discovery process
    fn stop(&mut self) {
        trace!("Completing discovery");
        self.discovery_round = None;
        self.discovery_nodes.clear();
    }

    fn check_expired(&mut self, uio: &UdpIoContext, time: Instant) {
        let mut nodes_to_expire = Vec::new();
        let ping_timeout = &self.config.ping_timeout;
        self.in_flight_pings.retain(|node_id, ping_request| {
            if time.duration_since(ping_request.sent_at) > *ping_timeout {
                debug!(
                    "Removing expired PING request for node_id={:#x}",
                    node_id
                );
                nodes_to_expire.push(*node_id);
                false
            } else {
                true
            }
        });
        let find_node_timeout = &self.config.find_node_timeout;
        self.in_flight_find_nodes.retain(|node_id, find_node_request| {
            if time.duration_since(find_node_request.sent_at) > *find_node_timeout {
                if !find_node_request.is_completed() {
                    debug!("Removing expired FIND NODE request for node_id={:#x}", node_id);
                    nodes_to_expire.push(*node_id);
                }
                false
            } else {
                true
            }
        });
        for node_id in nodes_to_expire {
            self.expire_node_request(uio, node_id);
        }
    }

    fn expire_node_request(&mut self, uio: &UdpIoContext, node_id: NodeId) {
        uio.node_db.write().note_failure(
            &node_id, false, /* by_connection */
            true,  /* trusted_only */
        );
    }

    fn update_new_nodes(&mut self, uio: &UdpIoContext) {
        while self.in_flight_pings.len() < self.config.max_nodes_ping {
            match self.adding_nodes.pop() {
                Some(next) => self.try_ping(uio, next),
                None => break,
            }
        }
    }

    fn discover(&mut self, uio: &UdpIoContext) {
        let discovery_round = match self.discovery_round {
            Some(r) => r,
            None => return,
        };
        if discovery_round == DISCOVERY_MAX_STEPS {
            trace!("Discover stop due to beyond max round count.");
            self.stop();
            return;
        }
        trace!("Starting round {:?}", self.discovery_round);
        let mut tried_count = 0;

        if self.disc_option.general {
            tried_count += self.discover_without_tag(uio);
        }

        if self.disc_option.archive {
            let key: String = NODE_TAG_NODE_TYPE.into();
            let value: String = NODE_TAG_ARCHIVE.into();
            tried_count += self.discover_with_tag(uio, &key, &value);
        }

        if tried_count == 0 {
            trace!("Discovery stop due to 0 tried_count");
            self.stop();
            return;
        }
        self.discovery_round = Some(discovery_round + 1);
    }

    fn send_find_node(
        &mut self, uio: &UdpIoContext, node: &NodeEntry,
        tag_key: Option<String>, tag_value: Option<String>,
    ) -> Result<(), Error>
    {
        let msg = FindNodeMessage::new(
            tag_key,
            tag_value,
            self.config.expire_timestamp(),
        );

        self.send_packet(
            uio,
            PACKET_FIND_NODE,
            &node.endpoint.udp_address(),
            &msg.rlp_bytes(),
        )?;

        self.in_flight_find_nodes
            .insert(node.id.clone(), FindNodeRequest::default());

        trace!("Sent FindNode to {:?}", node);
        Ok(())
    }

    pub fn round(&mut self, uio: &UdpIoContext) {
        self.check_expired(uio, Instant::now());
        self.update_new_nodes(uio);

        if self.discovery_round.is_some() {
            self.discover(uio);
        } else if self.in_flight_pings.is_empty() && !self.discovery_initiated {
            // Start discovering if the first pings have been sent (or timed
            // out)
            self.discovery_initiated = true;
            self.refresh();
        }
    }

    pub fn refresh(&mut self) {
        if self.discovery_round.is_none() {
            self.start();
        }
    }

    fn discover_without_tag(&mut self, uio: &UdpIoContext) -> usize {
        let sampled: Vec<NodeEntry> = uio
            .node_db
            .read()
            .sample_trusted_nodes(
                self.config.discover_node_count,
                &self.ip_filter,
            )
            .into_iter()
            .filter(|n| !self.discovery_nodes.contains(&n.id))
            .collect();

        self.discover_with_nodes(uio, sampled, None, None)
    }

    fn discover_with_nodes(
        &mut self, uio: &UdpIoContext, nodes: Vec<NodeEntry>,
        tag_key: Option<String>, tag_value: Option<String>,
    ) -> usize
    {
        let mut sent = 0;

        for node in nodes {
            match self.send_find_node(
                uio,
                &node,
                tag_key.clone(),
                tag_value.clone(),
            ) {
                Ok(_) => {
                    self.discovery_nodes.insert(node.id);
                    sent += 1;
                }
                Err(e) => {
                    warn!(
                        "Error sending node discovery packet for {:?}: {:?}",
                        node.endpoint, e
                    );
                }
            }
        }

        sent
    }

    fn discover_with_tag(
        &mut self, uio: &UdpIoContext, key: &String, value: &String,
    ) -> usize {
        let tagged_nodes = uio.node_db.read().sample_trusted_node_ids_with_tag(
            self.config.discover_node_count / 2,
            key,
            value,
        );

        let count = self.config.discover_node_count - tagged_nodes.len() as u32;
        let random_nodes = uio
            .node_db
            .read()
            .sample_trusted_node_ids(count, &self.ip_filter);

        let sampled: HashSet<NodeId> = tagged_nodes
            .into_iter()
            .chain(random_nodes)
            .filter(|id| !self.discovery_nodes.contains(id))
            .collect();

        let sampled_nodes = uio
            .node_db
            .read()
            .get_nodes(sampled, true /* trusted_only */);

        self.discover_with_nodes(
            uio,
            sampled_nodes,
            Some(key.clone()),
            Some(value.clone()),
        )
    }
}

fn assemble_packet(
    packet_id: u8, bytes: &[u8], secret: &Secret,
) -> Result<Bytes, Error> {
    let mut packet = Bytes::with_capacity(bytes.len() + 32 + 65 + 1 + 1);
    packet.push(UDP_PROTOCOL_DISCOVERY);
    packet.resize(1 + 32 + 65, 0); // Filled in below
    packet.push(packet_id);
    packet.extend_from_slice(bytes);

    let hash = keccak(&packet[(1 + 32 + 65)..]);
    let signature = match sign(secret, &hash) {
        Ok(s) => s,
        Err(e) => {
            warn!("Error signing UDP packet");
            return Err(Error::from(e));
        }
    };
    packet[(1 + 32)..(1 + 32 + 65)].copy_from_slice(&signature[..]);
    let signed_hash = keccak(&packet[(1 + 32)..]);
    packet[1..=32].copy_from_slice(signed_hash.as_bytes());
    Ok(packet)
}

pub struct DiscoveryOption {
    // discover nodes without any tag filter
    pub general: bool,
    // discover archive nodes
    pub archive: bool,
}

#[derive(RlpEncodable, RlpDecodable)]
struct FindNodeMessage {
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
    pub expire_timestamp: u64,
}

impl FindNodeMessage {
    fn new(
        tag_key: Option<String>, tag_value: Option<String>,
        expire_timestamp: u64,
    ) -> Self
    {
        FindNodeMessage {
            tag_key,
            tag_value,
            expire_timestamp,
        }
    }

    fn sample(
        &self, node_db: &NodeDatabase, ip_filter: &IpFilter,
        discover_node_count: u32,
    ) -> Result<Vec<NodeEntry>, Error>
    {
        let key = match self.tag_key {
            Some(ref key) => key,
            None => {
                return Ok(node_db
                    .sample_trusted_nodes(discover_node_count, ip_filter))
            }
        };

        let value = match self.tag_value {
            Some(ref value) => value,
            None => return Err(ErrorKind::BadProtocol.into()),
        };

        let ids = node_db.sample_trusted_node_ids_with_tag(
            discover_node_count,
            key,
            value,
        );

        Ok(node_db.get_nodes(ids, true /* trusted_onlys */))
    }
}

#[derive(RlpEncodable, RlpDecodable)]
struct NeighborsChunkMessage {
    neighbors: Vec<NodeEntry>,
    num_chunks: usize,
    chunk_index: usize,
}

impl NeighborsChunkMessage {
    fn chunks(
        neighbors: Vec<NodeEntry>, chunk_size: usize,
    ) -> Vec<NeighborsChunkMessage> {
        let chunks = neighbors.chunks(chunk_size);
        let num_chunks = chunks.len();
        chunks
            .enumerate()
            .map(|(chunk_index, chunk)| NeighborsChunkMessage {
                neighbors: chunk.to_vec(),
                num_chunks,
                chunk_index,
            })
            .collect()
    }

    fn validate(&self) -> Result<(), Error> {
        if self.neighbors.is_empty() {
            debug!("invalid NeighborsChunkMessage, neighbors is empty");
            bail!(ErrorKind::BadProtocol);
        }

        if self.num_chunks == 0 {
            debug!("invalid NeighborsChunkMessage, num_chunks is zero");
            bail!(ErrorKind::BadProtocol);
        }

        if self.chunk_index >= self.num_chunks {
            debug!(
                "invalid NeighborsChunkMessage, chunk index is invalid, len = {}, index = {}",
                self.num_chunks, self.chunk_index
            );
            bail!(ErrorKind::BadProtocol);
        }

        Ok(())
    }

    /// updates the find node request with this message.
    /// Return Ok(true) if new chunk received.
    /// Return Ok(false) if duplicated chunk received.
    /// Return Err if validation failed.
    fn update(&self, request: &mut FindNodeRequest) -> Result<bool, Error> {
        self.validate()?;

        if request.num_chunks == 0 {
            request.num_chunks = self.num_chunks;
        } else if request.num_chunks != self.num_chunks {
            debug!("invalid NeighborsChunkMessage, chunk number mismatch, requested = {}, responded = {}", request.num_chunks, self.num_chunks);
            bail!(ErrorKind::BadProtocol);
        }

        if !request.received_chunks.insert(self.chunk_index) {
            debug!("duplicated NeighborsChunkMessage");
            return Ok(false);
        }

        Ok(true)
    }
}
