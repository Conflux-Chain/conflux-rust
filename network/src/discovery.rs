// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hash::keccak,
    node_table::{NodeId, *},
    service::{UdpIoContext, MAX_DATAGRAM_SIZE, UDP_PROTOCOL_DISCOVERY},
    Error, ErrorKind, IpFilter,
};
use cfx_bytes::Bytes;
use cfx_types::{H256, H520};
use keylib::{recover, sign, KeyPair, Secret};
use rlp::{Rlp, RlpStream};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DISCOVER_PROTOCOL_VERSION: u32 = 1;

const DISCOVERY_MAX_STEPS: u16 = 4; // Max iterations of discovery. (discover)

const PACKET_PING: u8 = 1;
const PACKET_PONG: u8 = 2;
const PACKET_FIND_NODE: u8 = 3;
const PACKET_NEIGHBOURS: u8 = 4;

const PING_TIMEOUT: Duration = Duration::from_millis(500);
const FIND_NODE_TIMEOUT: Duration = Duration::from_secs(2);
const EXPIRY_TIME: Duration = Duration::from_secs(20);

pub const DISCOVER_NODES_COUNT: u32 = 16;
const MAX_NODES_PING: usize = 32; // Max nodes to add/ping at once

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
    // Number of items sent by the node
    response_count: usize,
    // Whether the request have been answered yet
    answered: bool,
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
}

impl Discovery {
    pub fn new(
        key: &KeyPair, public: NodeEndpoint, ip_filter: IpFilter,
    ) -> Discovery {
        Discovery {
            id: *key.public(),
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

        if self.in_flight_pings.len() < MAX_NODES_PING {
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
        append_expiration(&mut rlp);
        let hash = self.send_packet(
            uio,
            PACKET_PING,
            &node.endpoint.udp_address(),
            &rlp.drain(),
        )?;

        self.in_flight_pings.insert(
            node.id,
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
        let hash = H256::from(&packet[1..(1 + 32)]);
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
                self.on_ping(uio, &rlp, &node_id, &from, &hash_signed)
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
        append_expiration(&mut response);
        self.send_packet(uio, PACKET_PONG, from, &response.drain())?;

        let entry = NodeEntry {
            id: *node_id,
            endpoint: pong_to.clone(),
        };
        if !entry.endpoint.is_valid() {
            debug!("Got bad address: {:?}", entry);
        } else if !self.is_allowed(&entry) {
            debug!("Address not allowed: {:?}", entry);
        } else {
            let mut trusted = uio.trusted_nodes.write();
            let mut untrusted = uio.untrusted_nodes.write();

            if trusted.contains(&entry.id) {
                debug_assert!(!untrusted.contains(&entry.id));
                trusted.note_success(&entry.id, false, None);
            } else {
                let mut node = Node::new(entry.id, entry.endpoint);
                node.last_contact = Some(NodeContact::success());
                untrusted.update_last_contact(node);
            }
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
            uio.discover_trusted_node(&node);
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
        let timestamp: u64 = rlp.val_at(0)?;
        self.check_timestamp(timestamp)?;

        let neighbors = uio
            .trusted_nodes
            .read()
            .sample_nodes(DISCOVER_NODES_COUNT, &self.ip_filter);
        let mut packets: Vec<Vec<u8>> = {
            let limit = (MAX_DATAGRAM_SIZE - (1 + 109)) / 90;
            let chunks = neighbors.chunks(limit);
            let packets = chunks.map(|c| {
                let mut rlp = RlpStream::new_list(2);
                rlp.begin_list(c.len());
                for n in c {
                    rlp.begin_list(4);
                    n.endpoint.to_rlp(&mut rlp);
                    rlp.append(&n.id);
                }
                append_expiration(&mut rlp);
                rlp.out()
            });
            packets.collect()
        };

        for p in packets.drain(..) {
            self.send_packet(uio, PACKET_NEIGHBOURS, from, &p)?;
        }
        trace!("Sent {} Neighbours to {:?}", neighbors.len(), &from);
        Ok(())
    }

    fn on_neighbours(
        &mut self, uio: &UdpIoContext, rlp: &Rlp, node_id: &NodeId,
        from: &SocketAddr,
    ) -> Result<(), Error>
    {
        let results_count = rlp.at(0)?.item_count()?;

        let is_expected = match self.in_flight_find_nodes.entry(*node_id) {
            Entry::Occupied(mut entry) => {
                let expected = {
                    let request = entry.get_mut();
                    // Mark the request as answered
                    request.answered = true;
                    if request.response_count + results_count
                        <= DISCOVER_NODES_COUNT as usize
                    {
                        request.response_count += results_count;
                        true
                    } else {
                        debug!("Got unexpected Neighbors from {:?} ; oversized packet ({} + {}) node_id={:#x}", &from, request.response_count, results_count, node_id);
                        false
                    }
                };
                if entry.get().response_count == DISCOVER_NODES_COUNT as usize {
                    entry.remove();
                }
                expected
            }
            Entry::Vacant(_) => {
                debug!("Got unexpected Neighbors from {:?} ; couldn't find node_id={:#x}", &from, node_id);
                false
            }
        };

        if !is_expected {
            return Ok(());
        }

        trace!("Got {} Neighbours from {:?}", results_count, &from);
        for r in rlp.at(0)?.iter() {
            let endpoint = NodeEndpoint::from_rlp(&r)?;
            if !endpoint.is_valid() {
                debug!("Bad address: {:?}", endpoint);
                continue;
            }
            let node_id: NodeId = r.val_at(3)?;
            if node_id == self.id {
                continue;
            }
            let entry = NodeEntry {
                id: node_id,
                endpoint,
            };
            if !self.is_allowed(&entry) {
                debug!("Address not allowed: {:?}", entry);
                continue;
            }
            self.try_ping(uio, entry);
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
        self.in_flight_pings.retain(|node_id, ping_request| {
            if time.duration_since(ping_request.sent_at) > PING_TIMEOUT {
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
        self.in_flight_find_nodes.retain(|node_id, find_node_request| {
            if time.duration_since(find_node_request.sent_at) > FIND_NODE_TIMEOUT {
                if !find_node_request.answered {
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
        uio.trusted_nodes.write().note_failure(&node_id, false);
    }

    fn update_new_nodes(&mut self, uio: &UdpIoContext) {
        while self.in_flight_pings.len() < MAX_NODES_PING {
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
        {
            let discover_targets = uio
                .trusted_nodes
                .read()
                .sample_nodes(DISCOVER_NODES_COUNT, &self.ip_filter)
                .into_iter();
            let discover_targets = discover_targets
                .filter(|x| !self.discovery_nodes.contains(&x.id))
                .take(DISCOVER_NODES_COUNT as usize)
                .collect::<Vec<_>>();
            for r in discover_targets {
                match self.send_find_node(uio, &r) {
                    Ok(()) => {
                        self.discovery_nodes.insert(r.id);
                        tried_count += 1;
                    }
                    Err(e) => {
                        warn!("Error sending node discovery packet for {:?}: {:?}", &r.endpoint, e);
                    }
                };
            }
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
    ) -> Result<(), Error> {
        let mut rlp = RlpStream::new_list(1);
        append_expiration(&mut rlp);
        self.send_packet(
            uio,
            PACKET_FIND_NODE,
            &node.endpoint.udp_address(),
            &rlp.drain(),
        )?;

        self.in_flight_find_nodes.insert(
            node.id,
            FindNodeRequest {
                sent_at: Instant::now(),
                response_count: 0,
                answered: false,
            },
        );

        trace!("Sent FindNode to {:?}", &node.endpoint);
        Ok(())
    }

    pub fn round(&mut self, uio: &UdpIoContext) {
        self.check_expired(uio, Instant::now());
        self.update_new_nodes(uio);

        if self.discovery_round.is_some() {
            self.discover(uio);
        } else if self.in_flight_pings.len() == 0 && !self.discovery_initiated {
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
}

fn append_expiration(rlp: &mut RlpStream) {
    let expiry = SystemTime::now() + EXPIRY_TIME;
    let timestamp = expiry
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    rlp.append(&timestamp);
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
    packet[1..(1 + 32)].copy_from_slice(&signed_hash);
    Ok(packet)
}
