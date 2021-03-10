// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{ip_utils::*, AllowIP, Error, ErrorKind, IpFilter};
use cfx_types::H512;
use enum_map::EnumMap;
use io::*;
use rand::{self, prelude::SliceRandom, Rng};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_derive::Serialize;
use serde_json;
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    fs,
    hash::{Hash, Hasher},
    net::{
        Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
        ToSocketAddrs,
    },
    path::{Path, PathBuf},
    slice,
    str::FromStr,
    time::{self, Duration, SystemTime},
};
use strum::IntoEnumIterator;

/// Node public key
pub type NodeId = H512;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Node address info
pub struct NodeEndpoint {
    /// IP(V4 or V6) address
    pub address: SocketAddr,
    /// Connection port.
    pub udp_port: u16,
}

impl NodeEndpoint {
    pub fn udp_address(&self) -> SocketAddr {
        match self.address {
            SocketAddr::V4(a) => {
                SocketAddr::V4(SocketAddrV4::new(*a.ip(), self.udp_port))
            }
            SocketAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(
                *a.ip(),
                self.udp_port,
                a.flowinfo(),
                a.scope_id(),
            )),
        }
    }

    pub fn is_allowed(&self, filter: &IpFilter) -> bool {
        (self.is_allowed_by_predefined(&filter.predefined)
            || filter
                .custom_allow
                .iter()
                .any(|ipnet| self.address.ip().is_within(ipnet)))
            && !filter
                .custom_block
                .iter()
                .any(|ipnet| self.address.ip().is_within(ipnet))
    }

    pub fn is_allowed_by_predefined(&self, filter: &AllowIP) -> bool {
        match filter {
            AllowIP::All => true,
            AllowIP::Private => self.address.ip().is_usable_private(),
            AllowIP::Public => self.address.ip().is_usable_public(),
            AllowIP::None => false,
        }
    }

    pub fn from_rlp(rlp: &Rlp) -> Result<Self, DecoderError> {
        let tcp_port = rlp.val_at::<u16>(2)?;
        let udp_port = rlp.val_at::<u16>(1)?;
        let addr_bytes = rlp.at(0)?.data()?;
        let address = match addr_bytes.len() {
            4 => Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                ),
                tcp_port,
            ))),
            16 => {
                let mut o: [u16; 8] = [0; 8];
                for i in 0..8 {
                    o[i] = ((addr_bytes[2 * i + 1] as u16) << 8)
                        | (addr_bytes[2 * i] as u16);
                }
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(
                        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7],
                    ),
                    tcp_port,
                    0,
                    0,
                )))
            }
            _ => Err(DecoderError::RlpInconsistentLengthAndData),
        }?;
        Ok(NodeEndpoint { address, udp_port })
    }

    pub fn to_rlp(&self, rlp: &mut RlpStream) {
        match self.address {
            SocketAddr::V4(a) => {
                rlp.append(&(&a.ip().octets()[..]));
            }
            SocketAddr::V6(a) => unsafe {
                let o: *const u8 = a.ip().segments().as_ptr() as *const u8;
                rlp.append(&slice::from_raw_parts(o, 16));
            },
        };
        rlp.append(&self.udp_port);
        rlp.append(&self.address.port());
    }

    pub fn to_rlp_list(&self, rlp: &mut RlpStream) {
        rlp.begin_list(3);
        self.to_rlp(rlp);
    }

    /// Validates that the port is not 0 and address IP is specified
    pub fn is_valid(&self) -> bool {
        self.udp_port != 0
            && self.address.port() != 0
            && match self.address {
                SocketAddr::V4(a) => !a.ip().is_unspecified(),
                SocketAddr::V6(a) => !a.ip().is_unspecified(),
            }
    }
}

impl FromStr for NodeEndpoint {
    type Err = Error;

    /// Create endpoint from string. Performs name resolution if given a host
    /// name.
    fn from_str(s: &str) -> Result<NodeEndpoint, Error> {
        let address = s.to_socket_addrs().map(|mut i| i.next());
        match address {
            Ok(Some(a)) => Ok(NodeEndpoint {
                address: a,
                udp_port: a.port(),
            }),
            Ok(None) => bail!(ErrorKind::AddressResolve(None)),
            Err(_) => Err(ErrorKind::AddressParse.into()), /* always an io::Error of InvalidInput kind */
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeEntry {
    pub id: NodeId,
    pub endpoint: NodeEndpoint,
}

impl Encodable for NodeEntry {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        self.endpoint.to_rlp(s);
        s.append(&self.id);
    }
}

impl Decodable for NodeEntry {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(NodeEntry {
            id: rlp.val_at(3)?,
            endpoint: NodeEndpoint::from_rlp(rlp)?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PeerType {
    _Required,
    Optional,
}

/// A type for representing an interaction (contact) with a node at a given time
/// that was either a success or a failure.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeContact {
    Success(SystemTime),
    Failure(SystemTime),
    Demoted(SystemTime),
}

impl NodeContact {
    pub fn success() -> NodeContact { NodeContact::Success(SystemTime::now()) }

    pub fn failure() -> NodeContact { NodeContact::Failure(SystemTime::now()) }

    pub fn demoted() -> NodeContact { NodeContact::Demoted(SystemTime::now()) }

    pub fn is_demoted(&self) -> bool { matches!(self, NodeContact::Demoted(_)) }

    pub fn time(&self) -> SystemTime {
        match *self {
            NodeContact::Success(t)
            | NodeContact::Failure(t)
            | NodeContact::Demoted(t) => t,
        }
    }

    pub fn success_for_duration(&self, due: Duration) -> bool {
        let mut res = false;
        match *self {
            NodeContact::Success(t) => {
                if let Ok(d) = t.elapsed() {
                    if d > due {
                        res = true;
                    }
                }
            }
            _ => {}
        };

        res
    }

    /// Filters and old contact, returning `None` if it happened longer than a
    /// week ago.
    #[allow(dead_code)]
    fn recent(&self) -> Option<&NodeContact> {
        let t = self.time();
        if let Ok(d) = t.elapsed() {
            if d < Duration::from_secs(60 * 60 * 24 * 7) {
                return Some(self);
            }
        }

        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: NodeId,
    pub endpoint: NodeEndpoint,

    // Updated by both udp ping/pong message in discovery protocol
    // and tcp connection event.
    // This metric can be used in prioritizing selection of peers
    // to establish outgoing connections.
    // It can also be used in considering demoting a
    // trusted peer to untrusted.
    pub last_contact: Option<NodeContact>,
    // Updated by tcp connection event.
    // This metric is used to consider when to promote untrusted
    // peers to trusted. This is a runtime information which
    // does not need to be made persistent.
    pub last_connected: Option<NodeContact>,
    pub stream_token: Option<StreamToken>,
    // Generally, it is used by protocol handler layer to attach
    // some tags to node, so as to:
    // 1. Sampling nodes with special tags, e.g.
    //     - archive nodes first
    //     - good credit nodes first
    //     - good network nodes first
    // 2. Refuse incoming connection from node with special tags.
    pub tags: HashMap<String, String>,
}

impl Node {
    pub fn new(id: NodeId, endpoint: NodeEndpoint) -> Node {
        Node {
            id,
            endpoint,
            last_contact: None,
            last_connected: None,
            stream_token: None,
            tags: Default::default(),
        }
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if self.endpoint.udp_port != self.endpoint.address.port() {
            write!(
                f,
                "cfxnode://{:x}@{}+{}",
                self.id, self.endpoint.address, self.endpoint.udp_port
            )?;
        } else {
            write!(f, "cfxnode://{:x}@{}", self.id, self.endpoint.address)?;
        }
        Ok(())
    }
}

impl FromStr for Node {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (id, endpoint) =
            if let Some(id_and_address_str) = s.strip_prefix("cfxnode://") {
                // A node url with format "cfxnode://ID@IP:PORT"
                let delimiter_index = id_and_address_str
                    .find("@")
                    .ok_or(ErrorKind::AddressParse)?;
                (
                    id_and_address_str[..delimiter_index]
                        .parse()
                        .map_err(|_| ErrorKind::InvalidNodeId)?,
                    NodeEndpoint::from_str(
                        &id_and_address_str[delimiter_index + 1..],
                    )?,
                )
            } else {
                // A simple address without node id.
                (NodeId::default(), NodeEndpoint::from_str(s)?)
            };

        Ok(Node {
            id,
            endpoint,
            last_contact: None,
            last_connected: None,
            stream_token: None,
            tags: Default::default(),
        })
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool { self.id == other.id }
}

impl Eq for Node {}

impl Hash for Node {
    fn hash<H>(&self, state: &mut H)
    where H: Hasher {
        self.id.hash(state)
    }
}

const MAX_NODES: usize = 4096;

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Enum, EnumIter)]
enum NodeReputation {
    Success = 0,
    Unknown = 1,
    Failure = 2,
    Demoted = 3,
}

const NODE_REPUTATION_LEVEL_COUNT: usize = 3;

impl Default for NodeReputation {
    fn default() -> Self { NodeReputation::Unknown }
}

#[derive(Default, Clone, Copy)]
struct NodeReputationIndex(NodeReputation, usize);

/// Node table backed by disk file.
pub struct NodeTable {
    /// A vector list of nodes for each reputation level
    node_reputation_table: EnumMap<NodeReputation, Vec<Node>>,
    /// Map node id to the reputation level and the index in the above table
    node_index: HashMap<NodeId, NodeReputationIndex>,
    useless_nodes: HashSet<NodeId>,
    path: Option<PathBuf>,
}

impl NodeTable {
    pub fn new(dir: Option<String>, filename: &str) -> NodeTable {
        let path = dir.and_then(|dir| {
            let mut buf = PathBuf::from(dir);
            buf.push(filename);
            Some(buf)
        });

        let mut node_table = NodeTable {
            node_reputation_table: EnumMap::default(),
            node_index: HashMap::new(),
            path,
            useless_nodes: HashSet::new(),
        };

        node_table.load_from_file();
        node_table
    }

    fn node_reputation(contact: &Option<NodeContact>) -> NodeReputation {
        if let Some(contact) = contact {
            match contact {
                NodeContact::Success(_) => NodeReputation::Success,
                NodeContact::Failure(_) => NodeReputation::Failure,
                NodeContact::Demoted(_) => NodeReputation::Demoted,
                //_ => panic!("Unknown contact information!"),
            }
        } else {
            NodeReputation::Unknown
        }
    }

    fn load_from_file(&mut self) {
        let path = match self.path {
            Some(ref path) => path,
            None => return,
        };

        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) => {
                debug!("node table file not found: {:?}", e);
                return;
            }
        };
        let res: Result<json::NodeTable, _> = serde_json::from_reader(file);
        match res {
            Ok(table) => {
                for n in table.nodes {
                    let node = n.into_node();
                    if let Some(node) = node {
                        if !self.node_index.contains_key(&node.id) {
                            let node_rep =
                                Self::node_reputation(&node.last_contact);
                            self.add_to_reputation_level(node_rep, node);
                        } else {
                            warn!("There exist multiple entries for same node id: {:?}", node.id);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Error reading node table file: {:?}", e);
            }
        }
    }

    pub fn sample_nodes(
        &self, count: u32, _filter: &IpFilter,
    ) -> Vec<NodeEntry> {
        let mut nodes: Vec<NodeEntry> = Vec::new();
        for _i in 0..count {
            let mut rng = rand::thread_rng();
            let node_rep_idx = rng.gen::<usize>() % NODE_REPUTATION_LEVEL_COUNT;
            let node_rep = NodeReputation::iter().nth(node_rep_idx).unwrap();
            let node_rep_vec = &self.node_reputation_table[node_rep];
            if !node_rep_vec.is_empty() {
                let idx = rng.gen::<usize>() % node_rep_vec.len();
                let n = &node_rep_vec[idx];
                nodes.push(NodeEntry {
                    id: n.id,
                    endpoint: n.endpoint.clone(),
                });
            }
        }
        let mut unique_nodes: Vec<NodeEntry> = Vec::new();
        let mut nodes_set: HashSet<NodeId> = HashSet::new();
        for n in nodes {
            if !nodes_set.contains(&n.id) {
                nodes_set.insert(n.id);
                unique_nodes.push(n);
            }
        }
        unique_nodes
    }

    /// Return a random sample set of nodes inside the table
    pub fn sample_node_ids(
        &self, count: u32, _filter: &IpFilter,
    ) -> HashSet<NodeId> {
        let mut node_id_set: HashSet<NodeId> = HashSet::new();
        let mut rng = rand::thread_rng();
        for _i in 0..count {
            let node_rep_idx = rng.gen::<usize>() % NODE_REPUTATION_LEVEL_COUNT;
            let node_rep = NodeReputation::iter().nth(node_rep_idx).unwrap();
            let node_rep_vec = &self.node_reputation_table[node_rep];
            if !node_rep_vec.is_empty() {
                let idx = rng.gen::<usize>() % node_rep_vec.len();
                let n = &node_rep_vec[idx];
                if !node_id_set.contains(&n.id) {
                    node_id_set.insert(n.id);
                }
            }
        }

        node_id_set
    }

    // If node exists, update last contact, insert otherwise.
    // Endpoint will be updated if node exists.
    pub fn update_last_contact(&mut self, node: Node) {
        let mut _index = NodeReputationIndex::default();
        let mut exist = false;
        if let Some(index) = self.node_index.get_mut(&node.id) {
            _index = *index;
            exist = true;
        }

        let target_node_rep = Self::node_reputation(&node.last_contact);

        if !exist {
            self.add_to_reputation_level(target_node_rep, node);
            return;
        }

        // check whether the node position will change
        if target_node_rep == _index.0 {
            let old_node = &mut self.node_reputation_table[_index.0][_index.1];
            old_node.last_contact = node.last_contact;
            old_node.endpoint = node.endpoint;
        } else {
            let mut removed_node =
                self.remove_from_reputation_level(&_index).unwrap();
            removed_node.last_contact = node.last_contact;
            removed_node.endpoint = node.endpoint;
            self.add_to_reputation_level(target_node_rep, removed_node);
        }
    }

    // This function does not preserve runtime connection information
    pub fn add_node(&mut self, mut node: Node, preserve_last_contact: bool) {
        debug!("NodeTable {:?} add_node {:?}", self.path, node);
        let mut _index = NodeReputationIndex::default();
        let mut exist = false;
        if let Some(index) = self.node_index.get_mut(&node.id) {
            _index = *index;
            exist = true;
        }

        if !exist {
            let target_node_rep = Self::node_reputation(&node.last_contact);
            self.add_to_reputation_level(target_node_rep, node);
            return;
        }

        if preserve_last_contact {
            let node_vec = &mut self.node_reputation_table[_index.0];
            node.last_contact = node_vec[_index.1].last_contact;
            node_vec[_index.1] = node;
        } else {
            let target_node_rep = Self::node_reputation(&node.last_contact);
            // check whether the node position will change
            if target_node_rep == _index.0 {
                self.node_reputation_table[_index.0][_index.1] = node;
            } else {
                self.remove_from_reputation_level(&_index);
                self.add_to_reputation_level(target_node_rep, node);
            }
        }
    }

    fn is_reputation_level_demoted(&self, index: &NodeReputationIndex) -> bool {
        index.0 == NodeReputation::Demoted
    }

    fn remove_from_reputation_level(
        &mut self, index: &NodeReputationIndex,
    ) -> Option<Node> {
        let node_rep_vec = &mut self.node_reputation_table[index.0];

        if node_rep_vec.is_empty() || index.1 >= node_rep_vec.len() {
            return None;
        }

        if node_rep_vec.len() - 1 == index.1 {
            // to remove the last item
            let node_id = node_rep_vec[node_rep_vec.len() - 1].id;
            self.node_index.remove(&node_id);
            return node_rep_vec.pop();
        }

        let tail_node = node_rep_vec.pop();
        if let Some(tail_node) = tail_node {
            let removed_node = node_rep_vec[index.1].clone();
            self.node_index.remove(&removed_node.id);
            if let Some(node_idx) = self.node_index.get_mut(&tail_node.id) {
                node_rep_vec[index.1] = tail_node;
                *node_idx = *index;
                Some(removed_node)
            } else {
                panic!("Should not happen!");
            }
        } else {
            panic!("Should not happen!");
        }
    }

    fn add_to_reputation_level(
        &mut self, node_rep: NodeReputation, node: Node,
    ) {
        let node_idx = self.node_reputation_table[node_rep].len();
        let node_table_idx = NodeReputationIndex(node_rep, node_idx);
        self.node_index.insert(node.id, node_table_idx);
        self.node_reputation_table[node_rep].push(node);
    }

    /// Returns a list of ordered nodes according to their most recent contact
    /// and filtering useless nodes. The algorithm for creating the sorted nodes
    /// is:
    /// - Contacts that aren't recent (older than 1 week) are discarded
    /// - (1) Nodes with a successful contact are ordered (most recent success
    ///   first)
    /// - (2) Nodes with unknown contact (older than 1 week or new nodes) are
    ///   randomly shuffled
    /// - (3) Nodes with a failed contact are ordered (oldest failure first)
    /// - The final result is the concatenation of (1), (2) and (3)
    fn ordered_entries(&self) -> Vec<&Node> {
        let mut success = Vec::new();
        let mut failures = Vec::new();
        let mut unknown = Vec::new();

        for n in self.node_reputation_table[NodeReputation::Success].iter() {
            if !self.useless_nodes.contains(&n.id) {
                success.push(n);
            }
        }

        for n in self.node_reputation_table[NodeReputation::Failure].iter() {
            if !self.useless_nodes.contains(&n.id) {
                failures.push(n);
            }
        }

        for n in self.node_reputation_table[NodeReputation::Unknown].iter() {
            if !self.useless_nodes.contains(&n.id) {
                unknown.push(n);
            }
        }

        success.sort_by(|a, b| {
            let a = a.last_contact.expect(
                "vector only contains values with defined last_contact; qed",
            );
            let b = b.last_contact.expect(
                "vector only contains values with defined last_contact; qed",
            );
            // inverse ordering, most recent successes come first
            b.time().cmp(&a.time())
        });

        failures.sort_by(|a, b| {
            let a = a.last_contact.expect(
                "vector only contains values with defined last_contact; qed",
            );
            let b = b.last_contact.expect(
                "vector only contains values with defined last_contact; qed",
            );
            // normal ordering, most distant failures come first
            a.time().cmp(&b.time())
        });

        unknown.shuffle(&mut rand::thread_rng());

        success.append(&mut unknown);
        success.append(&mut failures);
        success
    }

    /// Returns node ids sorted by failure percentage, for nodes with the same
    /// failure percentage the absolute number of failures is considered.
    pub fn nodes(&self, filter: &IpFilter) -> Vec<NodeId> {
        self.ordered_entries()
            .iter()
            .filter(|n| n.endpoint.is_allowed(&filter))
            .map(|n| n.id)
            .collect()
    }

    pub fn entries_with_filter(&self, filter: &IpFilter) -> Vec<NodeEntry> {
        self.ordered_entries()
            .iter()
            .filter(|n| n.endpoint.is_allowed(&filter))
            .map(|n| NodeEntry {
                endpoint: n.endpoint.clone(),
                id: n.id,
            })
            .collect()
    }

    /// Ordered list of all entries by failure percentage, for nodes with the
    /// same failure percentage the absolute number of failures is
    /// considered.
    pub fn entries(&self) -> Vec<NodeEntry> {
        self.ordered_entries()
            .iter()
            .map(|n| NodeEntry {
                endpoint: n.endpoint.clone(),
                id: n.id,
            })
            .collect()
    }

    /// Get particular node
    pub fn get_mut(&mut self, id: &NodeId) -> Option<&mut Node> {
        let index = self.node_index.get(id);
        if let Some(index) = index {
            Some(&mut self.node_reputation_table[index.0][index.1])
        } else {
            None
        }
    }

    /// Get particular node
    pub fn get(&self, id: &NodeId) -> Option<&Node> {
        let index = self.node_index.get(id);
        if let Some(index) = index {
            Some(&self.node_reputation_table[index.0][index.1])
        } else {
            None
        }
    }

    /// Check if a node exists in the table.
    pub fn contains(&self, id: &NodeId) -> bool {
        self.node_index.contains_key(id)
    }

    pub fn remove_with_id(&mut self, id: &NodeId) -> Option<Node> {
        let mut _index;
        if let Some(index) = self.node_index.get(id) {
            _index = *index;
        } else {
            return None;
        }

        self.remove_from_reputation_level(&_index)
    }

    /// Set last contact as failure or demoted for a node
    pub fn note_unsuccess_contact(
        &mut self, id: &NodeId, by_connection: bool,
        last_contact: Option<NodeContact>,
    )
    {
        let mut _index;
        if let Some(index) = self.node_index.get(id) {
            _index = *index;
        } else {
            return;
        }

        let target_node_rep = Self::node_reputation(&last_contact);
        if target_node_rep == _index.0 {
            let node = &mut self.node_reputation_table[_index.0][_index.1];
            node.last_contact = last_contact.clone();
            if by_connection {
                node.last_connected = last_contact.clone();
            }
        } else if self.is_reputation_level_demoted(&_index) {
            // Only update node.last_connected
            if by_connection {
                let node = &mut self.node_reputation_table[_index.0][_index.1];
                node.last_connected = last_contact.clone();
            }
        } else if let Some(mut node) =
            self.remove_from_reputation_level(&_index)
        {
            node.last_contact = last_contact.clone();
            if by_connection {
                node.last_connected = last_contact.clone();
            }
            self.add_to_reputation_level(target_node_rep, node);
        } else {
            panic!("Should not happen!");
        }
    }

    /// Set last contact as success for a node
    pub fn note_success(
        &mut self, id: &NodeId, by_connection: bool, token: Option<StreamToken>,
    ) {
        let mut _index;
        if let Some(index) = self.node_index.get(id) {
            _index = *index;
        } else {
            return;
        }

        let target_node_rep = NodeReputation::Success;
        if target_node_rep == _index.0 {
            let node = &mut self.node_reputation_table[_index.0][_index.1];
            node.last_contact = Some(NodeContact::success());
            if by_connection {
                node.last_connected = Some(NodeContact::success());
                if token != None {
                    node.stream_token = token;
                }
            }
        } else if self.is_reputation_level_demoted(&_index) {
            // Only update node.last_connected
            if by_connection {
                let node = &mut self.node_reputation_table[_index.0][_index.1];
                node.last_connected = Some(NodeContact::success());
                if token != None {
                    node.stream_token = token;
                }
            }
        } else if let Some(mut node) =
            self.remove_from_reputation_level(&_index)
        {
            node.last_contact = Some(NodeContact::success());
            if by_connection {
                node.last_connected = Some(NodeContact::success());
                if token != None {
                    node.stream_token = token;
                }
            }
            self.add_to_reputation_level(target_node_rep, node);
        } else {
            panic!("Should not happen!");
        }
    }

    /// Mark as useless, no further attempts to connect until next call to
    /// `clear_useless`.
    pub fn mark_as_useless(&mut self, id: &NodeId) {
        self.useless_nodes.insert(id.clone());
    }

    /// Attempt to connect to useless nodes again.
    pub fn clear_useless(&mut self) { self.useless_nodes.clear(); }

    /// Save the (un)trusted_nodes.json file.
    pub fn save(&self) {
        let path = match self.path {
            Some(ref path) => Path::new(path),
            None => return,
        };

        if let Some(dir) = path.parent() {
            if let Err(e) = fs::create_dir_all(dir) {
                warn!("Error creating node table directory: {:?}", e);
                return;
            }
        }

        let node_ids = self.nodes(&IpFilter::default());
        let nodes = node_ids
            .into_iter()
            .map(|id| {
                let index = &self.node_index[&id];
                &self.node_reputation_table[index.0][index.1]
            })
            .take(MAX_NODES)
            .map(Into::into)
            .collect();
        let table = json::NodeTable { nodes };

        match fs::File::create(&path) {
            Ok(file) => {
                if let Err(e) = serde_json::to_writer_pretty(file, &table) {
                    warn!("Error writing node table file: {:?}", e);
                }
            }
            Err(e) => {
                warn!("Error creating node table file: {:?}", e);
            }
        }
    }

    pub fn all(&self) -> Vec<NodeId> {
        self.node_index.keys().copied().collect()
    }
}

impl Drop for NodeTable {
    fn drop(&mut self) { self.save(); }
}

/// Check if node url is valid
pub fn validate_node_url(url: &str) -> Option<Error> {
    match Node::from_str(url) {
        Ok(_) => None,
        Err(e) => Some(e),
    }
}

mod json {
    use super::*;

    #[derive(Serialize, Deserialize)]
    pub struct NodeTable {
        pub nodes: Vec<Node>,
    }

    #[derive(Serialize, Deserialize)]
    pub enum NodeContact {
        #[serde(rename = "success")]
        Success(u64),
        #[serde(rename = "failure")]
        Failure(u64),
        #[serde(rename = "demoted")]
        Demoted(u64),
    }

    impl NodeContact {
        pub fn into_node_contact(self) -> super::NodeContact {
            match self {
                NodeContact::Success(s) => super::NodeContact::Success(
                    time::UNIX_EPOCH + Duration::from_secs(s),
                ),
                NodeContact::Failure(s) => super::NodeContact::Failure(
                    time::UNIX_EPOCH + Duration::from_secs(s),
                ),
                NodeContact::Demoted(s) => super::NodeContact::Demoted(
                    time::UNIX_EPOCH + Duration::from_secs(s),
                ),
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct Node {
        pub url: String,
        pub last_contact: Option<NodeContact>,
        pub tags: HashMap<String, String>,
    }

    impl Node {
        pub fn into_node(self) -> Option<super::Node> {
            match super::Node::from_str(&self.url) {
                Ok(mut node) => {
                    node.last_contact =
                        self.last_contact.map(NodeContact::into_node_contact);
                    node.tags = self.tags;
                    Some(node)
                }
                _ => None,
            }
        }
    }

    impl<'a> From<&'a super::Node> for Node {
        fn from(node: &'a super::Node) -> Self {
            let last_contact = node.last_contact.and_then(|c| match c {
                super::NodeContact::Success(t) => t
                    .duration_since(time::UNIX_EPOCH)
                    .ok()
                    .map(|d| NodeContact::Success(d.as_secs())),
                super::NodeContact::Failure(t) => t
                    .duration_since(time::UNIX_EPOCH)
                    .ok()
                    .map(|d| NodeContact::Failure(d.as_secs())),
                super::NodeContact::Demoted(t) => t
                    .duration_since(time::UNIX_EPOCH)
                    .ok()
                    .map(|d| NodeContact::Demoted(d.as_secs())),
            });

            Node {
                url: format!("{}", node),
                last_contact,
                tags: node.tags.clone(),
            }
        }
    }
}
