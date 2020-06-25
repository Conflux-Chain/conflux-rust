// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(deprecated)]
extern crate io;
#[macro_use]
extern crate log;
extern crate mio;
extern crate parking_lot;
extern crate slab;
#[macro_use]
extern crate error_chain;
extern crate bytes;
extern crate ipnetwork;
extern crate rlp;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate enum_map;
extern crate igd;
extern crate keccak_hash as hash;
extern crate libc;
extern crate parity_path;
extern crate rand;
#[macro_use]
extern crate enum_map_derive;
extern crate strum;
#[macro_use]
extern crate strum_macros;
extern crate cfxkey as keylib;
extern crate keccak_hash;

pub const PROTOCOL_ID_SIZE: usize = 3;
pub type ProtocolId = [u8; PROTOCOL_ID_SIZE];
pub type HandlerWorkType = u8;
pub type PeerId = usize;

mod connection;
mod discovery;
mod error;
mod handshake;
mod ip;
mod ip_utils;
mod node_database;
pub mod node_table;
pub mod service;
mod session;
mod session_manager;
pub mod throttling;

pub use crate::{
    error::{DisconnectReason, Error, ErrorKind, ThrottlingReason},
    ip::SessionIpLimitConfig,
    node_table::Node,
    service::NetworkService,
    session::SessionDetails,
};
pub use io::TimerToken;

use crate::{
    node_table::NodeId,
    service::{
        ProtocolVersion, DEFAULT_CONNECTION_LIFETIME_FOR_PROMOTION,
        DEFAULT_DISCOVERY_REFRESH_TIMEOUT, DEFAULT_DISCOVERY_ROUND_TIMEOUT,
        DEFAULT_FAST_DISCOVERY_REFRESH_TIMEOUT, DEFAULT_HOUSEKEEPING_TIMEOUT,
        DEFAULT_NODE_TABLE_TIMEOUT,
    },
};
use ipnetwork::{IpNetwork, IpNetworkError};
use keylib::Secret;
use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_derive::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::{self, FromStr},
    sync::Arc,
    time::Duration,
};

pub const NODE_TAG_NODE_TYPE: &str = "node_type";
pub const NODE_TAG_ARCHIVE: &str = "archive";

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkConfiguration {
    pub is_consortium: bool,
    /// Network identifier
    pub id: u64,
    /// Directory path to store general network configuration. None means
    /// nothing will be saved
    pub config_path: Option<String>,
    pub listen_address: Option<SocketAddr>,
    /// IP address to advertise. Detected automatically if none.
    pub public_address: Option<SocketAddr>,
    pub udp_port: Option<u16>,
    /// Enable NAT configuration
    pub nat_enabled: bool,
    /// Enable discovery
    pub discovery_enabled: bool,
    pub boot_nodes: Vec<String>,
    /// Use provided node key instead of default
    pub use_secret: Option<Secret>,
    /// Maximum number of outgoing peers
    pub max_outgoing_peers: usize,
    /// Maximum number of outgoing connections to archive nodes. 0 represents
    /// not required to connect to archive nodes. E.g. light node or full node
    /// need not to connect to archive nodes.
    pub max_outgoing_peers_archive: usize,
    /// Maximum number of incoming peers
    pub max_incoming_peers: usize,
    /// Maximum number of ongoing handshakes
    pub max_handshakes: usize,
    /// List of reserved node addresses.
    pub reserved_nodes: Vec<String>,
    /// IP filter
    pub ip_filter: IpFilter,
    /// Timeout duration for initiating peer connection management
    pub housekeeping_timeout: Duration,
    /// Timeout duration for refreshing discovery protocol
    /// when there are enough outgoing connections
    pub discovery_refresh_timeout: Duration,
    /// Timeout duration for refreshing discovery protocol
    /// when there are NOT enough outgoing connections
    pub fast_discovery_refresh_timeout: Duration,
    /// Period between consecutive rounds of the same current discovery process
    pub discovery_round_timeout: Duration,
    /// Timeout duration for persisting node table
    pub node_table_timeout: Duration,
    /// Connection lifetime threshold for promotion
    pub connection_lifetime_for_promotion: Duration,
    pub test_mode: bool,
    /// Maximum number of P2P nodes for subnet B (ip/16).
    pub subnet_quota: usize,
    pub session_ip_limit_config: SessionIpLimitConfig,
}

impl NetworkConfiguration {
    pub fn new(id: u64) -> Self {
        NetworkConfiguration {
            is_consortium: false,
            id,
            config_path: Some("./net_config".to_string()),
            listen_address: None,
            public_address: None,
            udp_port: None,
            nat_enabled: true,
            discovery_enabled: false,
            boot_nodes: Vec::new(),
            use_secret: None,
            max_outgoing_peers: 0,
            max_outgoing_peers_archive: 0,
            max_incoming_peers: 0,
            max_handshakes: 0,
            reserved_nodes: Vec::new(),
            ip_filter: IpFilter::default(),
            housekeeping_timeout: DEFAULT_HOUSEKEEPING_TIMEOUT,
            discovery_refresh_timeout: DEFAULT_DISCOVERY_REFRESH_TIMEOUT,
            fast_discovery_refresh_timeout:
                DEFAULT_FAST_DISCOVERY_REFRESH_TIMEOUT,
            discovery_round_timeout: DEFAULT_DISCOVERY_ROUND_TIMEOUT,
            node_table_timeout: DEFAULT_NODE_TABLE_TIMEOUT,
            connection_lifetime_for_promotion:
                DEFAULT_CONNECTION_LIFETIME_FOR_PROMOTION,
            test_mode: false,
            subnet_quota: 32,
            session_ip_limit_config: SessionIpLimitConfig::default(),
        }
    }

    pub fn new_with_port(id: u64, port: u16) -> NetworkConfiguration {
        let mut config = NetworkConfiguration::new(id);
        config.listen_address = Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            port,
        )));
        config
    }

    pub fn new_local(id: u64) -> NetworkConfiguration {
        let mut config = NetworkConfiguration::new(id);
        config.listen_address = Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            0,
        )));
        config
    }
}

/// Type of NAT resolving method
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NatType {
    Nothing,
    Any,
    UPnP,
    NatPMP,
}

#[derive(Clone)]
pub enum NetworkIoMessage {
    Start,
    AddHandler {
        handler: Arc<dyn NetworkProtocolHandler + Sync>,
        protocol: ProtocolId,
        version: ProtocolVersion,
    },
    /// Register a new protocol timer
    AddTimer {
        /// Protocol Id.
        protocol: ProtocolId,
        /// Timer token.
        token: TimerToken,
        /// Timer delay.
        delay: Duration,
    },
    DispatchWork {
        /// Protocol Id.
        protocol: ProtocolId,
        /// Work type.
        work_type: HandlerWorkType,
    },
    HandleProtocolMessage {
        protocol: ProtocolId,
        peer: PeerId,
        node_id: NodeId,
        data: Vec<u8>,
    },
}

pub trait NetworkProtocolHandler: Sync + Send {
    fn minimum_supported_version(&self) -> ProtocolVersion;

    fn initialize(&self, _io: &dyn NetworkContext);

    fn on_message(
        &self, io: &dyn NetworkContext, node_id: &NodeId, data: &[u8],
    );

    fn on_peer_connected(
        &self, io: &dyn NetworkContext, node_id: &NodeId,
        peer_protocol_version: ProtocolVersion,
    );

    fn on_peer_disconnected(&self, io: &dyn NetworkContext, node_id: &NodeId);

    fn on_timeout(&self, io: &dyn NetworkContext, timer: TimerToken);

    fn send_local_message(&self, _io: &dyn NetworkContext, _message: Vec<u8>);

    fn on_work_dispatch(
        &self, _io: &dyn NetworkContext, _work_type: HandlerWorkType,
    );
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum UpdateNodeOperation {
    Failure,
    Demotion,
    Remove,
}

pub trait NetworkContext {
    fn get_protocol(&self) -> ProtocolId;

    fn get_peer_connection_origin(&self, node_id: &NodeId) -> Option<bool>;

    fn send(
        &self, node_id: &NodeId, msg: Vec<u8>,
        min_protocol_version: ProtocolVersion,
        version_valid_till: ProtocolVersion, priority: SendQueuePriority,
    ) -> Result<(), Error>;

    fn disconnect_peer(
        &self, node_id: &NodeId, op: Option<UpdateNodeOperation>, reason: &str,
    );

    /// Register a new IO timer. 'IoHandler::timeout' will be called with the
    /// token.
    fn register_timer(
        &self, token: TimerToken, delay: Duration,
    ) -> Result<(), Error>;

    fn dispatch_work(&self, work_type: HandlerWorkType);

    fn is_peer_self(&self, _node_id: &NodeId) -> bool;

    fn self_node_id(&self) -> NodeId;
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub id: Option<NodeId>,
    /// There won't be many protocols so it's faster to use Vec than Map.
    pub peer_protocols: Vec<ProtocolInfo>,
    pub originated: bool,
    /// Packet header version of the peer.
    pub peer_header_version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub protocol: ProtocolId,
    pub version: ProtocolVersion,
}

impl Encodable for ProtocolInfo {
    fn rlp_append(&self, rlp: &mut RlpStream) {
        rlp.begin_list(2);
        rlp.append(&&self.protocol[..]);
        rlp.append(&self.version);
    }
}

impl Decodable for ProtocolInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let p: Vec<u8> = rlp.val_at(0)?;
        if p.len() != 3 {
            return Err(DecoderError::Custom(
                "Invalid subprotocol string length",
            ));
        }
        let mut protocol: ProtocolId = [0u8; 3];
        protocol.clone_from_slice(&p);
        Ok(ProtocolInfo {
            protocol,
            version: rlp.val_at(1)?,
        })
    }
}

impl PartialOrd for ProtocolInfo {
    fn partial_cmp(&self, other: &ProtocolInfo) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolInfo {
    fn cmp(&self, other: &ProtocolInfo) -> Ordering {
        self.protocol.cmp(&other.protocol)
    }
}

#[derive(Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub nodeid: NodeId,
    pub protocols: Vec<ProtocolInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpFilter {
    pub predefined: AllowIP,
    pub custom_allow: Vec<IpNetwork>,
    pub custom_block: Vec<IpNetwork>,
}

impl Default for IpFilter {
    fn default() -> Self {
        IpFilter {
            predefined: AllowIP::All,
            custom_allow: vec![],
            custom_block: vec![],
        }
    }
}

impl IpFilter {
    /// Attempt to parse the peer mode from a string.
    pub fn parse(s: &str) -> Result<IpFilter, IpNetworkError> {
        let mut filter = IpFilter::default();
        for f in s.split_whitespace() {
            match f {
                "all" => filter.predefined = AllowIP::All,
                "private" => filter.predefined = AllowIP::Private,
                "public" => filter.predefined = AllowIP::Public,
                "none" => filter.predefined = AllowIP::None,
                custom => {
                    if custom.starts_with('-') {
                        filter.custom_block.push(IpNetwork::from_str(
                            &custom.to_owned().split_off(1),
                        )?)
                    } else {
                        filter.custom_allow.push(IpNetwork::from_str(custom)?)
                    }
                }
            }
        }
        Ok(filter)
    }
}

/// IP filter
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowIP {
    /// Connect to any address
    All,
    /// Connect to private network only
    Private,
    /// Connect to public network only
    Public,
    /// Block all addresses
    None,
}

pub fn parse_msg_id_leb128_2_bytes_at_most(msg: &mut &[u8]) -> u16 {
    let buf = *msg;

    let mut ret = 0;
    let mut pos = buf.len() - 1;

    let byte = buf[pos] as u16;
    ret |= byte & 0x7f;
    if byte & 0x80 != 0 {
        pos -= 1;
        let byte = buf[pos] as u16;
        ret |= (byte & 0x7f) << 7;
    }

    *msg = &buf[..pos];

    ret
}
