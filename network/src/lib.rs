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
extern crate keylib;
extern crate libc;
extern crate parity_path;
extern crate rand;
#[macro_use]
extern crate enum_map_derive;
extern crate strum;
#[macro_use]
extern crate strum_macros;
extern crate keccak_hash;

pub type ProtocolId = [u8; 3];
pub type PeerId = usize;

mod connection;
mod discovery;
mod error;
mod ip_utils;
pub mod node_table;
mod service;
mod session;
pub mod throttling;

pub use crate::{
    error::{DisconnectReason, Error, ErrorKind, ThrottlingReason},
    service::NetworkService,
};
pub use io::TimerToken;

use crate::{
    node_table::NodeId,
    service::{
        DEFAULT_CONNECTION_LIFETIME_FOR_PROMOTION,
        DEFAULT_DISCOVERY_REFRESH_TIMEOUT, DEFAULT_DISCOVERY_ROUND_TIMEOUT,
        DEFAULT_FAST_DISCOVERY_REFRESH_TIMEOUT, DEFAULT_HOUSEKEEPING_TIMEOUT,
        DEFAULT_NODE_TABLE_TIMEOUT,
    },
};
use ipnetwork::{IpNetwork, IpNetworkError};
use keylib::Secret;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    cmp::Ordering,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::{self, FromStr},
    sync::Arc,
    time::Duration,
};

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkConfiguration {
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
    pub max_outgoing_peers: u32,
    /// Maximum number of incoming peers
    pub max_incoming_peers: u32,
    /// Maximum number of ongoing handshakes
    pub max_handshakes: u32,
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
}

impl Default for NetworkConfiguration {
    fn default() -> Self { NetworkConfiguration::new() }
}

impl NetworkConfiguration {
    pub fn new() -> Self {
        NetworkConfiguration {
            config_path: Some("./config".to_string()),
            listen_address: None,
            public_address: None,
            udp_port: None,
            nat_enabled: true,
            discovery_enabled: false,
            boot_nodes: Vec::new(),
            use_secret: None,
            max_outgoing_peers: 16,
            max_incoming_peers: 32,
            max_handshakes: 64,
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
        }
    }

    pub fn new_with_port(port: u16) -> NetworkConfiguration {
        let mut config = NetworkConfiguration::new();
        config.listen_address = Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0),
            port,
        )));
        config
    }

    pub fn new_local() -> NetworkConfiguration {
        let mut config = NetworkConfiguration::new();
        config.listen_address = Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            0,
        )));
        config
    }
}

#[derive(Clone)]
pub enum NetworkIoMessage {
    Start,
    AddHandler {
        handler: Arc<NetworkProtocolHandler + Sync>,
        protocol: ProtocolId,
        versions: Vec<u8>,
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
    /// Disconnect a peer.
    Disconnect(PeerId),
}

pub trait NetworkProtocolHandler: Sync + Send {
    fn initialize(&self, _io: &NetworkContext) {}

    fn on_message(&self, io: &NetworkContext, peer: PeerId, data: &[u8]);

    fn on_peer_connected(&self, io: &NetworkContext, peer: PeerId);

    fn on_peer_disconnected(&self, io: &NetworkContext, peer: PeerId);

    fn on_timeout(&self, io: &NetworkContext, timer: TimerToken);
}

pub trait NetworkContext {
    fn get_peer_node_id(&self, peer: PeerId) -> NodeId;

    fn send(&self, peer: PeerId, msg: Vec<u8>) -> Result<(), Error>;

    fn disconnect_peer(&self, peer: PeerId);

    /// Register a new IO timer. 'IoHandler::timeout' will be called with the
    /// token.
    fn register_timer(
        &self, token: TimerToken, delay: Duration,
    ) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub id: Option<NodeId>,
    pub capabilities: Vec<Capability>,
    pub peer_capabilities: Vec<Capability>,
    pub originated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capability {
    pub protocol: ProtocolId,
    pub version: u8,
}

impl Encodable for Capability {
    fn rlp_append(&self, rlp: &mut RlpStream) {
        rlp.begin_list(2);
        rlp.append(&&self.protocol[..]);
        rlp.append(&self.version);
    }
}

impl Decodable for Capability {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let p: Vec<u8> = rlp.val_at(0)?;
        if p.len() != 3 {
            return Err(DecoderError::Custom(
                "Invalid subprotocol string length",
            ));
        }
        let mut protocol: ProtocolId = [0u8; 3];
        protocol.clone_from_slice(&p);
        Ok(Capability {
            protocol: protocol,
            version: rlp.val_at(1)?,
        })
    }
}

impl PartialOrd for Capability {
    fn partial_cmp(&self, other: &Capability) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Capability {
    fn cmp(&self, other: &Capability) -> Ordering {
        return self.protocol.cmp(&other.protocol);
    }
}

#[derive(Serialize)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub nodeid: NodeId,
    pub caps: Vec<Capability>,
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
                    if custom.starts_with("-") {
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

/// IP fiter
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
