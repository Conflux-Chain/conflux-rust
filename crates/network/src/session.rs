// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    connection::{Connection, ConnectionDetails, SendQueueStatus, WriteStatus},
    handshake::Handshake,
    node_table::{NodeEndpoint, NodeEntry, NodeId},
    parse_msg_id_leb128_2_bytes_at_most,
    service::{NetworkServiceInner, ProtocolVersion},
    DisconnectReason, Error, ProtocolId, ProtocolInfo, SessionMetadata,
    UpdateNodeOperation, PROTOCOL_ID_SIZE,
};
use bytes::Bytes;
use cfx_util_macros::bail;
use diem_crypto::{bls::BLS_PUBLIC_KEY_LENGTH, ValidCryptoMaterial};
use diem_types::validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey};
use io::*;
use log::{debug, trace};
use mio::{tcp::*, *};
use priority_send_queue::SendQueuePriority;
use rlp::{Rlp, RlpStream};
use serde::Deserialize;
use serde_derive::Serialize;
use std::{
    convert::TryFrom,
    fmt,
    net::SocketAddr,
    str,
    time::{Duration, Instant},
};

/// Peer session over TCP connection, including outgoing and incoming sessions.
///
/// When a session created, 2 peers handshake with each other to exchange the
/// node id based on asymmetric cryptography. After handshake, peers send HELLO
/// packet to exchange the supported protocols. Then, session is ready to send
/// and receive protocol packets.
///
/// Conflux do not use AES based encrypted connection to send protocol packets.
/// This is because that Conflux has high TPS, and the encryption/decryption
/// workloads are very heavy (about 20% CPU time in 3000 TPS).
pub struct Session {
    /// Session information
    pub metadata: SessionMetadata,
    /// Socket address of remote peer
    address: SocketAddr,
    /// Session state
    state: State,
    /// Timestamp of when Hello packet sent, which is used to measure timeout.
    sent_hello: Instant,
    /// Session ready flag that set after successful Hello packet received.
    had_hello: Option<Instant>,
    /// Session is no longer active flag.
    expired: Option<Instant>,

    // statistics for read/write
    last_read: Instant,
    last_write: (Instant, WriteStatus),
    pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
}

/// Session state.
enum State {
    /// Handshake to exchange node id.
    /// When handshake completed, the underlying TCP connection instance of
    /// handshake will also be moved to the state `State::Session`.
    Handshake(MovableWrapper<Handshake>),
    /// Ready to send Hello or protocol packets.
    Session(Connection),
}

/// Session data represents various of packet read from socket.
pub enum SessionData {
    /// No packet read from socket.
    None,
    /// Session is ready to send or receive protocol packets.
    Ready {
        pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    },
    /// A protocol packet has been received, and delegate to the corresponding
    /// protocol handler to handle the packet.
    Message { data: Vec<u8>, protocol: ProtocolId },
    /// Session has more data to be read.
    Continue,
}

pub struct SessionDataWithDisconnectInfo {
    pub session_data: SessionData,
    pub token_to_disconnect: Option<(StreamToken, String)>,
}

// id for Hello packet
const PACKET_HELLO: u8 = 0x80;
// id for Disconnect packet
const PACKET_DISCONNECT: u8 = 0x01;
// id for protocol packet
pub const PACKET_USER: u8 = 0x10;
/// header_version for protocol packet.
/// Change the version only when there is a major change to the protocol packet.
pub const PACKET_HEADER_VERSION: u8 = 0;
/// The header version where extension is introduced.
const HEADER_VERSION_WITH_EXTENSION: u8 = 0;

impl Session {
    /// Create a new instance of `Session`, which starts to handshake with
    /// remote peer.
    pub fn new<Message: Send + Sync + Clone + 'static>(
        io: &IoContext<Message>, socket: TcpStream, address: SocketAddr,
        id: Option<&NodeId>, peer_header_version: u8, token: StreamToken,
        host: &NetworkServiceInner,
        pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    ) -> Result<Session, Error> {
        let originated = id.is_some();

        let mut handshake = Handshake::new(token, id, socket);
        handshake.start(io, &host.metadata)?;

        Ok(Session {
            metadata: SessionMetadata {
                id: id.cloned(),
                peer_protocols: Vec::new(),
                originated,
                peer_header_version,
            },
            address,
            state: State::Handshake(MovableWrapper::new(handshake)),
            sent_hello: Instant::now(),
            had_hello: None,
            expired: None,
            last_read: Instant::now(),
            last_write: (Instant::now(), WriteStatus::Complete),
            pos_public_key,
        })
    }

    pub fn have_capability(&self, protocol: ProtocolId) -> bool {
        self.metadata
            .peer_protocols
            .iter()
            .any(|c| c.protocol == protocol)
    }

    /// Get id of the remote peer
    pub fn id(&self) -> Option<&NodeId> { self.metadata.id.as_ref() }

    pub fn originated(&self) -> bool { self.metadata.originated }

    pub fn is_ready(&self) -> bool { self.had_hello.is_some() }

    pub fn expired(&self) -> bool { self.expired.is_some() }

    pub fn set_expired(&mut self) { self.expired = Some(Instant::now()); }

    pub fn done(&self) -> bool {
        self.expired() && !self.connection().is_sending()
    }

    fn connection(&self) -> &Connection {
        match self.state {
            State::Handshake(ref h) => &h.get().connection,
            State::Session(ref c) => c,
        }
    }

    fn connection_mut(&mut self) -> &mut Connection {
        match self.state {
            State::Handshake(ref mut h) => &mut h.get_mut().connection,
            State::Session(ref mut c) => c,
        }
    }

    pub fn token(&self) -> StreamToken { self.connection().token() }

    pub fn address(&self) -> SocketAddr { self.address }

    /// Register event loop for the underlying connection.
    /// If session expired, no effect taken.
    pub fn register_socket(
        &self, reg: Token, event_loop: &Poll,
    ) -> Result<(), Error> {
        if !self.expired() {
            self.connection().register_socket(reg, event_loop)?;
        }

        Ok(())
    }

    /// Update the event loop for the underlying connection.
    pub fn update_socket(
        &self, reg: Token, event_loop: &Poll,
    ) -> Result<(), Error> {
        self.connection().update_socket(reg, event_loop)?;
        Ok(())
    }

    /// Deregister the event loop for the underlying connection.
    pub fn deregister_socket(&self, event_loop: &Poll) -> Result<(), Error> {
        self.connection().deregister_socket(event_loop)?;
        Ok(())
    }

    /// Complete the handshake process:
    /// 1. For incoming session, check if the remote peer is blacklisted.
    /// 2. Change the session state to `State::Session`.
    /// 3. Send Hello packet to remote peer.
    fn complete_handshake<Message>(
        &mut self, io: &IoContext<Message>, host: &NetworkServiceInner,
    ) -> Result<(), Error>
    where Message: Send + Sync + Clone {
        let wrapper = match self.state {
            State::Handshake(ref mut h) => h,
            State::Session(_) => panic!("Unexpected session state"),
        };

        // update node id for ingress session
        if self.metadata.id.is_none() {
            let id = wrapper.get().id.clone();

            // refuse incoming session if the node is blacklisted
            if host.node_db.write().evaluate_blacklisted(&id) {
                return Err(self.send_disconnect(DisconnectReason::Blacklisted));
            }

            self.metadata.id = Some(id);
        }

        // write HELLO packet to remote peer
        self.state = State::Session(wrapper.take().connection);
        self.write_hello(io, host)?;

        Ok(())
    }

    /// Readable IO handler. Returns packet data if available.
    pub fn readable<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, host: &NetworkServiceInner,
    ) -> Result<SessionDataWithDisconnectInfo, Error> {
        // update the last read timestamp for statistics
        self.last_read = Instant::now();

        if self.expired() {
            debug!("cannot read data due to expired, session = {:?}", self);
            return Ok(SessionDataWithDisconnectInfo {
                session_data: SessionData::None,
                token_to_disconnect: None,
            });
        }

        match self.state {
            State::Handshake(ref mut h) => {
                let h = h.get_mut();

                if !h.readable(io, &host.metadata)? {
                    return Ok(SessionDataWithDisconnectInfo {
                        session_data: SessionData::None,
                        token_to_disconnect: None,
                    });
                }

                if h.done() {
                    self.complete_handshake(io, host)?;
                    io.update_registration(self.token()).unwrap_or_else(|e| {
                        debug!("Token registration error: {:?}", e)
                    });
                }

                Ok(SessionDataWithDisconnectInfo {
                    session_data: SessionData::Continue,
                    token_to_disconnect: None,
                })
            }
            State::Session(ref mut c) => match c.readable()? {
                Some(data) => Ok(self.read_packet(data, host)?),
                None => Ok(SessionDataWithDisconnectInfo {
                    session_data: SessionData::None,
                    token_to_disconnect: None,
                }),
            },
        }
    }

    /// Handle the packet from underlying connection.
    fn read_packet(
        &mut self, data: Bytes, host: &NetworkServiceInner,
    ) -> Result<SessionDataWithDisconnectInfo, Error> {
        let packet = SessionPacket::parse(data)?;

        // For protocol packet, the Hello packet should already been received.
        // So that dispatch it to the corresponding protocol handler.
        if packet.id != PACKET_HELLO
            && packet.id != PACKET_DISCONNECT
            && self.had_hello.is_none()
        {
            return Err(Error::BadProtocol.into());
        }

        match packet.id {
            PACKET_HELLO => {
                debug!("Read HELLO in session {:?}", self);
                self.metadata.peer_header_version = packet.header_version;
                // For ingress session, update the node id in `SessionManager`
                let token_to_disconnect = self.update_ingress_node_id(host)?;

                let token_to_disconnect = match token_to_disconnect {
                    Some(token) => Some((
                        token,
                        String::from("Remove old session from the same node"),
                    )),
                    None => None,
                };

                // Handle Hello packet to exchange protocols
                let rlp = Rlp::new(&packet.data);
                let pos_public_key = self.read_hello(&rlp, host)?;
                Ok(SessionDataWithDisconnectInfo {
                    session_data: SessionData::Ready { pos_public_key },
                    token_to_disconnect,
                })
            }
            PACKET_DISCONNECT => {
                let rlp = Rlp::new(&packet.data);
                let reason: DisconnectReason = rlp.as_val()?;
                debug!(
                    "read packet DISCONNECT, reason = {}, session = {:?}",
                    reason, self
                );
                Err(Error::Disconnect(reason).into())
            }
            PACKET_USER => Ok(SessionDataWithDisconnectInfo {
                session_data: SessionData::Message {
                    data: packet.data.to_vec(),
                    protocol: packet
                        .protocol
                        .expect("protocol should available for USER packet"),
                },
                token_to_disconnect: None,
            }),
            _ => {
                debug!(
                    "read packet UNKNOWN, packet_id = {:?}, session = {:?}",
                    packet.id, self
                );
                Err(Error::BadProtocol.into())
            }
        }
    }

    /// Update node Id in `SessionManager` for ingress session.
    fn update_ingress_node_id(
        &mut self, host: &NetworkServiceInner,
    ) -> Result<Option<usize>, Error> {
        // ignore egress session
        if self.metadata.originated {
            return Ok(None);
        }

        let token = self.token();
        let node_id = self
            .metadata
            .id
            .expect("should have node id after handshake");

        host.sessions.update_ingress_node_id(token, &node_id)
            .map_err(|reason| {
                debug!(
                    "failed to update node id of ingress session, reason = {:?}, session = {:?}",
                    reason, self
                );

                self.send_disconnect(DisconnectReason::UpdateNodeIdFailed)
            })
    }

    /// Read Hello packet to exchange the supported protocols, and set the
    /// `had_hello` flag to indicates that session is ready to send/receive
    /// protocol packets.
    ///
    /// Besides, the node endpoint of remote peer will be added or updated in
    /// node database, which is used to establish outgoing connections.
    fn read_hello(
        &mut self, rlp: &Rlp, host: &NetworkServiceInner,
    ) -> Result<Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>, Error>
    {
        let remote_network_id: u64 = rlp.val_at(0)?;
        if remote_network_id != host.metadata.network_id {
            debug!(
                "failed to read hello, network id mismatch, self = {}, remote = {}",
                host.metadata.network_id, remote_network_id);
            return Err(self.send_disconnect(DisconnectReason::Custom(
                "network id mismatch".into(),
            )));
        }

        let mut peer_caps: Vec<ProtocolInfo> = rlp.list_at(1)?;
        for i in 1..peer_caps.len() {
            for j in 0..i {
                if peer_caps[j].protocol == peer_caps[i].protocol {
                    debug!(
                        "Invalid protocol list from hello. Duplication: {:?},\
                         remote = {}",
                        peer_caps[i].protocol, remote_network_id
                    );
                    bail!(self.send_disconnect(DisconnectReason::Custom(
                        "Invalid protocol list: duplication.".into()
                    )))
                }
            }
        }

        peer_caps.retain(|c| {
            host.metadata
                .minimum_peer_protocol_version
                .read()
                .iter()
                .any(|hc| hc.protocol == c.protocol && hc.version <= c.version)
        });

        self.metadata.peer_protocols = peer_caps;
        if self.metadata.peer_protocols.is_empty() {
            debug!("No common capabilities with remote peer, peer_node_id = {:?}, session = {:?}", self.metadata.id, self);
            return Err(self.send_disconnect(DisconnectReason::UselessPeer));
        }

        let mut hello_from = NodeEndpoint::from_rlp(&rlp.at(2)?)?;
        // Use the ip of the socket as endpoint ip directly.
        // We do not allow peers to specify the ip to avoid being used to DDoS
        // the target ip.
        hello_from.address.set_ip(self.address.ip());

        let ping_to = NodeEndpoint {
            address: hello_from.address,
            udp_port: hello_from.udp_port,
        };

        let entry = NodeEntry {
            id: self
                .metadata
                .id
                .expect("should have node ID after handshake"),
            endpoint: ping_to,
        };
        if !entry.endpoint.is_valid() {
            debug!("Got invalid endpoint {:?}, session = {:?}", entry, self);
            return Err(
                self.send_disconnect(DisconnectReason::WrongEndpointInfo)
            );
        } else if !(entry.endpoint.is_allowed(host.get_ip_filter())
            && entry.id != *host.metadata.id())
        {
            debug!(
                "Address not allowed, endpoint = {:?}, session = {:?}",
                entry, self
            );
            return Err(self.send_disconnect(DisconnectReason::IpLimited));
        } else {
            debug!("Received valid endpoint {:?}, session = {:?}", entry, self);
            host.node_db.write().insert_with_token(entry, self.token());
        }

        self.had_hello = Some(Instant::now());
        match rlp.item_count()? {
            3 => Ok(None),
            4 => {
                // FIXME(lpl): Verify keys.
                let pos_public_key_bytes: Vec<u8> = rlp.val_at(3)?;
                trace!("pos_public_key_bytes: {:?}", pos_public_key_bytes);
                if pos_public_key_bytes.len() < BLS_PUBLIC_KEY_LENGTH {
                    bail!("pos public key bytes is too short!");
                }
                let bls_pub_key = ConsensusPublicKey::try_from(
                    &pos_public_key_bytes[..BLS_PUBLIC_KEY_LENGTH],
                )
                .map_err(|e| Error::Decoder(format!("{:?}", e)))?;
                let vrf_pub_key = ConsensusVRFPublicKey::try_from(
                    &pos_public_key_bytes[BLS_PUBLIC_KEY_LENGTH..],
                )
                .map_err(|e| Error::Decoder(format!("{:?}", e)))?;

                Ok(Some((bls_pub_key, vrf_pub_key)))
            }
            length => Err(Error::Decoder(format!(
                "Hello has incorrect rlp length: {:?}",
                length
            ))
            .into()),
        }
    }

    /// Assemble a packet with specified protocol id, packet id and data.
    /// Return concrete error if session is expired or the protocol id is
    /// invalid.
    fn prepare_packet(
        &self, protocol: Option<ProtocolId>, packet_id: u8, data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        if protocol.is_some() && self.had_hello.is_none() {
            debug!(
                "Sending to unconfirmed session {}, protocol: {:?}, packet: {}",
                self.token(),
                protocol
                    .as_ref()
                    .map(|p| str::from_utf8(&p[..]).unwrap_or("???")),
                packet_id
            );
            bail!(Error::Expired);
        }

        if self.expired() {
            return Err(Error::Expired.into());
        }

        Ok(SessionPacket::assemble(
            packet_id,
            self.metadata.peer_header_version,
            protocol,
            data,
        ))
    }

    #[inline]
    pub fn check_message_protocol_version(
        &self, protocol: Option<ProtocolId>,
        min_protocol_version: ProtocolVersion, mut msg: &[u8],
    ) -> Result<(), Error> {
        // min_protocol_version is the version when the Message is introduced.
        // peer protocol version must be higher.
        if let Some(protocol) = protocol {
            for peer_protocol in &self.metadata.peer_protocols {
                if protocol.eq(&peer_protocol.protocol) {
                    if min_protocol_version <= peer_protocol.version {
                        break;
                    } else {
                        bail!(Error::SendUnsupportedMessage {
                            protocol,
                            msg_id: parse_msg_id_leb128_2_bytes_at_most(
                                &mut msg
                            ),
                            peer_protocol_version: Some(peer_protocol.version),
                            min_supported_version: None,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Send a packet to remote peer asynchronously.
    pub fn send_packet<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, protocol: Option<ProtocolId>,
        min_proto_version: ProtocolVersion, packet_id: u8, data: Vec<u8>,
        priority: SendQueuePriority,
    ) -> Result<SendQueueStatus, Error> {
        self.check_message_protocol_version(
            protocol.clone(),
            min_proto_version,
            &data,
        )?;
        let packet = self.prepare_packet(protocol, packet_id, data)?;
        self.connection_mut().send(io, packet, priority)
    }

    /// Send a packet to remote peer immediately.
    pub fn send_packet_immediately(
        &mut self, protocol: Option<ProtocolId>,
        min_proto_version: ProtocolVersion, packet_id: u8, data: Vec<u8>,
    ) -> Result<usize, Error> {
        self.check_message_protocol_version(
            protocol.clone(),
            min_proto_version,
            &data,
        )?;
        let packet = self.prepare_packet(protocol, packet_id, data)?;
        self.connection_mut().write_raw_data(packet)
    }

    /// Send a Disconnect packet immediately to the remote peer.
    pub fn send_disconnect(&mut self, reason: DisconnectReason) -> Error {
        let packet = rlp::encode(&reason);
        let _ = self.send_packet_immediately(
            None,
            ProtocolVersion::default(),
            PACKET_DISCONNECT,
            packet,
        );
        Error::Disconnect(reason).into()
    }

    /// Send Hello packet to remote peer.
    fn write_hello<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, host: &NetworkServiceInner,
    ) -> Result<(), Error> {
        debug!("Sending Hello, session = {:?}", self);
        let mut rlp = RlpStream::new_list(4);
        rlp.append(&host.metadata.network_id);
        rlp.append_list(&*host.metadata.protocols.read());
        host.metadata.public_endpoint.to_rlp_list(&mut rlp);
        let mut key_bytes =
            self.pos_public_key.as_ref().unwrap().0.to_bytes().to_vec();
        key_bytes.append(
            &mut self.pos_public_key.as_ref().unwrap().1.to_bytes().to_vec(),
        );
        rlp.append(&key_bytes);
        self.send_packet(
            io,
            None,
            ProtocolVersion::default(),
            PACKET_HELLO,
            rlp.drain(),
            SendQueuePriority::High,
        )
        .map(|_| ())
    }

    /// Writable IO handler. Sends pending packets.
    pub fn writable<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<(), Error> {
        let status = self.connection_mut().writable(io)?;
        self.last_write = (Instant::now(), status);
        Ok(())
    }

    /// Get the user friendly information of session.
    /// This is specially for Debug RPC.
    pub fn details(&self) -> SessionDetails {
        SessionDetails {
            originated: self.metadata.originated,
            node_id: self.metadata.id,
            address: self.address,
            connection: self.connection().details(),
            status: if let Some(time) = self.expired {
                format!("expired ({:?})", time.elapsed())
            } else if let Some(time) = self.had_hello {
                format!("communicating ({:?})", time.elapsed())
            } else {
                format!("handshaking ({:?})", self.sent_hello.elapsed())
            },
            last_read: format!("{:?}", self.last_read.elapsed()),
            last_write: format!("{:?}", self.last_write.0.elapsed()),
            last_write_status: format!("{:?}", self.last_write.1),
        }
    }

    /// Check if the session is timeout.
    /// Once a session is timeout during handshake or exchanging Hello packet,
    /// the TCP connection should be disconnected timely.
    ///
    /// Note, there is no periodical Ping/Pong mechanism to check if the session
    /// is inactive for a long time. The synchronization protocol handler has
    /// heartbeat mechanism to exchange peer status. As a result, Inactive
    /// sessions (e.g. network issue) will be disconnected timely.
    pub fn check_timeout(&self) -> (bool, Option<UpdateNodeOperation>) {
        if let Some(time) = self.expired {
            // should disconnected timely once expired
            if time.elapsed() > Duration::from_secs(5) {
                return (true, None);
            }
        } else if self.had_hello.is_none() {
            // should receive HELLO packet timely after session created
            if self.sent_hello.elapsed() > Duration::from_secs(300) {
                return (true, Some(UpdateNodeOperation::Failure));
            }
        }

        (false, None)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Session {{ token: {}, id: {:?}, originated: {}, address: {:?}, had_hello: {}, expired: {} }}",
               self.token(), self.id(), self.metadata.originated, self.address, self.had_hello.is_some(), self.expired.is_some())
    }
}

/// User friendly session information that used for Debug RPC.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetails {
    pub originated: bool,
    pub node_id: Option<NodeId>,
    pub address: SocketAddr,
    pub connection: ConnectionDetails,
    pub status: String,
    pub last_read: String,
    pub last_write: String,
    pub last_write_status: String,
}

/// MovableWrapper is a util to move a value out of a struct.
/// It is used to move the `Connection` instance when session state changed.
struct MovableWrapper<T> {
    item: Option<T>,
}

impl<T> MovableWrapper<T> {
    fn new(item: T) -> Self { MovableWrapper { item: Some(item) } }

    fn get(&self) -> &T {
        match self.item {
            Some(ref item) => item,
            None => panic!("cannot get moved item"),
        }
    }

    fn get_mut(&mut self) -> &mut T {
        match self.item {
            Some(ref mut item) => item,
            None => panic!("cannot get_mut moved item"),
        }
    }

    fn take(&mut self) -> T {
        if self.item.is_none() {
            panic!("cannot take moved item")
        }

        self.item.take().expect("should have value")
    }
}

/// Session packet is composed of packet id, optional protocol id and data.
/// To avoid memory copy, especially when the data size is very big (e.g. 4MB),
/// packet id and protocol id are appended in the end of data.
///
/// The packet format is:
///     [data (0 to more bytes) || header]
///
/// The header format is:
/// [  extensions (0 to more bytes) || protocol (0 or 3 bytes if protocol_flag)
///   || reserved (3 bit), has_extension (1 bit), header_version (3 bit),
///      protocol_flag (1 bit)
///   || packet_id]
///
/// The protocol format is:
///     [ protocol_id (3 bytes)]
///
/// The extensions format is:
/// [ extension data (0 to more bytes)
///   || extension data length (7 bit) | has_next_extension (1 bit)
/// ]
#[derive(Eq, PartialEq)]
struct SessionPacket {
    pub id: u8,
    pub protocol: Option<ProtocolId>,
    pub data: Bytes,
    pub header_version: u8,
    pub extensions: Vec<Vec<u8>>,
}

impl SessionPacket {
    // data + Option<protocol> + protocol_flag + packet_id
    fn assemble(
        id: u8, header_version: u8, protocol: Option<ProtocolId>,
        mut data: Vec<u8>,
    ) -> Vec<u8> {
        let mut protocol_flag = 0;
        if let Some(protocol) = protocol {
            data.extend_from_slice(&protocol);
            protocol_flag = 1;
        }

        let header_byte = (header_version << 1) + protocol_flag;
        data.push(header_byte);
        data.push(id);

        data
    }

    fn parse(mut data: Bytes) -> Result<Self, Error> {
        // packet id
        if data.is_empty() {
            debug!("failed to parse session packet, packet id missed");
            return Err(Error::BadProtocol.into());
        }

        let packet_id = data.split_off(data.len() - 1)[0];

        // protocol flag
        if data.is_empty() {
            debug!("failed to parse session packet, protocol flag missed");
            return Err(Error::BadProtocol.into());
        }

        let header_byte = data.split_off(data.len() - 1)[0];
        let protocol_flag = header_byte & 1;
        let header_version = (header_byte & 0x0f) >> 1;
        if header_version > HEADER_VERSION_WITH_EXTENSION {
            debug!("unsupported header_version {}", header_version);
            return Err(Error::BadProtocol.into());
        }
        let has_extension = (header_byte & 0x10) >> 4;

        // without protocol
        if protocol_flag == 0 {
            if packet_id == PACKET_USER {
                debug!("failed to parse session packet, no protocol for user packet");
                return Err(Error::BadProtocol.into());
            }

            let (data, extensions) =
                Self::parse_extensions(data, has_extension != 0)?;

            return Ok(SessionPacket {
                id: packet_id,
                header_version,
                protocol: None,
                data,
                extensions,
            });
        }

        if packet_id != PACKET_USER {
            debug!("failed to parse session packet, invalid packet id");
            return Err(Error::BadProtocol.into());
        }

        // protocol
        if data.len() < PROTOCOL_ID_SIZE {
            debug!("failed to parse session packet, protocol missed");
            return Err(Error::BadProtocol.into());
        }

        let protocol_bytes = data.split_off(data.len() - PROTOCOL_ID_SIZE);
        let mut protocol = ProtocolId::default();
        protocol.copy_from_slice(&protocol_bytes);

        // extensions
        let (data, extensions) =
            Self::parse_extensions(data, has_extension != 0)?;

        Ok(SessionPacket {
            id: packet_id,
            protocol: Some(protocol),
            header_version,
            data,
            extensions,
        })
    }

    fn parse_extensions(
        mut data: Bytes, mut has_extension: bool,
    ) -> Result<(Bytes, Vec<Vec<u8>>), Error> {
        let mut extensions = Vec::new();
        while has_extension {
            let extension_byte = data.split_off(data.len() - 1)[0];
            let extension_len = (extension_byte >> 1) as usize;
            has_extension = (extension_byte & 1) != 0;
            if data.len() < extension_len {
                debug!("failed to parse session packet, not enough bytes for extension.");
                bail!(Error::BadProtocol);
            }
            extensions
                .push(data.split_off(data.len() - extension_len).to_vec());
        }

        Ok((data, extensions))
    }
}

impl fmt::Debug for SessionPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SessionPacket {{ id: {}, protocol: {:?}, date_len: {} }}",
            self.id,
            self.protocol,
            self.data.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_assemble() {
        let packet =
            SessionPacket::assemble(5, PACKET_HEADER_VERSION, None, vec![1, 3]);
        assert_eq!(packet, vec![1, 3, 0, 5]);

        let packet = SessionPacket::assemble(
            6,
            PACKET_HEADER_VERSION,
            Some([8; 3]),
            vec![2, 4],
        );
        assert_eq!(packet, vec![2, 4, 8, 8, 8, 1, 6]);
    }

    #[test]
    fn test_packet_parse() {
        // packet id missed
        assert!(SessionPacket::parse(vec![].into()).is_err());

        // protocol flag missed
        assert!(SessionPacket::parse(vec![1].into()).is_err());

        // protocol flag invalid
        assert!(SessionPacket::parse(vec![2, 1].into()).is_err());

        // user packet without protocol
        assert!(SessionPacket::parse(vec![0, PACKET_USER].into()).is_err());

        // packet without protocol
        let packet = SessionPacket::parse(vec![1, 2, 0, 20].into()).unwrap();
        assert_eq!(
            packet,
            SessionPacket {
                id: 20,
                header_version: 0,
                protocol: None,
                data: vec![1, 2].into(),
                extensions: vec![],
            }
        );

        // non user packet with protocol
        assert!(SessionPacket::parse(vec![6, 6, 6, 1, 7].into()).is_err());

        // user packet, but protocol length is not enough
        assert!(
            SessionPacket::parse(vec![6, 6, 1, PACKET_USER].into()).is_err()
        );

        // user packet with protocol
        let packet =
            SessionPacket::parse(vec![1, 9, 3, 3, 3, 1, PACKET_USER].into())
                .unwrap();
        assert_eq!(
            packet,
            SessionPacket {
                id: PACKET_USER,
                header_version: 0,
                protocol: Some([3; 3]),
                data: vec![1, 9].into(),
                extensions: vec![],
            }
        );
    }
}
