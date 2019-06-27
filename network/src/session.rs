// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    connection::{
        Connection as TcpConnection, ConnectionDetails,
        PacketSizer as PacketSizerTrait, SendQueueStatus, WriteStatus,
        MAX_PAYLOAD_SIZE,
    },
    hash::keccak,
    node_table::{NodeEndpoint, NodeEntry, NodeId},
    service::NetworkServiceInner,
    Capability, DisconnectReason, Error, ErrorKind, ProtocolId,
    SessionMetadata, UpdateNodeOperation,
};
use bytes::{Buf, BufMut, Bytes, BytesMut, IntoBuf};
use cfx_bytes;
use cfx_types::H520;
use io::*;
use keylib::{recover, sign};
use mio::{deprecated::*, tcp::*, *};
use priority_send_queue::SendQueuePriority;
use rlp::{Rlp, RlpStream};
use serde_derive::Serialize;
use std::{
    fmt,
    net::SocketAddr,
    str,
    time::{Duration, Instant},
};

struct PacketSizer;

impl PacketSizerTrait for PacketSizer {
    fn packet_size(raw_packet: &Bytes) -> usize {
        let buf = &mut raw_packet.into_buf() as &mut Buf;
        if buf.remaining() >= 3 {
            let size = buf.get_uint_le(3) as usize;
            if buf.remaining() >= size {
                size + 3
            } else {
                0
            }
        } else {
            0
        }
    }
}

type Connection = TcpConnection<PacketSizer>;

pub struct Session {
    pub metadata: SessionMetadata,
    address: SocketAddr,
    connection: Connection,
    sent_hello: Instant,
    had_hello: Option<Instant>,
    expired: Option<Instant>,

    // statistics for read/write
    last_read: Instant,
    last_write: (Instant, Option<WriteStatus>), // None for error
}

pub enum SessionData {
    None,
    Ready,
    Message { data: Vec<u8>, protocol: ProtocolId },
    Continue,
}

const PACKET_HELLO: u8 = 0x80;
const PACKET_DISCONNECT: u8 = 0x01;
const PACKET_PING: u8 = 0x02;
const PACKET_PONG: u8 = 0x03;
pub const PACKET_USER: u8 = 0x10;

impl Session {
    pub fn new<Message: Send + Sync + Clone + 'static>(
        io: &IoContext<Message>, socket: TcpStream, address: SocketAddr,
        id: Option<&NodeId>, token: StreamToken, host: &NetworkServiceInner,
    ) -> Result<Session, Error>
    {
        let originated = id.is_some();
        let mut session = Session {
            metadata: SessionMetadata {
                id: id.cloned(),
                capabilities: Vec::new(),
                peer_capabilities: Vec::new(),
                originated,
            },
            address,
            connection: Connection::new(token, socket),
            sent_hello: Instant::now(),
            had_hello: None,
            expired: None,
            last_read: Instant::now(),
            last_write: (Instant::now(), None),
        };

        session.write_hello(io, host)?;

        Ok(session)
    }

    pub fn have_capability(&self, protocol: ProtocolId) -> bool {
        self.metadata
            .capabilities
            .iter()
            .any(|c| c.protocol == protocol)
    }

    /// Get id of the remote peer
    pub fn id(&self) -> Option<&NodeId> { self.metadata.id.as_ref() }

    pub fn is_ready(&self) -> bool { self.had_hello.is_some() }

    pub fn expired(&self) -> bool { self.expired.is_some() }

    pub fn set_expired(&mut self) { self.expired = Some(Instant::now()); }

    pub fn done(&self) -> bool {
        self.expired() && !self.connection().is_sending()
    }

    fn connection(&self) -> &Connection { &self.connection }

    pub fn token(&self) -> StreamToken { self.connection().token() }

    pub fn address(&self) -> SocketAddr { self.address }

    pub fn register_socket<H: Handler>(
        &self, reg: Token, event_loop: &mut EventLoop<H>,
    ) -> Result<(), Error> {
        self.connection.register_socket(reg, event_loop)?;
        Ok(())
    }

    pub fn update_socket<H: Handler>(
        &self, reg: Token, event_loop: &mut EventLoop<H>,
    ) -> Result<(), Error> {
        self.connection.update_socket(reg, event_loop)?;
        Ok(())
    }

    pub fn deregister_socket<H: Handler>(
        &self, event_loop: &mut EventLoop<H>,
    ) -> Result<(), Error> {
        self.connection().deregister_socket(event_loop)?;
        Ok(())
    }

    pub fn readable<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, host: &NetworkServiceInner,
    ) -> Result<SessionData, Error> {
        self.last_read = Instant::now();

        if self.expired() {
            debug!("cannot read data due to expired, session = {:?}", self);
            return Ok(SessionData::None);
        }

        match self.connection.readable()? {
            Some(data) => Ok(self.read_packet(io, &data, host)?),
            None => Ok(SessionData::None),
        }
    }

    fn read_packet<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, data: &Bytes,
        host: &NetworkServiceInner,
    ) -> Result<SessionData, Error>
    {
        if data.len() <= 3 {
            return Err(ErrorKind::BadProtocol.into());
        }

        let packet_id = data[3];
        if packet_id != PACKET_HELLO
            && packet_id != PACKET_DISCONNECT
            && self.had_hello.is_none()
        {
            return Err(ErrorKind::BadProtocol.into());
        }
        let data = &data[4..];
        match packet_id {
            PACKET_HELLO => {
                debug!("read packet HELLO, session = {:?}", self);
                if data.len() <= 32 + 65 {
                    return Err(ErrorKind::BadProtocol.into());
                }
                let hash_signed = keccak(&data[32..]);
                if hash_signed[..] != data[0..32] {
                    return Err(ErrorKind::BadProtocol.into());
                }
                let signed = &data[(32 + 65)..];
                let signature = H520::from_slice(&data[32..(32 + 65)]);
                let node_id = recover(&signature.into(), &keccak(signed))?;
                if self.metadata.id.is_none() {
                    if let Err(reason) = host
                        .sessions
                        .update_ingress_node_id(self.token(), &node_id)
                    {
                        debug!(
                            "failed to update node id of ingress session, reason = {:?}, session = {:?}",
                            reason, self
                        );
                        return Err(self.disconnect(
                            io,
                            DisconnectReason::UpdateNodeIdFailed,
                        ));
                    }

                    self.metadata.id = Some(node_id);
                } else {
                    if Some(node_id) != self.metadata.id {
                        return Err(self.disconnect(
                            io,
                            DisconnectReason::WrongEndpointInfo,
                        ));
                    }
                }
                let rlp = Rlp::new(signed);
                self.read_hello(io, &node_id, &rlp, host)?;
                Ok(SessionData::Ready)
            }
            PACKET_DISCONNECT => {
                let rlp = Rlp::new(&data);
                let reason: u8 = rlp.val_at(0)?;
                debug!(
                    "read packet DISCONNECT, reason = {}, session = {:?}",
                    DisconnectReason::from_u8(reason),
                    self
                );
                Err(ErrorKind::Disconnect(DisconnectReason::from_u8(reason))
                    .into())
            }
            PACKET_PING => {
                self.send_pong(io)?;
                Ok(SessionData::Continue)
            }
            PACKET_PONG => Ok(SessionData::Continue),
            PACKET_USER => {
                if data.len() < 3 {
                    Err(ErrorKind::Decoder.into())
                } else {
                    let mut protocol: ProtocolId = [0u8; 3];
                    protocol.clone_from_slice(&data[..3]);
                    Ok(SessionData::Message {
                        data: (&data[3..]).to_vec(),
                        protocol,
                    })
                }
            }
            _ => {
                debug!(
                    "read packet UNKNOWN, packet_id = {:?}, session = {:?}",
                    packet_id, self
                );
                Ok(SessionData::Continue)
            }
        }
    }

    fn read_hello<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, id: &NodeId, rlp: &Rlp,
        host: &NetworkServiceInner,
    ) -> Result<(), Error>
    {
        let peer_caps: Vec<Capability> = rlp.list_at(0)?;

        let mut caps: Vec<Capability> = Vec::new();
        for hc in host.metadata.capabilities.read().iter() {
            if peer_caps
                .iter()
                .any(|c| c.protocol == hc.protocol && c.version == hc.version)
            {
                caps.push(hc.clone());
            }
        }

        caps.retain(|c| {
            host.metadata
                .capabilities
                .read()
                .iter()
                .any(|hc| hc.protocol == c.protocol && hc.version == c.version)
        });
        let mut i = 0;
        while i < caps.len() {
            if caps.iter().any(|c| {
                c.protocol == caps[i].protocol && c.version > caps[i].version
            }) {
                caps.remove(i);
            } else {
                i += 1;
            }
        }
        caps.sort();

        self.metadata.capabilities = caps;
        self.metadata.peer_capabilities = peer_caps;
        if self.metadata.capabilities.is_empty() {
            debug!("No common capabilities with remote peer, peer_node_id = {:?}, session = {:?}", id, self);
            return Err(self.disconnect(io, DisconnectReason::UselessPeer));
        }

        let mut hello_from = NodeEndpoint::from_rlp(&rlp.at(1)?)?;
        // Use the ip of the socket as endpoint ip directly.
        // We do not allow peers to specify the ip to avoid being used to DDoS
        // the target ip.
        hello_from.address.set_ip(self.address.ip());

        let ping_to = NodeEndpoint {
            address: hello_from.address,
            udp_port: hello_from.udp_port,
        };

        let entry = NodeEntry {
            id: id.clone(),
            endpoint: ping_to.clone(),
        };
        if !entry.endpoint.is_valid() {
            debug!("Got invalid endpoint {:?}, session = {:?}", entry, self);
            return Err(self.disconnect(io, DisconnectReason::WrongEndpointInfo));
        } else if !(entry.endpoint.is_allowed(host.get_ip_filter())
            && entry.id != *host.metadata.id())
        {
            debug!(
                "Address not allowed, endpoint = {:?}, session = {:?}",
                entry, self
            );
            return Err(self.disconnect(io, DisconnectReason::IpLimited));
        } else {
            debug!("Received valid endpoint {:?}, session = {:?}", entry, self);
            host.node_db.write().insert_with_token(entry, self.token());
        }

        self.send_ping(io)?;
        self.had_hello = Some(Instant::now());

        Ok(())
    }

    pub fn send_packet<Message>(
        &mut self, io: &IoContext<Message>, protocol: Option<ProtocolId>,
        packet_id: u8, data: &[u8], priority: SendQueuePriority,
    ) -> Result<SendQueueStatus, Error>
    where
        Message: Send + Sync + Clone,
    {
        if protocol.is_some()
            && (self.metadata.capabilities.is_empty()
                || self.had_hello.is_none())
        {
            debug!(
                "Sending to unconfirmed session {}, protocol: {:?}, packet: {}",
                self.token(),
                protocol
                    .as_ref()
                    .map(|p| str::from_utf8(&p[..]).unwrap_or("???")),
                packet_id
            );
            bail!(ErrorKind::BadProtocol);
        }
        if self.expired() {
            return Err(ErrorKind::Expired.into());
        }
        let packet_size =
            1 + protocol.map(|p| p.len()).unwrap_or(0) + data.len();
        if packet_size > MAX_PAYLOAD_SIZE {
            error!(
                "Packet is too big, size = {}, max = {}, session = {:?}",
                packet_size, MAX_PAYLOAD_SIZE, self
            );
            bail!(ErrorKind::OversizedPacket);
        }
        let mut packet = BytesMut::with_capacity(3 + packet_size);
        packet.put_uint_le(packet_size as u64, 3);
        packet.put_u8(packet_id);
        if let Some(protocol) = protocol {
            packet.put_slice(&protocol);
        }
        packet.put_slice(&data);

        self.connection.send(io, &packet[..], priority)
    }

    pub fn disconnect<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, reason: DisconnectReason,
    ) -> Error {
        let mut rlp = RlpStream::new();
        rlp.begin_list(1).append(&(reason as u32));
        self.send_packet(
            io,
            None,
            PACKET_DISCONNECT,
            &rlp.drain(),
            SendQueuePriority::High,
        )
        .ok();
        ErrorKind::Disconnect(reason).into()
    }

    fn send_ping<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<(), Error> {
        self.send_packet(io, None, PACKET_PING, &[], SendQueuePriority::High)
            .map(|_| ())
    }

    fn send_pong<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<(), Error> {
        self.send_packet(io, None, PACKET_PONG, &[], SendQueuePriority::High)
            .map(|_| ())
    }

    fn write_hello<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, host: &NetworkServiceInner,
    ) -> Result<(), Error> {
        debug!("Sending Hello, session = {:?}", self);
        let mut rlp = RlpStream::new_list(2);
        rlp.append_list(&*host.metadata.capabilities.read());
        host.metadata.public_endpoint.to_rlp_list(&mut rlp);

        let mut packet =
            cfx_bytes::Bytes::with_capacity(rlp.as_raw().len() + 32 + 65);
        packet.resize(32 + 65, 0);
        packet.extend_from_slice(rlp.as_raw());
        let hash = keccak(&packet[(32 + 65)..]);
        let signature = match sign(host.metadata.keys.secret(), &hash) {
            Ok(s) => s,
            Err(e) => {
                debug!("failed to sign hello packet, session = {:?}", self);
                return Err(Error::from(e));
            }
        };
        packet[32..(32 + 65)].copy_from_slice(&signature[..]);
        let signed_hash = keccak(&packet[32..]);
        packet[0..32].copy_from_slice(&signed_hash);
        self.send_packet(
            io,
            None,
            PACKET_HELLO,
            &packet,
            SendQueuePriority::High,
        )
        .map(|_| ())
    }

    pub fn writable<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<(), Error> {
        match self.connection.writable(io) {
            Ok(status) => {
                self.last_write = (Instant::now(), Some(status));
                Ok(())
            }
            Err(e) => {
                self.last_write = (Instant::now(), None);
                Err(e)
            }
        }
    }

    pub fn details(&self) -> SessionDetails {
        SessionDetails {
            originated: self.metadata.originated,
            node_id: self.metadata.id,
            address: self.address,
            connection: self.connection.details(),
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

    pub fn check_timeout(&self) -> (bool, Option<UpdateNodeOperation>) {
        if let Some(time) = self.expired {
            // should disconnected timely once expired
            if time.elapsed() > Duration::from_secs(5) {
                return (true, None);
            }
        } else if self.had_hello.is_none() {
            // should receive HELLO packet timely after session created
            if self.sent_hello.elapsed() > Duration::from_secs(300) {
                return (true, Some(UpdateNodeOperation::Demotion));
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

#[derive(Serialize)]
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
