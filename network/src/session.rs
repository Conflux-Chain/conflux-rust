// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    connection::{Connection, ConnectionDetails, SendQueueStatus, WriteStatus},
    handshake::Handshake,
    node_table::{NodeEndpoint, NodeEntry, NodeId},
    service::NetworkServiceInner,
    Capability, DisconnectReason, Error, ErrorKind, ProtocolId,
    SessionMetadata, UpdateNodeOperation, PROTOCOL_ID_SIZE,
};
use bytes::Bytes;
use io::*;
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

pub struct Session {
    pub metadata: SessionMetadata,
    address: SocketAddr,
    state: State,
    sent_hello: Instant,
    had_hello: Option<Instant>,
    expired: Option<Instant>,

    // statistics for read/write
    last_read: Instant,
    last_write: (Instant, Option<WriteStatus>), // None for error
}

enum State {
    Handshake(MovableWrapper<Handshake>),
    Session(Connection),
}

pub enum SessionData {
    None,
    Ready,
    Message { data: Vec<u8>, protocol: ProtocolId },
}

const PACKET_HELLO: u8 = 0x80;
const PACKET_DISCONNECT: u8 = 0x01;
pub const PACKET_USER: u8 = 0x10;

impl Session {
    pub fn new<Message: Send + Sync + Clone + 'static>(
        io: &IoContext<Message>, socket: TcpStream, address: SocketAddr,
        id: Option<&NodeId>, token: StreamToken, host: &NetworkServiceInner,
    ) -> Result<Session, Error>
    {
        let originated = id.is_some();

        let nonce = host.metadata.next_nonce();
        let mut handshake = Handshake::new(token, id, socket, nonce)?;
        handshake.start(io, &host.metadata, originated)?;

        Ok(Session {
            metadata: SessionMetadata {
                id: id.cloned(),
                capabilities: Vec::new(),
                peer_capabilities: Vec::new(),
                originated,
            },
            address,
            state: State::Handshake(MovableWrapper::new(handshake)),
            sent_hello: Instant::now(),
            had_hello: None,
            expired: None,
            last_read: Instant::now(),
            last_write: (Instant::now(), None),
        })
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

    pub fn register_socket<H: Handler>(
        &self, reg: Token, event_loop: &mut EventLoop<H>,
    ) -> Result<(), Error> {
        if !self.expired() {
            self.connection().register_socket(reg, event_loop)?;
        }

        Ok(())
    }

    pub fn update_socket<H: Handler>(
        &self, reg: Token, event_loop: &mut EventLoop<H>,
    ) -> Result<(), Error> {
        self.connection().update_socket(reg, event_loop)?;
        Ok(())
    }

    pub fn deregister_socket<H: Handler>(
        &self, event_loop: &mut EventLoop<H>,
    ) -> Result<(), Error> {
        self.connection().deregister_socket(event_loop)?;
        Ok(())
    }

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

    pub fn readable<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, host: &NetworkServiceInner,
    ) -> Result<SessionData, Error> {
        self.last_read = Instant::now();

        if self.expired() {
            debug!("cannot read data due to expired, session = {:?}", self);
            return Ok(SessionData::None);
        }

        match self.state {
            State::Handshake(ref mut h) => {
                let h = h.get_mut();
                h.readable(io, &host.metadata)?;
                if h.done() {
                    self.complete_handshake(io, host)?;
                    io.update_registration(self.token()).unwrap_or_else(|e| {
                        debug!("Token registration error: {:?}", e)
                    });
                }
                Ok(SessionData::None)
            }
            State::Session(ref mut c) => match c.readable()? {
                Some(data) => Ok(self.read_packet(data, host)?),
                None => Ok(SessionData::None),
            },
        }
    }

    fn read_packet(
        &mut self, data: Bytes, host: &NetworkServiceInner,
    ) -> Result<SessionData, Error> {
        let packet = SessionPacket::parse(data)?;

        if packet.id != PACKET_HELLO
            && packet.id != PACKET_DISCONNECT
            && self.had_hello.is_none()
        {
            return Err(ErrorKind::BadProtocol.into());
        }

        match packet.id {
            PACKET_HELLO => {
                self.update_ingress_node_id(host)?;

                let rlp = Rlp::new(&packet.data);
                self.read_hello(&rlp, host)?;
                Ok(SessionData::Ready)
            }
            PACKET_DISCONNECT => {
                let rlp = Rlp::new(&packet.data);
                let reason: DisconnectReason = rlp.as_val()?;
                debug!(
                    "read packet DISCONNECT, reason = {}, session = {:?}",
                    reason, self
                );
                Err(ErrorKind::Disconnect(reason).into())
            }
            PACKET_USER => Ok(SessionData::Message {
                data: packet.data.to_vec(),
                protocol: packet
                    .protocol
                    .expect("protocol should available for USER packet"),
            }),
            _ => {
                debug!(
                    "read packet UNKNOWN, packet_id = {:?}, session = {:?}",
                    packet.id, self
                );
                Err(ErrorKind::BadProtocol.into())
            }
        }
    }

    /// Update node Id for ingress session.
    fn update_ingress_node_id(
        &mut self, host: &NetworkServiceInner,
    ) -> Result<(), Error> {
        // ignore egress session
        if self.metadata.originated {
            return Ok(());
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

    fn read_hello(
        &mut self, rlp: &Rlp, host: &NetworkServiceInner,
    ) -> Result<(), Error> {
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
            debug!("No common capabilities with remote peer, peer_node_id = {:?}, session = {:?}", self.metadata.id, self);
            return Err(self.send_disconnect(DisconnectReason::UselessPeer));
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
            id: self
                .metadata
                .id
                .expect("should have node ID after handshake"),
            endpoint: ping_to.clone(),
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

        Ok(())
    }

    fn prepare_packet(
        &self, protocol: Option<ProtocolId>, packet_id: u8, data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
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

        Ok(SessionPacket::assemble(packet_id, protocol, data))
    }

    pub fn send_packet<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, protocol: Option<ProtocolId>,
        packet_id: u8, data: Vec<u8>, priority: SendQueuePriority,
    ) -> Result<SendQueueStatus, Error>
    {
        let packet = self.prepare_packet(protocol, packet_id, data)?;
        self.connection_mut().send(io, packet, priority)
    }

    pub fn send_packet_immediately(
        &mut self, protocol: Option<ProtocolId>, packet_id: u8, data: Vec<u8>,
    ) -> Result<usize, Error> {
        let packet = self.prepare_packet(protocol, packet_id, data)?;
        self.connection_mut().write_raw_data(packet)
    }

    pub fn send_disconnect(&mut self, reason: DisconnectReason) -> Error {
        let packet = rlp::encode(&reason);
        let _ = self.send_packet_immediately(None, PACKET_DISCONNECT, packet);
        ErrorKind::Disconnect(reason).into()
    }

    fn write_hello<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>, host: &NetworkServiceInner,
    ) -> Result<(), Error> {
        debug!("Sending Hello, session = {:?}", self);
        let mut rlp = RlpStream::new_list(2);
        rlp.append_list(&*host.metadata.capabilities.read());
        host.metadata.public_endpoint.to_rlp_list(&mut rlp);
        self.send_packet(
            io,
            None,
            PACKET_HELLO,
            rlp.drain(),
            SendQueuePriority::High,
        )
        .map(|_| ())
    }

    pub fn writable<Message: Send + Sync + Clone>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<(), Error> {
        let result = match self.state {
            State::Handshake(ref mut h) => h.get_mut().writable(io),
            State::Session(ref mut s) => s.writable(io),
        };

        match result {
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

#[derive(Eq, PartialEq)]
struct SessionPacket {
    pub id: u8,
    pub protocol: Option<ProtocolId>,
    pub data: Bytes,
}

impl SessionPacket {
    // data + Option<protocol> + protocol_flag + packet_id
    fn assemble(
        id: u8, protocol: Option<ProtocolId>, mut data: Vec<u8>,
    ) -> Vec<u8> {
        let mut protocol_flag = 0;
        if let Some(protocol) = protocol {
            data.extend_from_slice(&protocol);
            protocol_flag = 1;
        }

        data.push(protocol_flag);
        data.push(id);

        data
    }

    fn parse(mut data: Bytes) -> Result<Self, Error> {
        // packet id
        if data.len() == 0 {
            debug!("failed to parse session packet, packet id missed");
            return Err(ErrorKind::BadProtocol.into());
        }

        let packet_id = data.split_off(data.len() - 1)[0];

        // protocol flag
        if data.len() == 0 {
            debug!("failed to parse session packet, protocol flag missed");
            return Err(ErrorKind::BadProtocol.into());
        }

        let protocol_flag = data.split_off(data.len() - 1)[0];
        if protocol_flag > 1 {
            debug!("failed to parse session packet, protocol flag is invalid");
            return Err(ErrorKind::BadProtocol.into());
        }

        // without protocol
        if protocol_flag == 0 {
            if packet_id == PACKET_USER {
                debug!("failed to parse session packet, no protocol for user packet");
                return Err(ErrorKind::BadProtocol.into());
            }

            return Ok(SessionPacket {
                id: packet_id,
                protocol: None,
                data,
            });
        }

        if packet_id != PACKET_USER {
            debug!("failed to parse session packet, invalid packet id");
            return Err(ErrorKind::BadProtocol.into());
        }

        // protocol
        if data.len() < PROTOCOL_ID_SIZE {
            debug!("failed to parse session packet, protocol missed");
            return Err(ErrorKind::BadProtocol.into());
        }

        let protocol_bytes = data.split_off(data.len() - PROTOCOL_ID_SIZE);
        let mut protocol = ProtocolId::default();
        protocol.copy_from_slice(&protocol_bytes);

        Ok(SessionPacket {
            id: packet_id,
            protocol: Some(protocol),
            data,
        })
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
        let packet = SessionPacket::assemble(5, None, vec![1, 3]);
        assert_eq!(packet, vec![1, 3, 0, 5]);

        let packet = SessionPacket::assemble(6, Some([8; 3]), vec![2, 4]);
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
                protocol: None,
                data: vec![1, 2].into(),
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
                protocol: Some([3; 3]),
                data: vec![1, 9].into(),
            }
        );
    }
}
