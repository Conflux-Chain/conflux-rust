// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    connection::Connection, node_table::NodeId, service::HostMetadata, Error,
    ErrorKind,
};
use cfx_types::{Public, H256};
use io::{IoContext, StreamToken};
use keylib::{crypto::ecies, Secret};
use mio::tcp::TcpStream;
use priority_send_queue::SendQueuePriority;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const AUTH_PACKET_SIZE: usize = 209;
const ACK_OF_AUTH_PACKET_SIZE: usize = 177;
const ACK_OF_ACK_PACKET_SIZE: usize = 145;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

// used for test purpose only to bypass the cryptography
pub static BYPASS_CRYPTOGRAPHY: AtomicBool = AtomicBool::new(false);

#[derive(PartialEq, Eq, Debug)]
enum HandshakeState {
    /// Just created
    New,
    /// Waiting for auth packet
    ReadingAuth,
    /// Waiting for ack of auth packet
    ReadingAckofAuth,
    /// Waiting for ack of ack packet
    ReadingAckofAck,
    /// Ready to start a session
    StartSession,
}

/// Three-way handshake to exchange the node Id.
pub struct Handshake {
    /// Remote node public key
    pub id: NodeId,
    /// Underlying connection
    pub connection: Connection,
    /// Handshake state
    state: HandshakeState,
    /// nonce for verification
    nonce: H256,
}

impl Handshake {
    /// Create a new handshake object
    pub fn new(
        token: StreamToken, id: Option<&NodeId>, socket: TcpStream,
    ) -> Self {
        Handshake {
            id: id.cloned().unwrap_or_else(NodeId::default),
            connection: Connection::new(token, socket),
            state: HandshakeState::New,
            nonce: H256::random(),
        }
    }

    /// Start a handshake
    pub fn start<Message>(
        &mut self, io: &IoContext<Message>, host: &HostMetadata,
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        io.register_timer(self.connection.token(), HANDSHAKE_TIMEOUT)?;

        if !self.id.is_zero() {
            self.write_auth(io, host.id())?;
        } else {
            self.state = HandshakeState::ReadingAuth;
        };

        Ok(())
    }

    /// Check if handshake is complete
    pub fn done(&self) -> bool {
        self.state == HandshakeState::StartSession
    }

    /// Readable IO handler. Drives the state change.
    pub fn readable<Message>(
        &mut self, io: &IoContext<Message>, host: &HostMetadata,
    ) -> Result<bool, Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        trace!("handshake readable enter, state = {:?}", self.state);

        let data = match self.connection.readable()? {
            Some(data) => data,
            None => return Ok(false),
        };

        match self.state {
            HandshakeState::New => {
                error!("handshake readable invalid for New state");
            }
            HandshakeState::StartSession => {
                error!("handshake readable invalid for StartSession state");
            }
            HandshakeState::ReadingAuth => {
                if data.len() == 64
                    && BYPASS_CRYPTOGRAPHY.load(Ordering::Relaxed)
                {
                    self.read_node_id(io, host.id(), &data)?;
                } else {
                    self.read_auth(io, host.secret(), &data)?;
                }
            }
            HandshakeState::ReadingAckofAuth => {
                self.read_ack_of_auth(io, host.secret(), &data)?;
            }
            HandshakeState::ReadingAckofAck => {
                self.read_ack_of_ack(host.secret(), &data)?;
            }
        }

        if self.state == HandshakeState::StartSession {
            io.clear_timer(self.connection.token())?;
        }

        trace!("handshake readable leave, state = {:?}", self.state);

        Ok(true)
    }

    /// Sends auth message
    fn write_auth<Message>(
        &mut self, io: &IoContext<Message>, public: &Public,
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        trace!(
            "Sending handshake auth to {:?}",
            self.connection.remote_addr_str()
        );

        let mut data =
            Vec::with_capacity(Public::len_bytes() + H256::len_bytes());
        data.extend_from_slice(public.as_bytes());
        data.extend_from_slice(self.nonce.as_bytes());

        let message = ecies::encrypt(&self.id, &[], &data)?;

        self.connection.send(io, message, SendQueuePriority::High)?;
        self.state = HandshakeState::ReadingAckofAuth;

        Ok(())
    }

    /// Parse, validate and confirm auth message
    fn read_auth<Message>(
        &mut self, io: &IoContext<Message>, secret: &Secret, data: &[u8],
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        trace!(
            "Received handshake auth from {:?}",
            self.connection.remote_addr_str()
        );

        if data.len() != AUTH_PACKET_SIZE {
            debug!(
                "failed to read auth, wrong packet size {}, expected = {}",
                data.len(),
                AUTH_PACKET_SIZE
            );
            return Err(ErrorKind::BadProtocol.into());
        }

        let auth = ecies::decrypt(secret, &[], data)?;

        let (remote_public, remote_nonce) = auth.split_at(NodeId::len_bytes());
        self.id.assign_from_slice(remote_public);

        self.write_ack_of_auth(io, remote_nonce)
    }

    /// Sends ack of auth message
    fn write_ack_of_auth<Message>(
        &mut self, io: &IoContext<Message>, remote_nonce: &[u8],
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        trace!(
            "Sending handshake ack of auth to {:?}",
            self.connection.remote_addr_str()
        );

        let mut data =
            Vec::with_capacity(remote_nonce.len() + H256::len_bytes());
        data.extend_from_slice(remote_nonce);
        data.extend_from_slice(self.nonce.as_ref());

        let message = ecies::encrypt(&self.id, &[], &data)?;

        self.connection.send(io, message, SendQueuePriority::High)?;
        self.state = HandshakeState::ReadingAckofAck;

        Ok(())
    }

    // for test purpose only
    fn read_node_id<Message>(
        &mut self, io: &IoContext<Message>, public: &Public, data: &[u8],
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        trace!(
            "Received handshake auth from {:?}, node id len = {}",
            self.connection.remote_addr_str(),
            data.len()
        );
        assert_eq!(data.len(), 64);
        self.id.assign_from_slice(data);
        self.connection.send(
            io,
            public.as_bytes().into(),
            SendQueuePriority::High,
        )?;
        self.state = HandshakeState::StartSession;
        Ok(())
    }

    /// Parse and validate ack of auth message
    fn read_ack_of_auth<Message>(
        &mut self, io: &IoContext<Message>, secret: &Secret, data: &[u8],
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        trace!(
            "Received handshake ack of auth from {:?}",
            self.connection.remote_addr_str()
        );

        if data.len() != ACK_OF_AUTH_PACKET_SIZE {
            debug!(
                "failed to read ack of auth, wrong packet size {}, expected = {}",
                data.len(),
                ACK_OF_AUTH_PACKET_SIZE
            );
            return Err(ErrorKind::BadProtocol.into());
        }

        let ack = ecies::decrypt(secret, &[], data)?;

        let (self_nonce, remote_nonce) = ack.split_at(H256::len_bytes());

        if self_nonce != &self.nonce[..] {
            debug!("failed to read ack of auth, nonce mismatch");
            return Err(ErrorKind::BadProtocol.into());
        }

        self.write_ack_of_ack(io, remote_nonce)
    }

    fn write_ack_of_ack<Message>(
        &mut self, io: &IoContext<Message>, remote_nonce: &[u8],
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        trace!(
            "Sending handshake ack of ack to {:?}",
            self.connection.remote_addr_str()
        );

        let message = ecies::encrypt(&self.id, &[], remote_nonce)?;

        self.connection.send(io, message, SendQueuePriority::High)?;
        self.state = HandshakeState::StartSession;

        Ok(())
    }

    fn read_ack_of_ack(
        &mut self, secret: &Secret, data: &[u8],
    ) -> Result<(), Error> {
        trace!(
            "Received handshake ack of ack from {:?}",
            self.connection.remote_addr_str()
        );

        if data.len() != ACK_OF_ACK_PACKET_SIZE {
            debug!(
                "failed to read ack of ack, wrong packet size {}, expected = {}",
                data.len(),
                ACK_OF_ACK_PACKET_SIZE
            );
            return Err(ErrorKind::BadProtocol.into());
        }

        let nonce = ecies::decrypt(secret, &[], data)?;

        if &nonce[..] != &self.nonce[..] {
            debug!("failed to read ack of ack, nonce mismatch");
            return Err(ErrorKind::BadProtocol.into());
        }

        self.state = HandshakeState::StartSession;

        Ok(())
    }
}
