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
    connection::{Connection, WriteStatus},
    node_table::NodeId,
    service::HostMetadata,
    Error, ErrorKind,
};
use cfx_bytes::Bytes;
use cfx_types::{Public, H256, H520};
use io::{IoContext, StreamToken};
use keccak_hash::write_keccak;
use keylib::{
    crypto::{ecdh, ecies},
    recover, sign, Generator, KeyPair, Random, Secret,
};
use mio::tcp::TcpStream;
use priority_send_queue::SendQueuePriority;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

// used for test purpose only to bypass the cryptography
pub static BYPASS_CRYPTOGRAPHY: AtomicBool = AtomicBool::new(false);

#[derive(PartialEq, Eq, Debug)]
enum HandshakeState {
    /// Just created
    New,
    /// Waiting for auth packet
    ReadingAuth,
    /// Waiting for ack packet
    ReadingAck,
    /// Ready to start a session
    StartSession,
}

/// `RLPx` protocol handshake. See https://github.com/ethereum/devp2p/blob/master/rlpx.md#encrypted-handshake
pub struct Handshake {
    /// Remote node public key
    pub id: NodeId,
    /// Underlying connection
    pub connection: Connection,
    /// Handshake state
    state: HandshakeState,
    /// Outgoing or incoming connection
    pub originated: bool,
    /// ECDH ephemeral
    pub ecdhe: KeyPair,
    /// Connection nonce
    pub nonce: H256,
    /// Handshake public key
    pub remote_ephemeral: Public,
    /// Remote connection nonce.
    pub remote_nonce: H256,
    /// A copy of received encrypted auth packet
    pub auth_cipher: Bytes,
    /// A copy of received encrypted ack packet
    pub ack_cipher: Bytes,
}

const V4_AUTH_PACKET_SIZE: usize = 307;
const V4_ACK_PACKET_SIZE: usize = 210;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

impl Handshake {
    /// Create a new handshake object
    pub fn new(
        token: StreamToken, id: Option<&NodeId>, socket: TcpStream, nonce: H256,
    ) -> Result<Handshake, Error> {
        Ok(Handshake {
            id: id.cloned().unwrap_or_else(|| NodeId::new()),
            connection: Connection::new(token, socket),
            originated: false,
            state: HandshakeState::New,
            ecdhe: Random.generate()?,
            nonce,
            remote_ephemeral: Public::new(),
            remote_nonce: H256::new(),
            auth_cipher: Bytes::new(),
            ack_cipher: Bytes::new(),
        })
    }

    /// Start a handshake
    pub fn start<Message>(
        &mut self, io: &IoContext<Message>, host: &HostMetadata,
        originated: bool,
    ) -> Result<(), Error>
    where
        Message: Send + Clone + Sync + 'static,
    {
        self.originated = originated;

        io.register_timer(self.connection.token(), HANDSHAKE_TIMEOUT)
            .ok();

        if originated {
            self.write_auth(io, host.secret(), host.id())?;
        } else {
            self.state = HandshakeState::ReadingAuth;
        };

        Ok(())
    }

    /// Check if handshake is complete
    pub fn done(&self) -> bool { self.state == HandshakeState::StartSession }

    /// Readable IO handler. Drives the state change.
    pub fn readable<Message>(
        &mut self, io: &IoContext<Message>, host: &HostMetadata,
    ) -> Result<bool, Error>
    where Message: Send + Clone + Sync + 'static {
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
            HandshakeState::ReadingAck => {
                self.read_ack(host.secret(), &data)?;
            }
        }

        if self.state == HandshakeState::StartSession {
            io.clear_timer(self.connection.token()).ok();
        }

        trace!("handshake readable leave, state = {:?}", self.state);

        Ok(true)
    }

    /// Writable IO handler.
    pub fn writable<Message>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<WriteStatus, Error>
    where Message: Send + Clone + Sync + 'static {
        self.connection.writable(io)
    }

    fn set_auth(
        &mut self, host_secret: &Secret, sig: &[u8], remote_public: &[u8],
        remote_nonce: &[u8],
    ) -> Result<(), Error>
    {
        self.id.clone_from_slice(remote_public);
        self.remote_nonce.clone_from_slice(remote_nonce);
        let shared = *ecdh::agree(host_secret, &self.id)?;
        let signature = H520::from_slice(sig);
        self.remote_ephemeral =
            recover(&signature.into(), &(shared ^ self.remote_nonce))?;
        Ok(())
    }

    /// Parse, validate and confirm auth message
    fn read_auth<Message>(
        &mut self, io: &IoContext<Message>, secret: &Secret, data: &[u8],
    ) -> Result<(), Error>
    where Message: Send + Clone + Sync + 'static {
        trace!(
            "Received handshake auth from {:?}",
            self.connection.remote_addr_str()
        );

        if data.len() != V4_AUTH_PACKET_SIZE {
            debug!(
                "failed to read auth, wrong auth packet size {}, expected = {}",
                data.len(),
                V4_AUTH_PACKET_SIZE
            );
            return Err(ErrorKind::BadProtocol.into());
        }

        self.auth_cipher = data.to_vec();

        let auth = ecies::decrypt(secret, &[], data)?;
        let (sig, rest) = auth.split_at(65);
        let (_, rest) = rest.split_at(32);
        let (pubk, rest) = rest.split_at(64);
        let (nonce, _) = rest.split_at(32);

        self.set_auth(secret, sig, pubk, nonce)?;
        self.write_ack(io)?;

        Ok(())
    }

    // for test purpose only
    fn read_node_id<Message>(
        &mut self, io: &IoContext<Message>, public: &Public, data: &[u8],
    ) -> Result<(), Error>
    where Message: Send + Clone + Sync + 'static {
        trace!(
            "Received handshake auth from {:?}, node id len = {}",
            self.connection.remote_addr_str(),
            data.len()
        );
        assert_eq!(data.len(), 64);
        self.id.clone_from_slice(data);
        self.connection
            .send(io, public.to_vec(), SendQueuePriority::High)?;
        self.state = HandshakeState::StartSession;
        Ok(())
    }

    /// Parse and validate ack message
    fn read_ack(&mut self, secret: &Secret, data: &[u8]) -> Result<(), Error> {
        trace!(
            "Received handshake ack from {:?}",
            self.connection.remote_addr_str()
        );

        if data.len() != V4_ACK_PACKET_SIZE {
            debug!(
                "failed to read ack, wrong ack packet size {}, expected = {}",
                data.len(),
                V4_ACK_PACKET_SIZE
            );
            return Err(ErrorKind::BadProtocol.into());
        }

        self.ack_cipher = data.to_vec();

        let ack = ecies::decrypt(secret, &[], data)?;
        self.remote_ephemeral.clone_from_slice(&ack[0..64]);
        self.remote_nonce.clone_from_slice(&ack[64..(64 + 32)]);

        self.state = HandshakeState::StartSession;

        Ok(())
    }

    /// Sends auth message
    fn write_auth<Message>(
        &mut self, io: &IoContext<Message>, secret: &Secret, public: &Public,
    ) -> Result<(), Error>
    where Message: Send + Clone + Sync + 'static {
        trace!(
            "Sending handshake auth to {:?}",
            self.connection.remote_addr_str()
        );

        let mut data = [0u8; /*Signature::SIZE*/ 65 + /*H256::SIZE*/ 32 + /*Public::SIZE*/ 64 + /*H256::SIZE*/ 32 + 1];
        let len = data.len();
        {
            data[len - 1] = 0x0;
            let (sig, rest) = data.split_at_mut(65);
            let (hepubk, rest) = rest.split_at_mut(32);
            let (pubk, rest) = rest.split_at_mut(64);
            let (nonce, _) = rest.split_at_mut(32);

            // E(remote-pubk, S(ecdhe-random, ecdh-shared-secret^nonce) ||
            // H(ecdhe-random-pubk) || pubk || nonce || 0x0)
            let shared = *ecdh::agree(secret, &self.id)?;
            sig.copy_from_slice(&*sign(
                self.ecdhe.secret(),
                &(shared ^ self.nonce),
            )?);
            write_keccak(self.ecdhe.public(), hepubk);
            pubk.copy_from_slice(public.as_ref());
            nonce.copy_from_slice(self.nonce.as_ref());
        }

        let message = ecies::encrypt(&self.id, &[], &data)?;

        self.auth_cipher = message.clone();
        self.connection.send(io, message, SendQueuePriority::High)?;
        self.state = HandshakeState::ReadingAck;

        Ok(())
    }

    /// Sends ack message
    fn write_ack<Message>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<(), Error>
    where Message: Send + Clone + Sync + 'static {
        trace!(
            "Sending handshake ack to {:?}",
            self.connection.remote_addr_str()
        );

        let mut data = [0u8; 1 + /*Public::SIZE*/ 64 + /*H256::SIZE*/ 32];
        let len = data.len();
        {
            data[len - 1] = 0x0;
            let (epubk, rest) = data.split_at_mut(64);
            let (nonce, _) = rest.split_at_mut(32);
            self.ecdhe.public().copy_to(epubk);
            self.nonce.copy_to(nonce);
        }

        let message = ecies::encrypt(&self.id, &[], &data)?;
        self.ack_cipher = message.clone();
        self.connection.send(io, message, SendQueuePriority::High)?;
        self.state = HandshakeState::StartSession;
        Ok(())
    }
}
