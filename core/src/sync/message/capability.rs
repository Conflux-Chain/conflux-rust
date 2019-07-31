// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable},
    msg_sender::send_message,
    Error, SynchronizationState,
};
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodableWrapper, RlpEncodableWrapper};
use std::collections::HashMap;

#[derive(Debug, Eq, PartialEq)]
pub enum Capability {
    TxRelay(bool),                 // provide tx relay
    ServeHeaders(bool),            // provide block header downloads
    ServeCheckpoint(Option<H256>), // provide checkpoint downloads
}

impl Capability {
    fn code(&self) -> u8 {
        match self {
            Capability::TxRelay(_) => 0,
            Capability::ServeHeaders(_) => 1,
            Capability::ServeCheckpoint(_) => 2,
        }
    }

    pub fn broadcast_with_peers(self, io: &NetworkContext, peers: Vec<PeerId>) {
        let msg = CapabilityChange { changed: self };

        for peer in peers {
            if let Err(e) = send_message(io, peer, &msg) {
                debug!("Failed to send capability change message, peer = {}, message = {:?}, err = {:?}", peer, msg, e);
            }
        }
    }

    pub fn broadcast(self, io: &NetworkContext, syn: &SynchronizationState) {
        let peers = syn.peers.read().keys().cloned().collect();
        self.broadcast_with_peers(io, peers);
    }
}

impl Encodable for Capability {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2).append(&self.code());

        match self {
            Capability::TxRelay(enabled) => s.append(enabled),
            Capability::ServeHeaders(enabled) => s.append(enabled),
            Capability::ServeCheckpoint(cp) => s.append(cp),
        };
    }
}

impl Decodable for Capability {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        match rlp.val_at::<u8>(0)? {
            0 => Ok(Capability::TxRelay(rlp.val_at(1)?)),
            1 => Ok(Capability::ServeHeaders(rlp.val_at(1)?)),
            2 => Ok(Capability::ServeCheckpoint(rlp.val_at(1)?)),
            _ => Err(DecoderError::Custom("invalid capability code")),
        }
    }
}

#[derive(Debug, Default)]
pub struct CapabilitySet {
    // received capabilities from remote peer
    recv: HashMap<u8, Capability>,
}

impl CapabilitySet {
    fn receive(&mut self, cap: Capability) {
        self.recv.insert(cap.code(), cap);
    }

    pub fn contains(&self, cap: Capability) -> bool {
        match self.recv.get(&cap.code()) {
            Some(cur_cap) => cur_cap == &cap,
            None => return false,
        }
    }
}

#[derive(Debug, RlpDecodableWrapper, RlpEncodableWrapper)]
pub struct CapabilityChange {
    pub changed: Capability,
}

impl Handleable for CapabilityChange {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer = ctx.manager.syn.get_peer_info(&ctx.peer)?;
        peer.write().capabilities.receive(self.changed);
        Ok(())
    }
}
