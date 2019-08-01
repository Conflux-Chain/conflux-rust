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
pub enum DynamicCapability {
    TxRelay(bool),                 // provide tx relay
    ServeHeaders(bool),            // provide block header downloads
    ServeCheckpoint(Option<H256>), // provide checkpoint downloads
}

impl DynamicCapability {
    fn code(&self) -> u8 {
        match self {
            DynamicCapability::TxRelay(_) => 0,
            DynamicCapability::ServeHeaders(_) => 1,
            DynamicCapability::ServeCheckpoint(_) => 2,
        }
    }

    pub fn broadcast_with_peers(self, io: &NetworkContext, peers: Vec<PeerId>) {
        let msg = DynamicCapabilityChange { changed: self };

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

impl Encodable for DynamicCapability {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2).append(&self.code());

        match self {
            DynamicCapability::TxRelay(enabled) => s.append(enabled),
            DynamicCapability::ServeHeaders(enabled) => s.append(enabled),
            DynamicCapability::ServeCheckpoint(cp) => s.append(cp),
        };
    }
}

impl Decodable for DynamicCapability {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        match rlp.val_at::<u8>(0)? {
            0 => Ok(DynamicCapability::TxRelay(rlp.val_at(1)?)),
            1 => Ok(DynamicCapability::ServeHeaders(rlp.val_at(1)?)),
            2 => Ok(DynamicCapability::ServeCheckpoint(rlp.val_at(1)?)),
            _ => Err(DecoderError::Custom("invalid capability code")),
        }
    }
}

#[derive(Debug, Default)]
pub struct DynamicCapabilitySet {
    caps: HashMap<u8, DynamicCapability>,
}

impl DynamicCapabilitySet {
    pub fn insert(&mut self, cap: DynamicCapability) {
        self.caps.insert(cap.code(), cap);
    }

    pub fn contains(&self, cap: DynamicCapability) -> bool {
        match self.caps.get(&cap.code()) {
            Some(cur_cap) => cur_cap == &cap,
            None => return false,
        }
    }
}

#[derive(Debug, RlpDecodableWrapper, RlpEncodableWrapper)]
pub struct DynamicCapabilityChange {
    pub changed: DynamicCapability,
}

impl Handleable for DynamicCapabilityChange {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer = ctx.manager.syn.get_peer_info(&ctx.peer)?;
        peer.write().capabilities.insert(self.changed);
        Ok(())
    }
}
