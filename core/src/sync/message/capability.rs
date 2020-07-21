// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::Message,
    sync::{
        message::{Context, Handleable},
        Error, SynchronizationState,
    },
};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use network::{node_table::NodeId, NetworkContext};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Debug, Eq, PartialEq, Clone, Copy, DeriveMallocSizeOf)]
pub enum DynamicCapability {
    NormalPhase(bool),  // provide tx relay
    ServeHeaders(bool), // provide block header downloads
}

impl DynamicCapability {
    fn code(&self) -> u8 {
        match self {
            DynamicCapability::NormalPhase(_) => 0,
            DynamicCapability::ServeHeaders(_) => 1,
        }
    }

    pub fn broadcast_with_peers(
        self, io: &dyn NetworkContext, peers: Vec<NodeId>,
    ) {
        let msg = DynamicCapabilityChange { changed: self };

        for peer in peers {
            if let Err(e) = msg.send(io, &peer) {
                debug!("Failed to send capability change message, peer = {}, message = {:?}, err = {:?}", peer, msg, e);
            }
        }
    }

    pub fn broadcast(
        self, io: &dyn NetworkContext, syn: &SynchronizationState,
    ) {
        let peers = syn.peers.read().keys().cloned().collect();
        self.broadcast_with_peers(io, peers);
    }
}

impl Encodable for DynamicCapability {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2).append(&self.code());

        match self {
            DynamicCapability::NormalPhase(enabled) => s.append(enabled),
            DynamicCapability::ServeHeaders(enabled) => s.append(enabled),
        };
    }
}

impl Decodable for DynamicCapability {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        match rlp.val_at::<u8>(0)? {
            0 => Ok(DynamicCapability::NormalPhase(rlp.val_at(1)?)),
            1 => Ok(DynamicCapability::ServeHeaders(rlp.val_at(1)?)),
            _ => Err(DecoderError::Custom("invalid capability code")),
        }
    }
}

#[derive(Debug, Default, DeriveMallocSizeOf)]
pub struct DynamicCapabilitySet {
    caps: [Option<DynamicCapability>; 3],
}

impl DynamicCapabilitySet {
    pub fn insert(&mut self, cap: DynamicCapability) {
        self.caps[cap.code() as usize] = Some(cap);
    }

    pub fn contains(&self, cap: DynamicCapability) -> bool {
        match self.caps[cap.code() as usize].as_ref() {
            Some(cur_cap) => cur_cap == &cap,
            None => return false,
        }
    }
}

#[derive(Debug)]
pub struct DynamicCapabilityChange {
    pub changed: DynamicCapability,
}

impl Encodable for DynamicCapabilityChange {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_internal(&self.changed);
    }
}

impl Decodable for DynamicCapabilityChange {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let changed = d.as_val()?;
        Ok(DynamicCapabilityChange { changed })
    }
}

impl Handleable for DynamicCapabilityChange {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!(
            "handle dynamic_capability_change: msg={:?}, peer={}",
            self, ctx.node_id
        );
        let peer = ctx.manager.syn.get_peer_info(&ctx.node_id)?;
        peer.write().capabilities.insert(self.changed);
        Ok(())
    }
}
