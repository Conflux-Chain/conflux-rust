// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        handleable::{Context, Handleable},
        Message, MsgId,
    },
    Error, ErrorKind, SynchronizationPeerState,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{collections::HashSet, time::Instant};

#[derive(Debug, PartialEq)]
pub struct Status {
    pub protocol_version: u8,
    pub network_id: u8,
    pub genesis_hash: H256,
    pub best_epoch: u64,
    pub terminal_block_hashes: Vec<H256>,
}

impl Handleable for Status {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        if !ctx.manager.syn.on_status(ctx.peer) {
            warn!("Unexpected Status message from peer={}", ctx.peer);
            return Err(ErrorKind::UnknownPeer.into());
        }

        debug!("on_status, msg=:{:?}", self);

        let genesis_hash = ctx.manager.graph.genesis_hash();
        if genesis_hash != self.genesis_hash {
            debug!(
                "Peer {:?} genesis hash mismatches (ours: {:?}, theirs: {:?})",
                ctx.peer, genesis_hash, self.genesis_hash
            );
            return Err(ErrorKind::Invalid.into());
        }

        let mut latest: HashSet<H256> =
            self.terminal_block_hashes.iter().cloned().collect();
        latest.extend(
            ctx.manager.graph.initial_missed_block_hashes.lock().drain(),
        );

        let peer_state = SynchronizationPeerState {
            id: ctx.peer,
            protocol_version: self.protocol_version,
            genesis_hash,
            best_epoch: self.best_epoch,
            latest_block_hashes: latest,
            received_transaction_count: 0,
            need_prop_trans: true,
            notified_mode: None,
            heartbeat: Instant::now(),
        };

        debug!(
            "New peer (pv={:?}, gh={:?})",
            self.protocol_version, self.genesis_hash
        );

        debug!("Peer {:?} connected", ctx.peer);
        ctx.manager.syn.peer_connected(ctx.peer, peer_state);
        ctx.manager.request_manager.on_peer_connected(ctx.peer);

        ctx.manager.start_sync(ctx.io);

        Ok(())
    }
}

impl Message for Status {
    fn msg_id(&self) -> MsgId { MsgId::STATUS }
}

impl Encodable for Status {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(5)
            .append(&self.protocol_version)
            .append(&self.network_id)
            .append(&self.genesis_hash)
            .append(&self.best_epoch)
            .append_list(&self.terminal_block_hashes);
    }
}

impl Decodable for Status {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Status {
            protocol_version: rlp.val_at::<u8>(0)?,
            network_id: rlp.val_at::<u8>(1)?,
            genesis_hash: rlp.val_at::<H256>(2)?,
            best_epoch: rlp.val_at::<u64>(3)?,
            terminal_block_hashes: rlp.list_at(4)?,
        })
    }
}
