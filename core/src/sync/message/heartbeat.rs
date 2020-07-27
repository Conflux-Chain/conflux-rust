// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::handleable::{Context, Handleable},
    Error,
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{collections::HashSet, time::Instant};

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct Heartbeat {
    pub best_epoch: u64,
    pub terminal_block_hashes: Vec<H256>,
}

impl Handleable for Heartbeat {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_heartbeat, msg=:{:?}", self);

        if let Ok(peer_info) = ctx.manager.syn.get_peer_info(&ctx.node_id) {
            let latest: HashSet<H256> =
                self.terminal_block_hashes.iter().cloned().collect();

            let latest_updated = {
                let mut peer_info = peer_info.write();
                peer_info.heartbeat = Instant::now();

                let updated = self.best_epoch != peer_info.best_epoch
                    || latest != peer_info.latest_block_hashes;

                // NOTE: we need to update best_epoch even if it's smaller than
                // the previous value, otherwise sync will get stuck in tests
                // with large chain reorg (decreasing best epoch value)
                if updated {
                    peer_info.best_epoch = self.best_epoch;
                    peer_info.latest_block_hashes = latest;
                }

                updated
            };

            if latest_updated {
                ctx.manager.start_sync(ctx.io);
            }
        }

        Ok(())
    }
}
