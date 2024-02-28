// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::handleable::{Context, Handleable},
    Error,
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::collections::HashSet;

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
                peer_info.update(None, latest, self.best_epoch)
            };

            if latest_updated {
                ctx.manager.start_sync(ctx.io);
            }
        }

        Ok(())
    }
}
