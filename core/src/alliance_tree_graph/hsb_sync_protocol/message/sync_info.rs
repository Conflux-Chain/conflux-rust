// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    alliance_tree_graph::bft::consensus::consensus_types::{
        common::Payload, sync_info::SyncInfo,
    },
    sync::Error,
};
use libra_types::account_address::AccountAddress;
use std::cmp::Ordering;

impl<P: Payload> Handleable<P> for SyncInfo {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        debug!("on_sync_info, msg={:?}", &self);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        match self.epoch().cmp(&ctx.manager.network_task.epoch()) {
            Ordering::Equal => {
                // SyncInfo verification is postponed to the moment it's
                // actually used.
                ctx.manager
                    .network_task
                    .sync_info_tx
                    .push(peer_address, (self, peer_address))?
            }
            Ordering::Less | Ordering::Greater => ctx
                .manager
                .network_task
                .different_epoch_tx
                .push(peer_address, (self.epoch(), peer_address))?,
        }

        Ok(())
    }
}
