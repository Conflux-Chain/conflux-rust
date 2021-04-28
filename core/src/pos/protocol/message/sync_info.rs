// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::protocol::sync_protocol::{Context, Handleable},
    sync::Error,
};
use consensus_types::sync_info::SyncInfo;
use diem_types::account_address::AccountAddress;
use std::cmp::Ordering;

impl Handleable for SyncInfo {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_sync_info, msg={:?}", &self);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        match self
            .epoch_id()
            .cmp(&ctx.manager.network_task.epoch_id())
        {
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
                .push(peer_address, (self.epoch_id(), peer_address))?,
        }

        Ok(())
    }
}
