// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::protocol::sync_protocol::{Context, Handleable},
    sync::Error,
};
use consensus_types::vote_msg::VoteMsg;
use diem_types::account_address::AccountAddress;

impl Handleable for VoteMsg {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_vote, msg={:?}", &self);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        ensure!(
            self.vote().author() == peer_address,
            "vote received must be from the sending peer"
        );

        if self.epoch_id() != ctx.manager.network_task.epoch_id() {
            ctx.manager
                .network_task
                .different_epoch_tx
                .push(peer_address, (self.epoch_id(), peer_address))?;
            return Ok(());
        }

        self.verify(&ctx.manager.network_task.epoch_info.read().verifier)?;
        ctx.manager.network_task.vote_tx.push(peer_address, self)?;
        Ok(())
    }
}
