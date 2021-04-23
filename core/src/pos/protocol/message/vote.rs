// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    pos::consensus::consensus_types::{common::Payload, vote_msg::VoteMsg},
    sync::Error,
};
use diem_types::account_address::AccountAddress;
use libra_logger::prelude::{security_log, SecurityEvent};

impl<P: Payload> Handleable<P> for VoteMsg {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        debug!("on_vote, msg={:?}", &self);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        ensure!(
            self.vote().author() == peer_address,
            "vote received must be from the sending peer"
        );

        if self.membership_id() != ctx.manager.network_task.membership_id() {
            ctx.manager
                .network_task
                .different_membership_tx
                .push(peer_address, (self.membership_id(), peer_address))?;
            return Ok(());
        }

        self.verify(&ctx.manager.network_task.membership_info.read().verifier)
            .map_err(|e| {
                security_log(SecurityEvent::InvalidConsensusVote)
                    .error(&e)
                    .data(&self)
                    .log();
                e
            })?;
        ctx.manager.network_task.vote_tx.push(peer_address, self)?;
        Ok(())
    }
}
