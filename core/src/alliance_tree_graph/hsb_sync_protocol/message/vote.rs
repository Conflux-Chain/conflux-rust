// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    alliance_tree_graph::bft::consensus::consensus_types::{
        common::Payload, vote_msg::VoteMsg,
    },
    sync::Error,
};
use libra_logger::prelude::{security_log, SecurityEvent};
use libra_types::account_address::AccountAddress;

impl<P: Payload> Handleable<P> for VoteMsg {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        debug!("on_vote, msg={:?}", &self);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        ensure!(
            self.vote().author() == peer_address,
            "vote received must be from the sending peer"
        );

        if self.epoch() != ctx.manager.network_task.epoch() {
            ctx.manager
                .network_task
                .different_epoch_tx
                .push(peer_address, (self.epoch(), peer_address))?;
            return Ok(());
        }

        self.verify(&ctx.manager.network_task.epoch_info.read().verifier)
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
