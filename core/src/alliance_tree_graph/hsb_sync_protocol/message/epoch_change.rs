// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    alliance_tree_graph::bft::consensus::consensus_types::common::Payload,
    sync::Error,
};
use libra_types::{
    account_address::AccountAddress, validator_change::ValidatorChangeProof,
};
use std::cmp::Ordering;

impl<P: Payload> Handleable<P> for ValidatorChangeProof {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        let msg_epoch = self.epoch()?;
        match msg_epoch.cmp(&ctx.manager.network_task.epoch()) {
            Ordering::Equal => {
                let rlock = ctx.manager.network_task.epoch_info.read().unwrap();
                let target_ledger_info =
                    self.verify(rlock.epoch, &rlock.verifier)?;
                debug!(
                    "Received epoch change to {}",
                    target_ledger_info.ledger_info().epoch() + 1
                );
                ctx.manager
                    .network_task
                    .epoch_change_tx
                    .push(peer_address, target_ledger_info)?;
            }
            Ordering::Less | Ordering::Greater => ctx
                .manager
                .network_task
                .different_epoch_tx
                .push(peer_address, (msg_epoch, peer_address))?,
        }
        Ok(())
    }
}
