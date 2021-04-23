// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use super::super::sync_protocol::{Context, Handleable};
use crate::{pos::consensus::consensus_types::common::Payload, sync::Error};
use diem_types::{
    account_address::AccountAddress, validator_change::ValidatorChangeProof,
};
use std::cmp::Ordering;

impl<P: Payload> Handleable<P> for ValidatorChangeProof {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        let msg_epoch = self.membership_id()?;
        match msg_epoch.cmp(&ctx.manager.network_task.membership_id()) {
            Ordering::Equal => {
                let rlock = ctx.manager.network_task.membership_info.read();
                let target_ledger_info = self.verify(
                    rlock.membership_id,
                    &rlock.verifier,
                    true, /* return_first */
                )?;
                debug!(
                    "Received epoch change to {}",
                    target_ledger_info.ledger_info().membership_id() + 1
                );
                ctx.manager
                    .network_task
                    .membership_change_tx
                    .push(peer_address, target_ledger_info)?;
            }
            Ordering::Less | Ordering::Greater => ctx
                .manager
                .network_task
                .different_membership_tx
                .push(peer_address, (msg_epoch, peer_address))?,
        }
        Ok(())
    }
}
