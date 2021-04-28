// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::protocol::sync_protocol::{Context, Handleable},
    sync::Error
};
use diem_types::{
    account_address::AccountAddress, epoch_change::EpochChangeProof,
};
use std::cmp::Ordering;
use crate::pos::consensus::network_interface::ConsensusMsg;
use std::mem::discriminant;

impl Handleable for EpochChangeProof {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        let msg_epoch = self.epoch_id()?;
        match msg_epoch.cmp(&ctx.manager.network_task.epoch_id()) {
            Ordering::Equal => {
                /*let rlock = ctx.manager.network_task.epoch_info.read();
                let target_ledger_info = self.verify(
                    rlock.epoch_id,
                    &rlock.verifier,
                    true, /* return_first */
                )?;
                debug!(
                    "Received epoch change to {}",
                    target_ledger_info.ledger_info().epoch_id() + 1
                );*/
                let msg = ConsensusMsg::EpochChangeProof(Box::new(self));
                ctx.manager
                    .network_task
                    .consensus_messages_tx
                    .push((peer_address, discriminant(&msg)), (peer_address, msg))?;
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
