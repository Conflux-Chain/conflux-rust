// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::protocol::sync_protocol::{Context, Handleable},
    sync::Error,
};
use consensus_types::epoch_retrieval::EpochRetrievalRequest;
use diem_types::account_address::AccountAddress;
use std::cmp::Ordering;
use crate::pos::consensus::network_interface::ConsensusMsg;
use std::mem::discriminant;

impl Handleable for EpochRetrievalRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_epoch_retrieval, msg={:?}", &self);
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        debug!(
            "Received epoch retrieval from peer {}, start epoch {}, end epoch {}",
            peer_address, self.start_epohc_id, self.end_epoch_id
        );
        match self
            .end_epoch_id
            .cmp(&ctx.manager.network_task.epoch_id())
        {
            Ordering::Less | Ordering::Equal => {
                let msg = ConsensusMsg::EpochRetrievalRequest(Box::new(self));
                ctx
                    .manager
                    .network_task
                    .consensus_messages_tx
                    .push((peer_address, discriminant(&msg)), (peer_address, msg))?;
            },
            Ordering::Greater => {
                warn!("Received EpochRetrievalRequest beyond what we have locally");
            }
        }
        Ok(())
    }
}
