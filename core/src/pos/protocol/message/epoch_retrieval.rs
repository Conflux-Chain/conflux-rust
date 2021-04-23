// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    pos::consensus::consensus_types::{
        common::Payload, membership_retrieval::MembershipRetrievalRequest,
    },
    sync::Error,
};
use diem_types::account_address::AccountAddress;
use std::cmp::Ordering;

impl<P: Payload> Handleable<P> for MembershipRetrievalRequest {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        debug!("on_epoch_retrieval, msg={:?}", &self);
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        debug!(
            "Received epoch retrieval from peer {}, start epoch {}, end epoch {}",
            peer_address, self.start_membership_id, self.end_membership_id
        );
        match self
            .end_membership_id
            .cmp(&ctx.manager.network_task.membership_id())
        {
            Ordering::Less | Ordering::Equal => ctx
                .manager
                .network_task
                .membership_retrieval_tx
                .push(peer_address, (self, peer_address))?,
            Ordering::Greater => {
                warn!("Received EpochRetrievalRequest beyond what we have locally");
            }
        }
        Ok(())
    }
}
