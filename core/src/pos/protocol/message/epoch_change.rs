// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::{
        consensus::network_interface::ConsensusMsg,
        protocol::sync_protocol::{Context, Handleable},
    },
    sync::Error,
};
use diem_types::{
    account_address::AccountAddress, epoch_change::EpochChangeProof,
};
use std::{cmp::Ordering, mem::discriminant};

impl Handleable for EpochChangeProof {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        let msg = ConsensusMsg::EpochChangeProof(Box::new(self));
        ctx.manager
            .network_task
            .consensus_messages_tx
            .push((peer_address, discriminant(&msg)), (peer_address, msg))?;
        Ok(())
    }
}
