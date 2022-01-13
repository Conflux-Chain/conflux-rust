// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::{
        consensus::network::ConsensusMsg,
        protocol::sync_protocol::{Context, Handleable},
    },
    sync::Error,
};
use diem_types::epoch_change::EpochChangeProof;
use std::mem::discriminant;

impl Handleable for EpochChangeProof {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer_address = ctx.get_peer_account_address()?;
        let msg = ConsensusMsg::EpochChangeProof(Box::new(self));
        ctx.manager
            .consensus_network_task
            .consensus_messages_tx
            .push((peer_address, discriminant(&msg)), (peer_address, msg))?;
        Ok(())
    }
}
