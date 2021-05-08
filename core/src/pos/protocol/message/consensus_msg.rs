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
use consensus_types::epoch_retrieval::EpochRetrievalRequest;
use diem_types::account_address::AccountAddress;
use std::{cmp::Ordering, mem::discriminant};

impl Handleable for ConsensusMsg {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_consensus_msg, msg={:?}", &self);
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        ctx.manager
            .network_task
            .consensus_messages_tx
            .push((peer_address, discriminant(&self)), (peer_address, self))?;
        Ok(())
    }
}
