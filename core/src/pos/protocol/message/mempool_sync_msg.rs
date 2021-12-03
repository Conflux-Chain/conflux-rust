// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::{
        mempool::network::MempoolSyncMsg,
        protocol::sync_protocol::{Context, Handleable},
    },
    sync::Error,
};
use std::mem::discriminant;

impl Handleable for MempoolSyncMsg {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        ctx.manager
            .mempool_network_task
            .mempool_sync_message_tx
            .push((ctx.peer, discriminant(&self)), (ctx.peer, self))?;
        Ok(())
    }
}
