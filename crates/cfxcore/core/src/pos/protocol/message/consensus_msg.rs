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
use diem_logger::prelude::diem_debug;
use std::mem::discriminant;

impl Handleable for ConsensusMsg {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        diem_debug!("on_consensus_msg, msg={:?}", &self);
        let peer_address = ctx.get_peer_account_address()?;
        let author = match &self {
            ConsensusMsg::ProposalMsg(p) => p.proposer(),
            ConsensusMsg::VoteMsg(v) => v.vote().author(),
            _ => peer_address,
        };
        ctx.manager
            .consensus_network_task
            .consensus_messages_tx
            .push((author, discriminant(&self)), (peer_address, self))?;
        Ok(())
    }
}
