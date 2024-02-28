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

use consensus_types::proposal_msg::ProposalMsg;
use diem_logger::prelude::diem_debug;
use std::mem::discriminant;

impl Handleable for ProposalMsg {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        diem_debug!("on_proposal, msg={:?}", &self);

        let peer_address = ctx.get_peer_account_address()?;

        /*ensure!(
            self.author() == Some(peer_address),
            "proposal received must be from the sending peer"
        );*/

        let author = self.proposer();
        let msg = ConsensusMsg::ProposalMsg(Box::new(self));
        ctx.manager
            .consensus_network_task
            .consensus_messages_tx
            .push((author, discriminant(&msg)), (peer_address, msg))?;
        Ok(())
    }
}
