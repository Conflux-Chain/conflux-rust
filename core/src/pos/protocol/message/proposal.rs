// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    pos::{
        protocol::sync_protocol::{Context, Handleable},
        consensus::network_interface::ConsensusMsg
    },
    sync::Error,
};

use diem_types::{
    account_address::AccountAddress, transaction::SignedTransaction,
};
use consensus_types::proposal_msg::ProposalMsg;
use std::mem::discriminant;

impl Handleable for ProposalMsg {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_proposal, msg={:?}", self.0);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        /*
        if self.epoch_id() != ctx.manager.network_task.epoch_id() {
            ctx.manager
                .network_task
                .different_epoch_tx
                .push(peer_address, (self.epoch_id(), peer_address))?;
            return Ok(());
        }*/

        ensure!(
            self.author() == Some(peer_address),
            "proposal received must be from the sending peer"
        );

        let proposal = self
            .validate_signatures(
                &ctx.manager.network_task.epoch_info.read().verifier,
            )?
            .verify_well_formed()?;

        let msg = ConsensusMsg::ProposalMsg(Box::new(proposal));
        ctx.manager
            .network_task
            .consensus_messages_tx
            .push((peer_address, discriminant(&msg)), (peer_address, msg))?;
        Ok(())
    }
}
