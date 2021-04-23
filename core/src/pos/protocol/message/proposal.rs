// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    pos::consensus::consensus_types::{
        common::Payload,
        proposal_msg::{ProposalMsg, ProposalUncheckedSignatures},
    },
    sync::Error,
};

use diem_types::{
    account_address::AccountAddress, transaction::SignedTransaction,
};

pub type ProposalMsgWithTransactions = ProposalMsg<Vec<SignedTransaction>>;

impl<P: Payload> Handleable<P> for ProposalUncheckedSignatures<P> {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        debug!("on_proposal, msg={:?}", self.0);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        if self.membership_id() != ctx.manager.network_task.membership_id() {
            ctx.manager
                .network_task
                .different_membership_tx
                .push(peer_address, (self.membership_id(), peer_address))?;
            return Ok(());
        }

        ensure!(
            self.author() == Some(peer_address),
            "proposal received must be from the sending peer"
        );

        let proposal = self
            .validate_signatures(
                &ctx.manager.network_task.membership_info.read().verifier,
            )?
            .verify_well_formed()?;

        ctx.manager
            .network_task
            .proposal_tx
            .push(peer_address, proposal)?;
        Ok(())
    }
}
