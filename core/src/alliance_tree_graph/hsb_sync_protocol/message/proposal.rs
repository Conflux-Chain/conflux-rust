// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    alliance_tree_graph::bft::consensus::consensus_types::{
        common::Payload,
        proposal_msg::{ProposalMsg, ProposalUncheckedSignatures},
    },
    sync::Error,
};

use libra_types::{
    account_address::AccountAddress, transaction::SignedTransaction,
};

pub type ProposalMsgWithTransactions = ProposalMsg<Vec<SignedTransaction>>;

impl<P: Payload> Handleable<P> for ProposalUncheckedSignatures<P> {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        debug!("on_proposal, msg={:?}", self.0);

        let peer_address = AccountAddress::new(ctx.peer_hash.into());

        if self.epoch() != ctx.manager.network_task.epoch() {
            ctx.manager
                .network_task
                .different_epoch_tx
                .push(peer_address, (self.epoch(), peer_address))?;
            return Ok(());
        }

        ensure!(
            self.author() == Some(peer_address),
            "proposal received must be from the sending peer"
        );

        let proposal = self
            .validate_signatures(
                &ctx.manager.network_task.epoch_info.read().verifier,
            )?
            .verify_well_formed()?;

        ctx.manager
            .network_task
            .proposal_tx
            .push(peer_address, proposal)?;
        Ok(())
    }
}
