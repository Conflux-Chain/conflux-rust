// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    hotstuff_types::proposal_msg::{ProposalMsg, ProposalUncheckedSignatures},
    primitives::TransactionWithSignature,
    sync::Error,
};
use libra_types::account_address::AccountAddress;

pub type ProposalMsgWithTransactions =
    ProposalMsg<Vec<TransactionWithSignature>>;

impl Handleable for ProposalUncheckedSignatures<Vec<TransactionWithSignature>> {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
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
                &ctx.manager.network_task.epoch_info.read().unwrap().verifier,
            )?
            .verify_well_formed()?;
        debug!("Received proposal {:?}", proposal);
        ctx.manager
            .network_task
            .proposal_tx
            .push(peer_address, proposal)?;
        Ok(())
    }
}
