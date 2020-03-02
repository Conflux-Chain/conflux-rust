// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable};
use crate::{
    alliance_tree_graph::bft::consensus::consensus_types::{
        common::Payload, epoch_retrieval::EpochRetrievalRequest,
    },
    sync::Error,
};
use libra_types::account_address::AccountAddress;
use std::cmp::Ordering;

impl<P: Payload> Handleable<P> for EpochRetrievalRequest {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        debug!("on_epoch_retrieval, msg={:?}", &self);
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        debug!(
            "Received epoch retrieval from peer {}, start epoch {}, end epoch {}",
            peer_address, self.start_epoch, self.end_epoch
        );
        match self.end_epoch.cmp(&ctx.manager.network_task.epoch()) {
            Ordering::Less | Ordering::Equal => ctx
                .manager
                .network_task
                .epoch_retrieval_tx
                .push(peer_address, (self, peer_address))?,
            Ordering::Greater => {
                warn!("Received EpochRetrievalRequest beyond what we have locally");
            }
        }
        Ok(())
    }
}
