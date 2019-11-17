// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockExecutionResult,
    sync::{
        message::{Context, Handleable},
        state::{delta::RangedManifest, SnapshotManifestRequest},
        Error, ErrorKind,
    },
};
use cfx_types::H256;
use primitives::StateRoot;
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(RlpDecodable, RlpEncodable)]
pub struct SnapshotManifestResponse {
    pub request_id: u64,
    pub checkpoint: H256,
    pub manifest: RangedManifest,
    // We have state_root_vec for two reasons: 1) construct
    // state_root_blame_vec; 2) construct state_root_with_aux_vec.
    //
    // We need state_root_with_aux_vec because we mark the state of
    // a few epochs as executed, but in the local db we also save the
    // StateRootAuxInfo, which isn't verifiable, and should be computed
    // from the consensus graph. Lucky enough that the intermediate_epoch_id
    // for the snapshot block is itself. So is it for a few following
    // epochs.
    pub state_root_vec: Vec<StateRoot>,
    pub receipt_blame_vec: Vec<H256>,
    pub bloom_blame_vec: Vec<H256>,
    pub block_receipts: Vec<BlockExecutionResult>,
}

impl Handleable for SnapshotManifestResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let message = ctx.match_request(self.request_id)?;

        let request = message.downcast_ref::<SnapshotManifestRequest>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        if let Err(e) = self.validate(ctx, request) {
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            return Err(e);
        }

        ctx.manager
            .state_sync
            .handle_snapshot_manifest_response(ctx, self, &request);

        Ok(())
    }
}

impl SnapshotManifestResponse {
    fn validate(
        &self, _: &Context, request: &SnapshotManifestRequest,
    ) -> Result<(), Error> {
        if self.checkpoint != request.checkpoint {
            debug!(
                "Responded snapshot manifest checkpoint mismatch, requested = {:?}, responded = {:?}",
                request.checkpoint,
                self.checkpoint,
            );
            bail!(ErrorKind::Invalid);
        }

        if request.is_initial_request() && self.state_root_vec.is_empty() {
            debug!("Responded snapshot manifest has empty blame states");
            bail!(ErrorKind::Invalid);
        }

        if self.state_root_vec.len() != self.receipt_blame_vec.len()
            || self.state_root_vec.len() != self.bloom_blame_vec.len()
        {
            debug!("Responded snapshot manifest has mismatch blame states/receipts/blooms");
            bail!(ErrorKind::Invalid);
        }

        if self.block_receipts.is_empty() {
            debug!("Responded epoch_receipts has mismatch length");
            bail!(ErrorKind::Invalid);
        }

        Ok(())
    }
}
