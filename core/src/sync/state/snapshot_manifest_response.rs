// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, MsgId},
    storage::RangedManifest,
    sync::{
        message::{msgid, Context, Handleable},
        state::SnapshotManifestRequest,
        Error, ErrorKind,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::any::Any;

#[derive(RlpDecodable, RlpEncodable)]
pub struct SnapshotManifestResponse {
    pub request_id: u64,
    pub checkpoint: H256,
    pub manifest: RangedManifest,
    pub state_blame_vec: Vec<H256>,
    pub receipt_blame_vec: Vec<H256>,
    pub bloom_blame_vec: Vec<H256>,
}

build_msg_impl! { SnapshotManifestResponse, msgid::GET_SNAPSHOT_MANIFEST_RESPONSE, "SnapshotManifestResponse" }

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
            .handle_snapshot_manifest_response(ctx, self);

        Ok(())
    }
}

impl SnapshotManifestResponse {
    fn validate(
        &self, ctx: &Context, request: &SnapshotManifestRequest,
    ) -> Result<(), Error> {
        if self.checkpoint != request.checkpoint {
            debug!(
                "Responded snapshot manifest checkpoint mismatch, requested = {:?}, responded = {:?}",
                request.checkpoint,
                self.checkpoint,
            );
            bail!(ErrorKind::Invalid);
        }

        let root = ctx.must_get_state_root(&self.checkpoint);

        if let Err(e) = self
            .manifest
            .validate(&root.snapshot_root, &request.start_chunk)
        {
            debug!("failed to validate snapshot manifest, error = {:?}", e);
            bail!(ErrorKind::Invalid);
        }

        if request.trusted_blame_block.is_some()
            && self.state_blame_vec.is_empty()
        {
            debug!("Responded snapshot manifest has empty blame states");
            bail!(ErrorKind::Invalid);
        }

        if self.state_blame_vec.len() != self.receipt_blame_vec.len()
            || self.state_blame_vec.len() != self.bloom_blame_vec.len()
        {
            debug!("Responded snapshot manifest has mismatch blame states/receipts/blooms");
            bail!(ErrorKind::Invalid);
        }

        Ok(())
    }
}
