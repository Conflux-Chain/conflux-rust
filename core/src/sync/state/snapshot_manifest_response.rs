// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, MsgId},
    sync::{
        message::{msgid, Context, Handleable},
        state::SnapshotManifestRequest,
        Error, ErrorKind,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, collections::HashSet};

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct SnapshotManifestResponse {
    pub request_id: u64,
    pub checkpoint: H256,
    pub chunk_hashes: Vec<H256>,
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

        if request.checkpoint != self.checkpoint {
            debug!(
                "Responded snapshot manifest checkpoint mismatch, requested = {:?}, responded = {:?}",
                request.checkpoint,
                self.checkpoint,
            );
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            bail!(ErrorKind::Invalid);
        }

        let distinct_chunks: HashSet<H256> =
            self.chunk_hashes.iter().cloned().collect();
        if distinct_chunks.len() != self.chunk_hashes.len() {
            debug!("Responded snapshot manifest has duplicated chunks");
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            bail!(ErrorKind::Invalid);
        }

        ctx.manager
            .state_sync
            .handle_snapshot_manifest_response(ctx, self);

        Ok(())
    }
}
