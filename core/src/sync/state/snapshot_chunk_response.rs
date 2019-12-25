// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable},
    state::{storage::Chunk, SnapshotChunkRequest},
    Error, ErrorKind,
};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(RlpDecodable, RlpEncodable)]
pub struct SnapshotChunkResponse {
    pub request_id: u64,
    pub chunk: Chunk,
}

impl Handleable for SnapshotChunkResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let message = ctx.match_request(self.request_id)?;

        let request = message.downcast_ref::<SnapshotChunkRequest>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        if let Err(e) = self.chunk.validate(&request.chunk_key) {
            debug!("failed to validate the snapshot chunk, error = {:?}", e);
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            bail!(ErrorKind::Invalid);
        }

        ctx.manager.state_sync.handle_snapshot_chunk_response(
            ctx,
            request.chunk_key.clone(),
            self.chunk,
        );

        Ok(())
    }
}
