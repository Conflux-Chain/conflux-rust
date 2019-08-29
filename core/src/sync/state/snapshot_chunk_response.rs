// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, MsgId},
    storage::Chunk,
    sync::{
        message::{msgid, Context, Handleable},
        state::SnapshotChunkRequest,
        Error, ErrorKind,
    },
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::any::Any;

#[derive(RlpDecodable, RlpEncodable)]
pub struct SnapshotChunkResponse {
    pub request_id: u64,
    pub chunk: Chunk,
}

build_msg_impl! { SnapshotChunkResponse, msgid::GET_SNAPSHOT_CHUNK_RESPONSE, "SnapshotChunkResponse" }

impl Handleable for SnapshotChunkResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let message = ctx.match_request(self.request_id)?;

        let request = message.downcast_ref::<SnapshotChunkRequest>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        let root = ctx.must_get_state_root(&request.checkpoint);

        if let Err(e) =
            self.chunk.validate(&request.chunk_key, &root.snapshot_root)
        {
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
