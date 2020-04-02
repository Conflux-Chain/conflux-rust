// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{GetMaybeRequestId, Message, MsgId},
    sync::{
        message::{msgid, Context, Handleable},
        state::{storage::Chunk, SnapshotChunkRequest},
        Error, ErrorKind,
    },
};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};

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
        )?;

        if let Err(e) = self.chunk.validate(&request.chunk_key) {
            debug!("failed to validate the snapshot chunk, error = {:?}", e);
            // TODO: is the "other" peer guaranteed to have the chunk?
            // How did we pass the peer list?
            ctx.manager
                .request_manager
                .resend_request_to_another_peer(ctx.io, &message);
            bail!(ErrorKind::InvalidSnapshotChunk(e.description().into()));
        }

        ctx.manager.state_sync.handle_snapshot_chunk_response(
            ctx,
            request.chunk_key.clone(),
            self.chunk,
        )?;

        Ok(())
    }
}
