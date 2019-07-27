// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable, Message, MsgId},
    state::SnapshotChunkRequest,
    Error, ErrorKind,
};
use cfx_bytes::Bytes;
use keccak_hash::keccak;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Debug)]
pub struct SnapshotChunkResponse {
    pub request_id: u64,
    pub chunk: Bytes,
}

impl Handleable for SnapshotChunkResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let message = ctx.match_request(self.request_id)?;

        let request = message.downcast_ref::<SnapshotChunkRequest>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        let responded_chunk_hash = keccak(&self.chunk);
        if responded_chunk_hash != request.chunk_hash {
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            bail!(ErrorKind::Invalid);
        }

        ctx.manager.state_sync.handle_snapshot_chunk_response(
            ctx,
            responded_chunk_hash,
            self,
        );

        Ok(())
    }
}

impl Message for SnapshotChunkResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_SNAPSHOT_CHUNK_RESPONSE }

    fn msg_name(&self) -> &'static str { "SnapshotChunkResponse" }
}

impl Encodable for SnapshotChunkResponse {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.request_id)
            .append_list(&self.chunk);
    }
}

impl Decodable for SnapshotChunkResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(SnapshotChunkResponse {
            request_id: rlp.val_at(0)?,
            chunk: rlp.list_at(1)?,
        })
    }
}
