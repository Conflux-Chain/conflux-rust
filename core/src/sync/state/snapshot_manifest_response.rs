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
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{any::Any, collections::HashSet};

#[derive(Debug)]
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

impl Encodable for SnapshotManifestResponse {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.request_id)
            .append(&self.checkpoint)
            .append_list(&self.chunk_hashes);
    }
}

impl Decodable for SnapshotManifestResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(SnapshotManifestResponse {
            request_id: rlp.val_at(0)?,
            checkpoint: rlp.val_at(1)?,
            chunk_hashes: rlp.list_at(2)?,
        })
    }
}
