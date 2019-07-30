// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, MsgId},
    sync::{
        message::{msgid, Context, Handleable},
        state::SnapshotChunkRequest,
        Error, ErrorKind,
    },
};
use cfx_bytes::Bytes;
use cfx_types::H256;
use keccak_hash::keccak;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{any::Any, collections::HashMap};

#[derive(Debug)]
pub struct SnapshotChunkResponse {
    pub request_id: u64,
    pub chunk: Bytes,
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

        let chunk_hash = keccak(&self.chunk);
        if chunk_hash != request.chunk_hash {
            debug!("Responded snapshot chunk hash mismatch");
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            bail!(ErrorKind::Invalid);
        }

        let kvs = match self.into_kvs() {
            Ok(kvs) => kvs,
            Err(e) => {
                debug!("Failed to decode responded snapshot chunk data to kvs, error = {:?}", e);
                ctx.manager
                    .request_manager
                    .remove_mismatch_request(ctx.io, &message);
                bail!(ErrorKind::Decoder(e));
            }
        };

        ctx.manager
            .state_sync
            .handle_snapshot_chunk_response(ctx, chunk_hash, kvs);

        Ok(())
    }
}

impl SnapshotChunkResponse {
    pub fn new(request_id: u64, kvs: HashMap<H256, Bytes>) -> Self {
        let mut s = RlpStream::new_list(kvs.len());
        for (key, value) in kvs {
            s.begin_list(2).append(&key).append_list(&value);
        }

        SnapshotChunkResponse {
            request_id,
            chunk: s.drain(),
        }
    }

    pub fn into_kvs(self) -> Result<HashMap<H256, Bytes>, DecoderError> {
        let rlp = Rlp::new(self.chunk.as_slice());
        let mut kvs = HashMap::new();

        for i in 0..rlp.item_count()? {
            let kv = rlp.at(i)?;

            if kv.item_count()? != 2 {
                return Err(DecoderError::RlpIncorrectListLen);
            }

            let key = kv.val_at(0)?;
            let value = kv.list_at(1)?;

            if kvs.insert(key, value).is_some() {
                return Err(DecoderError::Custom("duplicated key"));
            }
        }

        Ok(kvs)
    }
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
