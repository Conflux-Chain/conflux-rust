// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        Context, GetBlockHeadersResponse, Handleable, Message, MsgId, RequestId,
    },
    synchronization_protocol_handler::MAX_HEADERS_TO_SEND,
    Error,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    cmp::min,
    ops::{Deref, DerefMut},
};

#[derive(Debug, PartialEq, Clone)]
pub struct GetBlockHeaderChain {
    pub request_id: RequestId,
    pub hash: H256,
    pub max_blocks: u64,
}

impl Handleable for GetBlockHeaderChain {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let mut hash = self.hash;
        let mut block_headers_resp = GetBlockHeadersResponse::default();
        block_headers_resp.set_request_id(self.request_id());

        for _ in 0..min(MAX_HEADERS_TO_SEND, self.max_blocks) {
            let header = ctx.manager.graph.block_header_by_hash(&hash);
            if header.is_none() {
                break;
            }
            let header = header.unwrap();
            block_headers_resp.headers.push(header.clone());
            if hash == ctx.manager.graph.genesis_hash() {
                break;
            }
            hash = header.parent_hash().clone();
        }

        debug!(
            "Returned {:?} block headers to peer {:?}",
            block_headers_resp.headers.len(),
            ctx.peer
        );

        ctx.send_response(&block_headers_resp)
    }
}

impl Message for GetBlockHeaderChain {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HEADER_CHAIN }
}

impl Deref for GetBlockHeaderChain {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHeaderChain {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockHeaderChain {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&self.hash)
            .append(&self.max_blocks);
    }
}

impl Decodable for GetBlockHeaderChain {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockHeaderChain {
            request_id: rlp.val_at(0)?,
            hash: rlp.val_at(1)?,
            max_blocks: rlp.val_at(2)?,
        })
    }
}
