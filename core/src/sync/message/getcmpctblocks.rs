// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        GetCompactBlocksResponse, Message, MsgId, Request, RequestContext,
        RequestId,
    },
    synchronization_protocol_handler::{
        MAX_BLOCKS_TO_SEND, MAX_HEADERS_TO_SEND,
    },
    Error,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Default)]
pub struct GetCompactBlocks {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

impl Request for GetCompactBlocks {
    fn handle(&self, context: &RequestContext) -> Result<(), Error> {
        let mut compact_blocks = Vec::with_capacity(self.hashes.len());
        let mut blocks = Vec::new();

        for hash in self.hashes.iter() {
            if let Some(compact_block) =
                context.graph.data_man.compact_block_by_hash(hash)
            {
                if (compact_blocks.len() as u64) < MAX_HEADERS_TO_SEND {
                    compact_blocks.push(compact_block);
                }
            } else if let Some(block) = context.graph.block_by_hash(hash) {
                debug!("Have complete block but no compact block, return complete block instead");
                if (blocks.len() as u64) < MAX_BLOCKS_TO_SEND {
                    blocks.push(block.as_ref().clone());
                }
            } else {
                warn!(
                    "Peer {} requested non-existent compact block {}",
                    context.peer, hash
                );
            }
        }

        let response = GetCompactBlocksResponse {
            request_id: self.request_id.clone(),
            compact_blocks,
            blocks,
        };

        context.send_response(&response)
    }
}

impl Message for GetCompactBlocks {
    fn msg_id(&self) -> MsgId { MsgId::GET_CMPCT_BLOCKS }
}

impl Deref for GetCompactBlocks {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetCompactBlocks {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetCompactBlocks {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetCompactBlocks {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetCompactBlocks {
            request_id: rlp.val_at(0)?,
            hashes: rlp.list_at(1)?,
        })
    }
}
