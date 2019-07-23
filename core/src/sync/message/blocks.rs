// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::{Message, MsgId, RequestId};
use primitives::Block;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Default)]
pub struct GetBlocksResponse {
    pub request_id: RequestId,
    pub blocks: Vec<Block>,
}

impl Message for GetBlocksResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCKS_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }
}

impl Deref for GetBlocksResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlocksResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlocksResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.blocks);
    }
}

impl Decodable for GetBlocksResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(GetBlocksResponse {
            request_id: rlp.val_at(0)?,
            blocks: rlp.list_at(1)?,
        })
    }
}

//////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Default)]
pub struct GetBlocksWithPublicResponse {
    pub request_id: RequestId,
    pub blocks: Vec<Block>,
}

impl Message for GetBlocksWithPublicResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCKS_WITH_PUBLIC_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }
}

impl Deref for GetBlocksWithPublicResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlocksWithPublicResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlocksWithPublicResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .begin_list(self.blocks.len());

        for block in self.blocks.iter() {
            stream.begin_list(2).append(&block.block_header);
            stream.begin_list(block.transactions.len());
            for tx in &block.transactions {
                stream.append(tx.as_ref());
            }
        }
    }
}

impl Decodable for GetBlocksWithPublicResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let request_id = rlp.val_at(0)?;
        let rlp_blocks = rlp.at(1)?;
        let mut blocks = Vec::new();

        for i in 0..rlp_blocks.item_count()? {
            let rlp_block = rlp_blocks.at(i)?;
            let block = Block::decode_with_tx_public(&rlp_block)
                .expect("Wrong block rlp format!");
            blocks.push(block);
        }

        Ok(GetBlocksWithPublicResponse { request_id, blocks })
    }
}
