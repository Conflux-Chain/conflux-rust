// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::{Message, MsgId, RequestId};
use primitives::{block::CompactBlock, Block};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Default)]
pub struct GetCompactBlocksResponse {
    pub request_id: RequestId,
    pub compact_blocks: Vec<CompactBlock>,
    pub blocks: Vec<Block>,
}

impl Message for GetCompactBlocksResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_CMPCT_BLOCKS_RESPONSE }
}

impl Deref for GetCompactBlocksResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetCompactBlocksResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetCompactBlocksResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append_list(&self.compact_blocks)
            .append_list(&self.blocks);
    }
}

impl Decodable for GetCompactBlocksResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(GetCompactBlocksResponse {
            request_id: rlp.val_at(0)?,
            compact_blocks: rlp.list_at(1)?,
            blocks: rlp.list_at(2)?,
        })
    }
}
