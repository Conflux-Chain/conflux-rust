// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::{Message, MsgId, RequestId};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Clone)]
pub struct GetBlockHeaderChain {
    pub request_id: RequestId,
    pub hash: H256,
    pub max_blocks: u64,
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
