// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::{Message, MsgId, RequestId};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq)]
pub struct GetBlockBodies {
    request_id: RequestId,
    pub with_public: bool,
    pub hashes: Vec<H256>,
}

impl Message for GetBlockBodies {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_BODIES }
}

impl Deref for GetBlockBodies {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockBodies {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockBodies {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&self.with_public)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetBlockBodies {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockBodies {
            request_id: rlp.val_at(0)?,
            with_public: rlp.val_at(1)?,
            hashes: rlp.list_at(2)?,
        })
    }
}
