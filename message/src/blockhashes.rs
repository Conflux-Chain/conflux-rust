// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};
use Message;
use MsgId;
use RequestId;

#[derive(Debug, PartialEq)]
pub struct GetBlockHashesResponse {
    request_id: RequestId,
    hashes: Vec<H256>,
}

impl Message for GetBlockHashesResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HASHES_RESPONSE }
}

impl Deref for GetBlockHashesResponse {
    type Target = RequestID;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHashesResponse {
    fn deref_mut(&mut self) -> &mut RequestID { &mut self.request_id }
}

impl Encodable for GetBlockHashesResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetBlockHashesResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(GetBlockHashesResponse {
            request_id: rlp.val_at(0)?,
            hashes: rlp.list_at(1)?,
        })
    }
}
