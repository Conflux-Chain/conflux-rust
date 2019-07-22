// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::{Message, MsgId, RequestId};
use primitives::BlockHeader;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Default)]
pub struct GetBlockHeadersResponse {
    request_id: RequestId,
    pub headers: Vec<BlockHeader>,
}

impl Message for GetBlockHeadersResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HEADERS_RESPONSE }
}

impl Deref for GetBlockHeadersResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHeadersResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockHeadersResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.headers);
    }
}

impl Decodable for GetBlockHeadersResponse {
    fn decode(rlp: &Rlp) -> Result<GetBlockHeadersResponse, DecoderError> {
        Ok(GetBlockHeadersResponse {
            request_id: rlp.val_at(0)?,
            headers: rlp.list_at(1)?,
        })
    }
}
