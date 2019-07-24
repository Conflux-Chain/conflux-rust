// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable, Message, MsgId, RequestId},
    Error,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq)]
pub struct GetTerminalBlockHashesResponse {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

impl Handleable for GetTerminalBlockHashesResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_terminal_block_hashes_response, msg=:{:?}", self);

        ctx.match_request(self.request_id())?;

        for hash in self.hashes {
            if !ctx.manager.graph.contains_block_header(&hash) {
                ctx.manager.request_block_headers(
                    ctx.io,
                    Some(ctx.peer),
                    vec![hash],
                );
            }
        }

        Ok(())
    }
}

impl Message for GetTerminalBlockHashesResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_TERMINAL_BLOCK_HASHES_RESPONSE }
}

impl Deref for GetTerminalBlockHashesResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetTerminalBlockHashesResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetTerminalBlockHashesResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetTerminalBlockHashesResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(GetTerminalBlockHashesResponse {
            request_id: rlp.val_at(0)?,
            hashes: rlp.list_at(1)?,
        })
    }
}
