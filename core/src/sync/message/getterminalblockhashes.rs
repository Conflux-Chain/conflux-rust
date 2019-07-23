// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        GetTerminalBlockHashesResponse, Message, MsgId, Request,
        RequestContext, RequestId,
    },
    Error,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq)]
pub struct GetTerminalBlockHashes {
    pub request_id: RequestId,
}

impl Request for GetTerminalBlockHashes {
    fn handle(&self, context: &RequestContext) -> Result<(), Error> {
        let best_info = context.graph.consensus.get_best_info();
        let terminal_hashes = match &best_info.terminal_block_hashes {
            Some(x) => x.clone(),
            None => best_info.bounded_terminal_block_hashes.clone(),
        };
        let response = GetTerminalBlockHashesResponse {
            request_id: self.request_id.clone(),
            hashes: terminal_hashes,
        };
        context.send_response(&response)
    }
}

impl Message for GetTerminalBlockHashes {
    fn msg_id(&self) -> MsgId { MsgId::GET_TERMINAL_BLOCK_HASHES }
}

impl Deref for GetTerminalBlockHashes {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetTerminalBlockHashes {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetTerminalBlockHashes {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(1).append(&self.request_id);
    }
}

impl Decodable for GetTerminalBlockHashes {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(GetTerminalBlockHashes {
            request_id: rlp.val_at(0)?,
        })
    }
}
