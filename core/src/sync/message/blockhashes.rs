// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        Context, GetBlockHashesByEpoch, Handleable, Message, MsgId, RequestId,
    },
    Error,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq)]
pub struct GetBlockHashesResponse {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

impl Handleable for GetBlockHashesResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_block_hashes_response, msg={:?}", self);

        let req = ctx.match_request(self.request_id())?;
        let epoch_req = req.downcast_general::<GetBlockHashesByEpoch>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        // assume received everything
        // FIXME: peer should signal error?
        let req = epoch_req.epochs.clone().into_iter().collect();
        let rec = epoch_req.epochs.clone().into_iter().collect();
        ctx.manager
            .request_manager
            .epochs_received(ctx.io, req, rec);

        // request missing headers
        let missing_headers = self
            .hashes
            .iter()
            .filter(|h| !ctx.manager.graph.contains_block_header(&h))
            .cloned()
            .collect();

        // NOTE: this is to make sure no section of the DAG is skipped
        // e.g. if the request for epoch 4 is lost or the reply is in-
        // correct, the request for epoch 5 should recursively request
        // all dependent blocks (see on_block_headers_response)

        // self.request_manager.request_block_headers(
        //     io,
        //     Some(peer),
        //     missing_headers,
        // );

        ctx.manager.request_block_headers(
            ctx.io,
            Some(ctx.peer),
            missing_headers,
        );

        // TODO: handle empty response

        // try requesting some more epochs
        ctx.manager.start_sync(ctx.io);

        Ok(())
    }
}

impl Message for GetBlockHashesResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HASHES_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetBlockHashesResponse" }
}

impl Deref for GetBlockHashesResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHashesResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
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
    fn decode(rlp: &Rlp) -> Result<GetBlockHashesResponse, DecoderError> {
        Ok(GetBlockHashesResponse {
            request_id: rlp.val_at(0)?,
            hashes: rlp.list_at(1)?,
        })
    }
}
