// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::RequestId,
    sync::{
        message::{Context, GetBlockHashesByEpoch, Handleable},
        Error,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct GetBlockHashesResponse {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

impl Handleable for GetBlockHashesResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_block_hashes_response, msg={:?}", self);

        let req = ctx.match_request(self.request_id)?;
        let epoch_req = req.downcast_ref::<GetBlockHashesByEpoch>(
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
