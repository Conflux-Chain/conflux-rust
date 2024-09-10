// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    message::RequestId,
    pos::protocol::{
        message::block_retrieval::BlockRetrievalRpcRequest,
        request_manager::AsAny,
        sync_protocol::{Context, Handleable, RpcResponse},
    },
    sync::Error,
};
use consensus_types::block_retrieval::BlockRetrievalResponse;
use serde::{Deserialize, Serialize};
use std::any::Any;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockRetrievalRpcResponse {
    pub request_id: RequestId,
    #[serde(bound(deserialize = "BlockRetrievalResponse: Deserialize<'de>"))]
    pub response: BlockRetrievalResponse,
}

impl RpcResponse for BlockRetrievalRpcResponse {}

impl AsAny for BlockRetrievalRpcResponse {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Handleable for BlockRetrievalRpcResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let mut req = ctx.match_request(self.request_id)?;
        // FIXME: There is a potential issue if downcast error happens.
        match req.downcast_mut::<BlockRetrievalRpcRequest>(
            ctx.io,
            &ctx.manager.request_manager,
        ) {
            Ok(req) => {
                let res_tx = req.response_tx.take();
                if let Some(tx) = res_tx {
                    if let Err(e) = tx.send(Ok(Box::new(self))) {
                        bail!(Error::UnexpectedMessage(
                            format!("{:?}", e).into()
                        ))
                    }
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
        Ok(())
    }
}
