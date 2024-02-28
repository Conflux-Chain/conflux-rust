// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

use crate::{
    message::{Message, RequestId},
    pos::{
        consensus::network::IncomingBlockRetrievalRequest,
        protocol::{
            message::block_retrieval_response::BlockRetrievalRpcResponse,
            request_manager::{AsAny, Request},
            sync_protocol::{Context, Handleable, RpcResponse},
        },
    },
    sync::{Error, ProtocolConfiguration},
};
use channel::diem_channel::ElementStatus;
use consensus_types::block_retrieval::{
    BlockRetrievalRequest, BlockRetrievalResponse, BlockRetrievalStatus,
};
use diem_logger::prelude::diem_debug;
use futures::channel::oneshot;
use serde::{Deserialize, Serialize};
use std::{any::Any, time::Duration};

//#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize, Debug)]
pub struct BlockRetrievalRpcRequest {
    pub request_id: RequestId,
    pub request: BlockRetrievalRequest,
    #[serde(skip)]
    pub is_empty: bool,
    #[serde(skip)]
    pub response_tx:
        Option<oneshot::Sender<Result<Box<dyn RpcResponse>, Error>>>,
    #[serde(skip)]
    pub timeout: Duration,
}

impl AsAny for BlockRetrievalRpcRequest {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Request for BlockRetrievalRpcRequest {
    fn timeout(&self, _conf: &ProtocolConfiguration) -> Duration {
        self.timeout
    }

    fn notify_error(&mut self, error: Error) {
        let res_tx = self.response_tx.take();
        if let Some(tx) = res_tx {
            if let Err(e) = tx.send(Err(error)) {
                // receiver dropped, we can just drop this error.
                debug!("send ResponseTX EmptyError: e={:?}", e);
            }
        }
    }

    fn set_response_notification(
        &mut self, res_tx: oneshot::Sender<Result<Box<dyn RpcResponse>, Error>>,
    ) {
        self.response_tx = Some(res_tx);
    }
}

impl Handleable for BlockRetrievalRpcRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer_address = ctx.get_peer_account_address()?;
        let req = self.request;
        diem_debug!(
            "Received block retrieval request [block id: {}, request_id: {}]",
            req.block_id(),
            self.request_id
        );
        let req_with_callback = IncomingBlockRetrievalRequest {
            req,
            peer_id: ctx.peer,
            request_id: self.request_id,
        };
        // We only keep one pending retrieval with a LIFO style, so if an old
        // request is dropped, we respond with an empty response so the
        // sender does not need to wait for timeout.
        let (status_tx, mut status_rx) = oneshot::channel();
        ctx.manager
            .consensus_network_task
            .block_retrieval_tx
            .push_with_feedback(
                peer_address,
                req_with_callback,
                Some(status_tx),
            )?;
        if let Ok(Some(ElementStatus::Dropped(request))) = status_rx.try_recv()
        {
            let response = BlockRetrievalRpcResponse {
                request_id: request.request_id,
                response: BlockRetrievalResponse::new(
                    BlockRetrievalStatus::IdNotFound,
                    vec![],
                ),
            };
            response.send(ctx.io, &ctx.peer)?;
        }
        Ok(())
    }
}
