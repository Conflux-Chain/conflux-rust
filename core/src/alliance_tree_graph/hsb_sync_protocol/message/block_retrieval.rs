// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable, RpcResponse};
use crate::{
    alliance_tree_graph::{
        bft::consensus::{
            chained_bft::network::IncomingBlockRetrievalRequest,
            consensus_types::{
                block_retrieval::BlockRetrievalRequest, common::Payload,
            },
        },
        hsb_sync_protocol::request_manager::{AsAny, Request},
    },
    message::RequestId,
    sync::{Error, ProtocolConfiguration},
};
use futures::channel::oneshot;
use libra_types::account_address::AccountAddress;
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
            tx.send(Err(error))
                .expect("send ResponseTX EmptyError should succeed");
        }
    }

    fn set_response_notification(
        &mut self, res_tx: oneshot::Sender<Result<Box<dyn RpcResponse>, Error>>,
    ) {
        self.response_tx = Some(res_tx);
    }
}

impl<P: Payload> Handleable<P> for BlockRetrievalRpcRequest {
    fn handle(self, ctx: &Context<P>) -> Result<(), Error> {
        let peer_address = AccountAddress::new(ctx.peer_hash.into());
        let req = self.request;
        debug!(
            "Received block retrieval request [block id: {}, request_id: {}]",
            req.block_id(),
            self.request_id
        );
        let req_with_callback = IncomingBlockRetrievalRequest {
            req,
            peer_id: ctx.peer,
            request_id: self.request_id,
        };
        ctx.manager
            .network_task
            .block_request_tx
            .push(peer_address, req_with_callback)?;
        Ok(())
    }
}
