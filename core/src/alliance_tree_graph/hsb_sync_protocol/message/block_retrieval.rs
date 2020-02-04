// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::sync_protocol::{Context, Handleable, RpcResponse};
use crate::{
    alliance_tree_graph::bft::consensus::{
        chained_bft::network::IncomingBlockRetrievalRequest,
        consensus_types::{
            block_retrieval::BlockRetrievalRequest, common::Payload,
        },
    },
    message::{Message, RequestId},
    sync::{
        message::{Key, KeyContainer},
        request_manager::{AsAny, Request},
        Error, ErrorKind, ProtocolConfiguration,
    },
};
use bytes::Bytes;
use cfx_types::H256;
use futures::channel::oneshot;
use libra_types::account_address::AccountAddress;
use primitives::TransactionWithSignature;
use serde::{Deserialize, Serialize};
use std::{any::Any, sync::Arc, time::Duration};

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
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration { self.timeout }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());
        let key = H256::from_slice(self.request.block_id().to_vec().as_slice());
        inflight_keys.remove(&Key::Hash(key));
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let inflight_keys = inflight_keys.write(self.msg_id());
        let key = H256::from_slice(self.request.block_id().to_vec().as_slice());
        if inflight_keys.contains(&Key::Hash(key)) {
            self.is_empty = true;
        }
    }

    fn is_empty(&self) -> bool { self.is_empty }

    fn resend(&self) -> Option<Box<dyn Request>> { None }

    fn notify_empty(&mut self) {
        let res_tx = self.response_tx.take();
        if let Some(tx) = res_tx {
            tx.send(Err(ErrorKind::RpcCancelledByEmpty.into()));
        }
    }

    fn notify_timeout(&mut self) {
        let res_tx = self.response_tx.take();
        if let Some(tx) = res_tx {
            tx.send(Err(ErrorKind::RpcTimeout.into()));
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
        debug!("Received block retrieval request {}", req);
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
