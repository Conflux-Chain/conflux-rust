// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    sync::{
        message::{
            Context, GetBlockTxnResponse, GetBlocks, Handleable, KeyContainer,
        },
        request_manager::Request,
        Error, ErrorKind, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, PartialEq, Default, RlpDecodable, RlpEncodable)]
pub struct GetBlockTxn {
    pub request_id: RequestId,
    pub block_hash: H256,
    pub indexes: Vec<usize>,
}

impl Request for GetBlockTxn {
    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &mut KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &mut KeyContainer) {
        // reuse the inflight key of GetCompactBlocks
    }

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<Request>> {
        Some(Box::new(GetBlocks {
            request_id: 0,
            with_public: true,
            hashes: vec![self.block_hash.clone()],
        }))
    }
}

impl Handleable for GetBlockTxn {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        match ctx.manager.graph.block_by_hash(&self.block_hash) {
            Some(block) => {
                debug!("Process get_blocktxn hash={:?}", block.hash());
                let mut tx_resp = Vec::with_capacity(self.indexes.len());
                let mut last = 0;
                for index in self.indexes.iter() {
                    last += *index;
                    if last >= block.transactions.len() {
                        warn!(
                            "Request tx index out of bound, peer={}, hash={}",
                            ctx.peer,
                            block.hash()
                        );
                        return Err(ErrorKind::Invalid.into());
                    }
                    tx_resp.push(block.transactions[last].transaction.clone());
                    last += 1;
                }
                let response = GetBlockTxnResponse {
                    request_id: self.request_id.clone(),
                    block_hash: self.block_hash.clone(),
                    block_txn: tx_resp,
                };

                ctx.send_response(&response)
            }
            None => {
                warn!(
                    "Get blocktxn request of non-existent block, hash={}",
                    self.block_hash
                );

                let response = GetBlockTxnResponse {
                    request_id: self.request_id.clone(),
                    block_hash: H256::default(),
                    block_txn: Vec::new(),
                };

                ctx.send_response(&response)
            }
        }
    }
}
