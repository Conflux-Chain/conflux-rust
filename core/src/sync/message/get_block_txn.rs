// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::RequestId,
    sync::{
        message::{
            msgid, Context, GetBlockTxnResponse, GetBlocks, Handleable, Key,
            KeyContainer,
        },
        request_manager::{AsAny, Request},
        Error, ErrorKind, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, PartialEq, Default, RlpDecodable, RlpEncodable, Clone)]
pub struct GetBlockTxn {
    pub request_id: RequestId,
    pub block_hash: H256,
    pub index_skips: Vec<usize>,
}

impl AsAny for GetBlockTxn {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Request for GetBlockTxn {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut inflight_blocks = inflight_keys.write(msgid::GET_BLOCKS);
        let mut net_inflight_blocks =
            inflight_keys.write(msgid::NET_INFLIGHT_BLOCKS);
        inflight_blocks.remove(&Key::Hash(self.block_hash.clone()));
        net_inflight_blocks.remove(&Key::Hash(self.block_hash.clone()));
    }

    fn with_inflight(&mut self, _inflight_keys: &KeyContainer) {
        // reuse the inflight key of GetCompactBlocks
    }

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<dyn Request>> {
        Some(Box::new(GetBlocks {
            request_id: 0,
            // request_block_need_public can only be true in catch_up_mode,
            // where GetBlockTxn can not be initiated.
            with_public: false,
            hashes: vec![self.block_hash.clone()],
        }))
    }
}

impl Handleable for GetBlockTxn {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        match ctx.manager.graph.block_by_hash(&self.block_hash) {
            Some(block) => {
                debug!("Process get_blocktxn hash={:?}", block.hash());
                let mut tx_resp = Vec::with_capacity(self.index_skips.len());
                let mut last = 0;
                for index_skip in self.index_skips.iter() {
                    last += *index_skip;
                    if last >= block.transactions.len() {
                        warn!(
                            "Request tx index out of bound, peer={}, hash={}",
                            ctx.node_id,
                            block.hash()
                        );
                        return Err(ErrorKind::InvalidGetBlockTxn(
                            "index out-of-bound".into(),
                        )
                        .into());
                    }
                    tx_resp.push(block.transactions[last].transaction.clone());
                    last += 1;
                }
                let response = GetBlockTxnResponse {
                    request_id: self.request_id,
                    block_hash: self.block_hash,
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
                    request_id: self.request_id,
                    block_hash: H256::default(),
                    block_txn: Vec::new(),
                };

                ctx.send_response(&response)
            }
        }
    }
}
