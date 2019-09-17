// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::RequestId,
    sync::{
        message::{
            metrics::BLOCK_TXN_HANDLE_TIMER, Context, GetBlockTxn, Handleable,
        },
        Error,
    },
};
use cfx_types::H256;
use metrics::MeterTimer;
use primitives::{Block, TransactionWithSignature};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Default, RlpDecodable, RlpEncodable)]
pub struct GetBlockTxnResponse {
    pub request_id: RequestId,
    pub block_hash: H256,
    pub block_txn: Vec<TransactionWithSignature>,
}

impl Handleable for GetBlockTxnResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(BLOCK_TXN_HANDLE_TIMER.as_ref());

        debug!("on_get_blocktxn_response");
        let resp_hash = self.block_hash;
        let req = ctx.match_request(self.request_id)?;
        let req = req.downcast_ref::<GetBlockTxn>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        let mut request_again = false;
        let mut request_from_same_peer = false;
        if resp_hash != req.block_hash {
            warn!("Response blocktxn is not the requested block, req={:?}, resp={:?}", req.block_hash, resp_hash);
            request_again = true;
        } else if ctx.manager.graph.contains_block(&resp_hash) {
            debug!(
                "Get blocktxn, but full block already received, hash={}",
                resp_hash
            );
        } else if let Some(header) =
            ctx.manager.graph.block_header_by_hash(&resp_hash)
        {
            debug!("Process blocktxn hash={:?}", resp_hash);
            let signed_txes = ctx
                .manager
                .graph
                .data_man
                .recover_unsigned_tx_with_order(&self.block_txn)?;
            match ctx.manager.graph.data_man.compact_block_by_hash(&resp_hash) {
                Some(cmpct) => {
                    let mut trans =
                        Vec::with_capacity(cmpct.reconstructed_txes.len());
                    let mut index = 0;
                    for tx in cmpct.reconstructed_txes {
                        match tx {
                            Some(tx) => trans.push(tx),
                            None => {
                                trans.push(signed_txes[index].clone());
                                index += 1;
                            }
                        }
                    }
                    // FIXME Should check if hash matches
                    let block = Block::new(header, trans);
                    debug!(
                        "new block received: block_header={:?}, tx_count={}, block_size={}",
                        block.block_header,
                        block.transactions.len(),
                        block.size(),
                    );
                    let (success, to_relay) = ctx.manager.graph.insert_block(
                        block, true,  // need_to_verify
                        true,  // persistent
                        false, // recover_from_db
                    );

                    let mut blocks = Vec::new();
                    blocks.push(resp_hash);
                    if success {
                        request_again = false;

                        // a transaction from compact block should be
                        // added to received pool
                        ctx.manager
                            .request_manager
                            .append_received_transactions(signed_txes);
                    } else {
                        // If the peer is honest, may still fail due to
                        // tx hash collision
                        request_again = true;
                        request_from_same_peer = true;
                    }
                    if to_relay && !ctx.manager.catch_up_mode() {
                        ctx.manager.relay_blocks(ctx.io, blocks).ok();
                    }
                }
                None => {
                    request_again = true;
                    warn!(
                        "Get blocktxn, but misses compact block, hash={}",
                        resp_hash
                    );
                }
            }
        } else {
            request_again = true;
            warn!("Get blocktxn, but header not received, hash={}", resp_hash);
        }

        if request_again {
            let mut req_hashes = HashSet::new();
            req_hashes.insert(req.block_hash);
            let req_peer = if request_from_same_peer {
                Some(ctx.peer)
            } else {
                None
            };
            ctx.manager.blocks_received(
                ctx.io,
                req_hashes,
                HashSet::new(),
                true,
                req_peer,
            );
        }
        Ok(())
    }
}
