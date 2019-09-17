// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::RequestId,
    sync::{
        message::{
            metrics::{CMPCT_BLOCK_HANDLE_TIMER, CMPCT_BLOCK_RECOVER_TIMER},
            Context, GetCompactBlocks, Handleable,
        },
        synchronization_protocol_handler::RecoverPublicTask,
        Error,
    },
};
use cfx_types::H256;
use metrics::MeterTimer;
use primitives::{block::CompactBlock, Block};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Default, RlpDecodable, RlpEncodable)]
pub struct GetCompactBlocksResponse {
    pub request_id: RequestId,
    pub compact_blocks: Vec<CompactBlock>,
    pub blocks: Vec<Block>,
}

impl Handleable for GetCompactBlocksResponse {
    /// For requested compact block,
    ///     if a compact block is returned
    ///         if it is recoverable and reconstructed block is valid,
    ///             it's removed from requested_manager
    ///         if it is recoverable and reconstructed block is not valid,
    ///             it's sent to requested_manager as requested but not received
    /// block, and the full block
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(CMPCT_BLOCK_HANDLE_TIMER.as_ref());

        debug!(
            "on_get_compact_blocks_response request_id={} compact={} block={}",
            self.request_id,
            self.compact_blocks.len(),
            self.blocks.len()
        );

        let req = ctx.match_request(self.request_id)?;
        let mut failed_blocks = HashSet::new();
        let mut completed_blocks = Vec::new();

        let mut requested_blocks: HashSet<H256> = req
            .downcast_ref::<GetCompactBlocks>(
                ctx.io,
                &ctx.manager.request_manager,
                true,
            )?
            .hashes
            .iter()
            .cloned()
            .collect();

        for mut cmpct in self.compact_blocks {
            let hash = cmpct.hash();

            if !requested_blocks.remove(&hash) {
                warn!("Response has not requested compact block {:?}", hash);
                continue;
            }

            if ctx.manager.graph.contains_block(&hash) {
                debug!(
                    "Get cmpct block, but full block already received, hash={}",
                    hash
                );
                continue;
            }

            let header = match ctx.manager.graph.block_header_by_hash(&hash) {
                Some(header) => header,
                None => {
                    warn!(
                        "Get cmpct block, but header not received, hash={}",
                        hash
                    );
                    continue;
                }
            };

            if ctx.manager.graph.data_man.contains_compact_block(&hash) {
                debug!("Cmpct block already received, hash={}", hash);
                continue;
            }

            debug!("Cmpct block Processing, hash={}", hash);

            let missing = {
                let _timer =
                    MeterTimer::time_func(CMPCT_BLOCK_RECOVER_TIMER.as_ref());
                ctx.manager.graph.data_man.build_partial(&mut cmpct)
            };
            if !missing.is_empty() {
                debug!("Request {} missing tx in {}", missing.len(), hash);
                ctx.manager.graph.data_man.insert_compact_block(cmpct);
                ctx.manager
                    .request_manager
                    .request_blocktxn(ctx.io, ctx.peer, hash, missing);
            } else {
                let trans = cmpct
                    .reconstructed_txes
                    .into_iter()
                    .map(|tx| tx.unwrap())
                    .collect();
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

                // May fail due to transactions hash collision
                if !success {
                    failed_blocks.insert(hash);
                }
                if to_relay {
                    completed_blocks.push(hash);
                }
            }
        }

        ctx.manager.blocks_received(
            ctx.io,
            failed_blocks,
            completed_blocks.iter().cloned().collect(),
            true,
            Some(ctx.peer),
        );

        ctx.manager.recover_public_queue.dispatch(
            ctx.io,
            RecoverPublicTask::new(
                self.blocks,
                requested_blocks,
                ctx.peer,
                true,
            ),
        );

        // Broadcast completed block_header_ready blocks
        ctx.manager.relay_blocks(ctx.io, completed_blocks)
    }
}
