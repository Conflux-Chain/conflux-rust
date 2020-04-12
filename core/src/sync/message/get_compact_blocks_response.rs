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
        let delay = req.delay;
        let mut to_relay_blocks = Vec::new();
        let mut received_reconstructed_blocks = Vec::new();

        let mut requested_except_inflight_txn: HashSet<H256> = req
            .downcast_ref::<GetCompactBlocks>(
                ctx.io,
                &ctx.manager.request_manager,
            )?
            .hashes
            .iter()
            .cloned()
            .collect();

        for mut cmpct in self.compact_blocks {
            let hash = cmpct.hash();

            if !requested_except_inflight_txn.contains(&hash) {
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

            debug!("Cmpct block Processing, hash={:?}", hash);

            let missing = {
                let _timer =
                    MeterTimer::time_func(CMPCT_BLOCK_RECOVER_TIMER.as_ref());
                ctx.manager
                    .graph
                    .data_man
                    .find_missing_tx_indices_encoded(&mut cmpct)
            };
            if !missing.is_empty() {
                debug!("Request {} missing tx in {}", missing.len(), hash);
                ctx.manager.graph.data_man.insert_compact_block(cmpct);
                ctx.manager.request_manager.request_blocktxn(
                    ctx.io,
                    ctx.node_id.clone(),
                    hash,
                    missing,
                    None,
                );
                // The block remains inflight.
                requested_except_inflight_txn.remove(&hash);
            } else {
                let trans = cmpct
                    .reconstructed_txns
                    .into_iter()
                    .map(|tx| tx.unwrap())
                    .collect();
                let block = Block::new(header, trans);
                debug!("transaction received by block: ratio=0");
                debug!(
                    "new block received: block_header={:?}, tx_count={}, block_size={}",
                    block.block_header,
                    block.transactions.len(),
                    block.size(),
                );
                let insert_result = ctx.manager.graph.insert_block(
                    block, true,  // need_to_verify
                    true,  // persistent
                    false, // recover_from_db
                );

                if !insert_result.request_again() {
                    received_reconstructed_blocks.push(hash);
                }
                if insert_result.should_relay() {
                    to_relay_blocks.push(hash);
                }
            }
        }

        // We cannot just mark `self.blocks` as completed here because they
        // might be invalid.
        let mut received_full_blocks = HashSet::new();
        let mut compact_block_responded_requests =
            requested_except_inflight_txn;
        for block in &self.blocks {
            received_full_blocks.insert(block.hash());
            compact_block_responded_requests.remove(&block.hash());
        }

        ctx.manager.blocks_received(
            ctx.io,
            compact_block_responded_requests.clone(),
            received_reconstructed_blocks.iter().cloned().collect(),
            true,
            Some(ctx.node_id.clone()),
            delay,
        );

        ctx.manager.recover_public_queue.dispatch(
            ctx.io,
            RecoverPublicTask::new(
                self.blocks,
                received_full_blocks,
                ctx.node_id.clone(),
                true,
                delay,
            ),
        );

        // Broadcast completed block_header_ready blocks
        ctx.manager.relay_blocks(ctx.io, to_relay_blocks)
    }
}
