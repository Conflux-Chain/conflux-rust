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

#[derive(Debug, PartialEq, Default, RlpEncodable, RlpDecodable)]
pub struct GetBlockTxnResponse {
    pub request_id: RequestId,
    pub block_hash: H256,
    pub block_txn: Vec<TransactionWithSignature>,
}

impl Handleable for GetBlockTxnResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(BLOCK_TXN_HANDLE_TIMER.as_ref());

        debug!("on_get_blocktxn_response, hash={:?}", self.block_hash);

        let resp_hash = self.block_hash;
        let req = ctx.match_request(self.request_id)?;
        let delay = req.delay;
        let req = req.downcast_ref::<GetBlockTxn>(
            ctx.io,
            &ctx.manager.request_manager,
        )?;

        let mut request_from_same_peer = false;
        // There can be at most one success block in this set.
        let mut received_blocks = HashSet::new();
        if resp_hash != req.block_hash {
            warn!("Response blocktxn is not the requested block, req={:?}, resp={:?}", req.block_hash, resp_hash);
        } else if ctx.manager.graph.contains_block(&resp_hash) {
            debug!(
                "Get blocktxn, but full block already received, hash={}",
                resp_hash
            );
            received_blocks.insert(resp_hash);
        } else if let Some(header) =
            ctx.manager.graph.block_header_by_hash(&resp_hash)
        {
            debug!("Process blocktxn hash={:?}", resp_hash);

            let signed_txns = ctx
                .manager
                .graph
                .data_man
                .recover_unsigned_tx_with_order(&self.block_txn)?;
            match ctx.manager.graph.data_man.compact_block_by_hash(&resp_hash) {
                Some(cmpct) => {
                    // FIXME: Invalid blocktxn responses after match_request
                    // must still clean up block inflight
                    // state and resend the request. Otherwise the
                    // corresponding request will never be satisfied.
                    let trans = fill_missing_slots(
                        cmpct.reconstructed_txns,
                        &signed_txns,
                    )
                    .ok_or(Error::UnexpectedResponse)?;
                    // FIXME Should check if hash matches
                    let block = Block::new(header, trans);
                    debug!(
                        "transaction received by block: ratio={:?}",
                        self.block_txn.len() as f64
                            / block.transactions.len() as f64
                    );
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
                        received_blocks.insert(resp_hash);
                    }
                    if insert_result.is_valid() {
                        //insert signed transaction to tx pool
                        let (signed_txns, _) = ctx
                            .manager
                            .graph
                            .consensus
                            .tx_pool()
                            .insert_new_signed_transactions(signed_txns);
                        // a transaction from compact block should be
                        // added to received pool
                        ctx.manager
                            .request_manager
                            .append_received_transactions(signed_txns);
                    }
                    if insert_result.should_relay()
                        && !ctx.manager.catch_up_mode()
                    {
                        ctx.manager.relay_blocks(ctx.io, vec![resp_hash]).ok();
                    }
                    if insert_result.request_again() {
                        request_from_same_peer = true;
                    }
                }
                None => {
                    warn!(
                        "Get blocktxn, but misses compact block, hash={}",
                        resp_hash
                    );
                }
            }
        } else {
            warn!("Get blocktxn, but header not received, hash={}", resp_hash);
        }

        let peer = if request_from_same_peer {
            Some(ctx.node_id.clone())
        } else {
            None
        };
        ctx.manager.blocks_received(
            ctx.io,
            vec![req.block_hash].into_iter().collect(),
            received_blocks,
            true,
            peer,
            delay,
            None, /* preferred_node_type_for_block_request */
        );
        Ok(())
    }
}

/// Fill missing slots with candidates in order.
///
/// `items` contains already-known values as `Some` and holes as `None`.
/// `candidates` must match those holes exactly: too few candidates would leave
/// missing values unresolved, while too many candidates means the response does
/// not match the requested layout. Returns `None` for either mismatch.
fn fill_missing_slots<'a, T: Clone>(
    items: Vec<Option<T>>, candidates: &[T],
) -> Option<Vec<T>> {
    let mut candidates_iter = candidates.iter();
    let result: Vec<T> = items
        .into_iter()
        .map(|slot| slot.or_else(|| candidates_iter.next().cloned()))
        // Any single None that can't be filled fails the entire reconstruction.
        .collect::<Option<Vec<T>>>()?;

    // Extra candidates means the response doesn't match the compact layout.
    if candidates_iter.next().is_some() {
        return None;
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_too_few_candidates() {
        assert!(fill_missing_slots(vec![None::<u8>], &[]).is_none());
    }

    #[test]
    fn reject_too_many_candidates() {
        assert!(fill_missing_slots(vec![Some(1u8)], &[2]).is_none());
    }

    #[test]
    fn fill_missing_slots_in_order() {
        assert_eq!(
            fill_missing_slots(vec![Some(1u8), None, Some(3)], &[2]).unwrap(),
            vec![1, 2, 3],
        );
    }
}
