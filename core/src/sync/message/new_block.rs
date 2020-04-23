// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable},
    Error, ErrorKind,
};
use cfx_types::H256;
use primitives::Block;
use rlp_derive::{RlpDecodableWrapper, RlpEncodableWrapper};

#[derive(Debug, PartialEq, RlpDecodableWrapper, RlpEncodableWrapper)]
pub struct NewBlock {
    pub block: Block,
}

impl Handleable for NewBlock {
    // TODO This is only used in tests now. Maybe we can add a rpc to send full
    // block and remove NEW_BLOCK from p2p
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        // We may receive some messages from peer during recover from db
        // phase. We should ignore it, since it may cause some
        // inconsistency.
        if ctx.manager.in_recover_from_db_phase() {
            return Ok(());
        }
        let mut block = self.block;
        ctx.manager.graph.data_man.recover_block(&mut block)?;

        debug!(
            "on_new_block, header={:?} tx_number={}",
            block.block_header,
            block.transactions.len()
        );

        let parent_hash = block.block_header.parent_hash().clone();
        let referee_hashes = block.block_header.referee_hashes().clone();

        let headers_to_request = std::iter::once(parent_hash)
            .chain(referee_hashes)
            .filter(|h| !ctx.manager.graph.contains_block_header(&h))
            .collect();

        ctx.manager.request_block_headers(
            ctx.io,
            Some(ctx.node_id.clone()),
            headers_to_request,
            true, /* ignore_db */
        );

        let need_to_relay = on_new_decoded_block(ctx, block, true, true)?;

        // broadcast the hash of the newly got block
        ctx.manager.relay_blocks(ctx.io, need_to_relay)
    }
}

fn on_new_decoded_block(
    ctx: &Context, mut block: Block, need_to_verify: bool, persistent: bool,
) -> Result<Vec<H256>, Error> {
    let hash = block.block_header.hash();
    let mut need_to_relay = Vec::new();
    match ctx.manager.graph.block_header_by_hash(&hash) {
        Some(header) => block.block_header = header,
        None => {
            let (insert_result, to_relay) =
                ctx.manager.graph.insert_block_header(
                    &mut block.block_header,
                    need_to_verify,
                    false,
                    false,
                    true,
                );
            if insert_result.is_new_valid() {
                need_to_relay.extend(to_relay);
            } else {
                return Err(Error::from_kind(ErrorKind::InvalidBlock));
            }
        }
    }

    let insert_result = ctx.manager.graph.insert_block(
        block,
        need_to_verify,
        persistent,
        false, // recover_from_db
    );
    if insert_result.should_relay() {
        need_to_relay.push(hash);
    }
    Ok(need_to_relay)
}
