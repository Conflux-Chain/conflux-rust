// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    parameters::{
        block::ACCEPTABLE_TIME_DRIFT, sync::LOCAL_BLOCK_INFO_QUERY_THRESHOLD,
    },
    sync::{
        message::{
            metrics::BLOCK_HEADER_HANDLE_TIMER, Context, GetBlockHeaders,
            Handleable,
        },
        msg_sender::NULL,
        synchronization_state::PeerFilter,
        Error,
    },
};
use cfx_types::H256;
use metrics::MeterTimer;
use primitives::BlockHeader;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, PartialEq, Default, RlpDecodable, RlpEncodable)]
pub struct GetBlockHeadersResponse {
    pub request_id: RequestId,
    pub headers: Vec<BlockHeader>,
}

impl Handleable for GetBlockHeadersResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(BLOCK_HEADER_HANDLE_TIMER.as_ref());

        for header in &self.headers {
            debug!(
                "new block headers received: block_header={:?}, tx_count={}, block_size={}",
                header,
                0,
                0,
            );
        }

        if ctx.peer == NULL {
            let requested = self.headers.iter().map(|h| h.hash()).collect();

            self.handle_block_headers(
                ctx,
                &self.headers,
                requested,
                None,
                None,
            );
            return Ok(());
        }

        // We may receive some messages from peer during recover from db
        // phase. We should ignore it, since it may cause some
        // inconsistency.
        if ctx.manager.in_recover_from_db_phase() {
            return Ok(());
        }

        let req = ctx.match_request(self.request_id)?;
        let delay = req.delay;
        let req = req.downcast_ref::<GetBlockHeaders>(
            ctx.io,
            &ctx.manager.request_manager,
        )?;

        // keep first time drift validation error to return later
        let now_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let timestamp_validation_result =
            if ctx.manager.graph.verification_config.verify_timestamp {
                self.headers
                    .iter()
                    .map(|h| {
                        ctx.manager
                            .graph
                            .verification_config
                            .validate_header_timestamp(h, now_timestamp)
                    })
                    .find(|result| result.is_err())
                    .unwrap_or(Ok(()))
            } else {
                Ok(())
            };

        let chosen_peer = if timestamp_validation_result.is_ok() {
            Some(ctx.peer)
        } else {
            PeerFilter::new(self.msg_id())
                .exclude(ctx.peer)
                .select(&ctx.manager.syn)
        };

        // re-request headers requested but not received
        let requested: HashSet<H256> = req.hashes.iter().cloned().collect();
        self.handle_block_headers(
            ctx,
            &self.headers,
            requested,
            chosen_peer,
            delay,
        );

        timestamp_validation_result
    }
}

impl GetBlockHeadersResponse {
    // FIXME Remove recursive call if block headers exist db
    fn handle_block_headers(
        &self, ctx: &Context, block_headers: &Vec<BlockHeader>,
        requested: HashSet<H256>, chosen_peer: Option<usize>,
        delay: Option<Duration>,
    )
    {
        // This stores the block hashes for blocks without block body.
        let mut hashes = Vec::new();
        let mut dependent_hashes_bounded = HashSet::new();
        let mut dependent_hashes_unbounded = HashSet::new();
        // This stores the block hashes for blocks which can relay to peers.
        let mut need_to_relay = Vec::new();
        let mut returned_headers = HashSet::new();
        let best_height = ctx.manager.graph.consensus.best_epoch_number();
        let now_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for header in block_headers {
            let hash = header.hash();
            returned_headers.insert(hash);
            if ctx.manager.graph.contains_block_header(&hash) {
                // A block header might be loaded from db and sent to the local
                // queue multiple times, but we should only
                // process it and request its dependence once.
                continue;
            }

            // Check timestamp drift
            // See comments in verify_header_graph_ready_block()
            if ctx.manager.graph.verification_config.verify_timestamp {
                let header_timestamp = header.timestamp();
                if header_timestamp > now_timestamp {
                    warn!("Block {} timestamp {} is ahead of the current time {}. Potential time drift!", hash, header_timestamp, now_timestamp);
                }
                if header_timestamp > now_timestamp + ACCEPTABLE_TIME_DRIFT {
                    warn!("The drift is more than the acceptable range ({}s). The processing of block {} will be delayed.", ACCEPTABLE_TIME_DRIFT, hash);
                    ctx.manager.future_blocks.insert(header.clone());
                    continue;
                }
            }

            // check whether block is in old era
            let (era_genesis_hash, era_genesis_height) = ctx
                .manager
                .graph
                .get_genesis_hash_and_height_in_current_era();
            if (header.height() < era_genesis_height)
                || (header.height() == era_genesis_height
                    && header.hash() != era_genesis_hash)
            {
                // TODO: optimize to make block body empty
                assert!(true);
            }

            // insert into sync graph
            let (valid, to_relay) = ctx.manager.graph.insert_block_header(
                &mut header.clone(),
                true,  /* need_to_verify */
                false, /* bench_mode */
                ctx.manager.insert_header_to_consensus(),
                true, /* persistent */
            );
            if !valid {
                continue;
            }

            // check missing dependencies
            let parent = header.parent_hash();
            if !ctx.manager.graph.contains_block_header(parent) {
                if header.height() > best_height
                    || best_height - header.height()
                        < LOCAL_BLOCK_INFO_QUERY_THRESHOLD
                {
                    dependent_hashes_bounded.insert(*parent);
                } else {
                    dependent_hashes_unbounded.insert(*parent);
                }
            }

            for referee in header.referee_hashes() {
                if !ctx.manager.graph.contains_block_header(referee) {
                    dependent_hashes_unbounded.insert(*referee);
                }
            }
            need_to_relay.extend(to_relay);

            // check block body
            if !ctx.manager.graph.contains_block(&hash) {
                hashes.push(hash);
            }
        }

        // do not request headers we just received
        for hash in &returned_headers {
            dependent_hashes_bounded.remove(hash);
            dependent_hashes_unbounded.remove(hash);
        }
        for hash in &dependent_hashes_bounded {
            dependent_hashes_unbounded.remove(hash);
        }

        debug!(
            "get headers response of hashes:{:?}, requesting block:{:?}",
            returned_headers, hashes
        );

        ctx.manager.request_manager.headers_received(
            ctx.io,
            requested,
            returned_headers,
            delay,
        );

        // request missing headers. We do not need to request more headers on
        // the pivot chain after the request_epoch mechanism is applied.
        ctx.manager.request_block_headers(
            ctx.io,
            chosen_peer,
            dependent_hashes_bounded.into_iter().collect(),
            true, /* ignore_db */
        );
        ctx.manager.request_block_headers(
            ctx.io,
            chosen_peer,
            dependent_hashes_unbounded.into_iter().collect(),
            false, /* ignore_db */
        );

        if ctx.manager.need_requesting_blocks() {
            // request missing blocks
            ctx.manager
                .request_missing_blocks(ctx.io, chosen_peer, hashes)
                .ok();

            // relay if necessary
            ctx.manager.relay_blocks(ctx.io, need_to_relay).ok();
        }
    }
}
