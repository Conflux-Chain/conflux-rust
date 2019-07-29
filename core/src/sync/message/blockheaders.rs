// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    sync::{
        message::{
            metrics::BLOCK_HEADER_HANDLE_TIMER, Context, Handleable, Message,
            MsgId, RequestId,
        },
        msg_sender::NULL,
        request_manager::RequestMessage,
        Error, ErrorKind,
    },
    verification::ACCEPTABLE_TIME_DRIFT,
};
use cfx_types::H256;
use metrics::MeterTimer;
use primitives::BlockHeader;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, PartialEq, Default)]
pub struct GetBlockHeadersResponse {
    request_id: RequestId,
    pub headers: Vec<BlockHeader>,
}

impl Handleable for GetBlockHeadersResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(BLOCK_HEADER_HANDLE_TIMER.as_ref());

        debug!("on_block_headers_response, msg=:{:?}", self);

        if ctx.peer == NULL {
            let requested =
                self.headers.iter().map(|h| h.hash().clone()).collect();

            self.handle_block_headers(ctx, &self.headers, requested, None);
            return Ok(());
        }

        let req = ctx.match_request(self.request_id())?;

        self.validate_block_headers_response(ctx, &req, &self)?;

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
            let mut exclude = HashSet::new();
            exclude.insert(ctx.peer);
            ctx.manager.syn.get_random_peer(&exclude)
        };

        // re-request headers requested but not received
        let requested = match req {
            RequestMessage::Headers(h) => h.hashes,
            RequestMessage::HeaderChain(h) => vec![h.hash],
            _ => return Err(ErrorKind::UnexpectedResponse.into()),
        };
        self.handle_block_headers(ctx, &self.headers, requested, chosen_peer);

        timestamp_validation_result
    }
}

impl GetBlockHeadersResponse {
    // FIXME Remove recursive call if block headers exist db
    fn handle_block_headers(
        &self, ctx: &Context, block_headers: &Vec<BlockHeader>,
        requested: Vec<H256>, chosen_peer: Option<usize>,
    )
    {
        let mut hashes = HashSet::new();
        let mut dependent_hashes = HashSet::new();
        let mut need_to_relay = HashSet::new();
        let mut returned_headers = HashSet::new();
        let now_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for header in block_headers {
            let hash = header.hash();
            returned_headers.insert(hash);
            // check timestamp drift
            if ctx.manager.graph.verification_config.verify_timestamp {
                if header.timestamp() > now_timestamp + ACCEPTABLE_TIME_DRIFT {
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
                true,
                false,
                ctx.manager.insert_header_to_consensus(),
                true,
            );
            if !valid {
                continue;
            }

            // check missing dependencies
            let parent = header.parent_hash();
            if !ctx.manager.graph.contains_block_header(parent) {
                dependent_hashes.insert(*parent);
            }

            for referee in header.referee_hashes() {
                if !ctx.manager.graph.contains_block_header(referee) {
                    dependent_hashes.insert(*referee);
                }
            }
            need_to_relay.extend(to_relay);

            // check block body
            if !ctx.manager.graph.contains_block(&hash) {
                hashes.insert(hash);
            }
        }

        // do not request headers we just received
        dependent_hashes.remove(&H256::default());
        for hash in &returned_headers {
            dependent_hashes.remove(hash);
        }

        debug!(
            "get headers response of hashes:{:?}, requesting block:{:?}",
            returned_headers, hashes
        );

        ctx.manager.request_manager.headers_received(
            ctx.io,
            requested.into_iter().collect(),
            returned_headers,
        );

        // request missing headers. We do not need to request more headers on
        // the pivot chain after the request_epoch mechanism is applied.
        ctx.manager.request_block_headers(
            ctx.io,
            chosen_peer,
            dependent_hashes.into_iter().collect(),
        );

        if ctx.manager.need_requesting_blocks() {
            // request missing blocks
            ctx.manager.request_missing_blocks(
                ctx.io,
                chosen_peer,
                hashes.into_iter().collect(),
            );

            // relay if necessary
            ctx.manager
                .relay_blocks(ctx.io, need_to_relay.into_iter().collect())
                .ok();
        }
    }

    fn validate_block_headers_response(
        &self, ctx: &Context, req: &RequestMessage,
        resp: &GetBlockHeadersResponse,
    ) -> Result<(), Error>
    {
        match &req {
            // For normal header requests, we have no
            // assumption about the response structure.
            RequestMessage::Headers(_) => return Ok(()),

            // For chained header requests, we assume the
            // response contains a sequence of block headers
            // which are listed in order with parent-child
            // relationship. For example, bh[i-1] should be
            // the parent of bh[i] which is in turn the parent
            // of bh[i+1].
            RequestMessage::HeaderChain(_) => {
                let mut parent_hash = None;
                for header in &resp.headers {
                    let hash = header.hash();
                    if parent_hash != None && parent_hash.unwrap() != hash {
                        // chain assumption not met, resend request
                        ctx.manager
                            .request_manager
                            .remove_mismatch_request(ctx.io, req);
                        return Err(ErrorKind::Invalid.into());
                    }
                    parent_hash = Some(header.parent_hash().clone());
                }

                return Ok(());
            }

            // Although the response matches the request id, it does
            // not match the content, so resend the request again.
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, resp);
                ctx.manager
                    .request_manager
                    .remove_mismatch_request(ctx.io, &req);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };
    }
}

impl Message for GetBlockHeadersResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HEADERS_RESPONSE }
}

impl Deref for GetBlockHeadersResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHeadersResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockHeadersResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.headers);
    }
}

impl Decodable for GetBlockHeadersResponse {
    fn decode(rlp: &Rlp) -> Result<GetBlockHeadersResponse, DecoderError> {
        Ok(GetBlockHeadersResponse {
            request_id: rlp.val_at(0)?,
            headers: rlp.list_at(1)?,
        })
    }
}
