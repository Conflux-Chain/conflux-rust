// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable},
    Error,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Debug, PartialEq)]
pub struct NewBlockHashes {
    pub block_hashes: Vec<H256>,
}

impl Encodable for NewBlockHashes {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_list(&self.block_hashes);
    }
}

impl Decodable for NewBlockHashes {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let block_hashes = d.as_list()?;
        Ok(NewBlockHashes { block_hashes })
    }
}

impl Handleable for NewBlockHashes {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_new_block_hashes, msg={:?}", self);

        // Determine which block hashes are unknown to us, but only when at
        // least one consumer actually needs the result.
        //
        // Two consumers exist:
        //   1. The `log_block_source` logging path, which uses the unknown
        //      hashes for approximate first-seen deduplication so that only the
        //      first peer to propagate a block hash (before we download its
        //      header) generates a [BLOCK_SOURCE] log entry.
        //   2. The header-request path (active only outside catch-up mode),
        //      which filters out hashes whose headers we already have to avoid
        //      redundant requests.
        //
        // When neither consumer is active — i.e. we are in catch-up mode with
        // logging disabled — the `block_header_by_hash` lookups are skipped
        // entirely and `unknown_hashes` stays empty (no allocation). This
        // restores the pre-logging performance characteristics: zero overhead
        // in catch-up mode.
        //
        // The result is computed once and shared by both consumers, avoiding
        // duplicate lookups. A `Vec<&H256>` is used instead of a `HashSet`
        // because the typical NewBlockHashes message contains only 1–2 hashes,
        // making linear iteration cheaper than HashSet allocation and hashing.
        //
        // Trade-off: this uses the existing block_header_by_hash lookup
        // (in-memory HashMap + DB fallback) for approximate first-seen
        // deduplication. It is not a strict first-seen guarantee: multiple
        // peers propagating the same hash within the header-download window
        // (typically milliseconds to a few seconds) each generate a log
        // entry. After the header is cached, all subsequent NewBlockHashes
        // for the same block are silently suppressed, which is the desired
        // behavior for tracking block propagation sources.
        let in_catch_up_mode = ctx.manager.catch_up_mode();

        let unknown_hashes: Vec<&H256> = if ctx
            .manager
            .protocol_config
            .log_block_source
            || !in_catch_up_mode
        {
            self.block_hashes
                .iter()
                .filter(|hash| {
                    ctx.manager
                        .graph
                        .data_man
                        .block_header_by_hash(hash)
                        .is_none()
                })
                .collect()
        } else {
            Vec::new()
        };

        if ctx.manager.protocol_config.log_block_source {
            let peer_addr = ctx
                .peer_addr
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            for hash in &unknown_hashes {
                info!(
                    "[BLOCK_SOURCE] hash={:#x} from_node={} from_addr={}",
                    hash, ctx.node_id, peer_addr
                );
            }
        }

        if in_catch_up_mode {
            // If a node is in catch-up mode and we are not in test-mode, we
            // just simple ignore new block hashes.
            if ctx.manager.protocol_config.test_mode {
                if let Ok(info) = ctx.manager.syn.get_peer_info(&ctx.node_id) {
                    let mut info = info.write();
                    self.block_hashes.iter().for_each(|h| {
                        info.latest_block_hashes.insert(*h);
                    });
                }
            }
            return Ok(());
        }

        let headers_to_request: Vec<H256> =
            unknown_hashes.into_iter().cloned().collect();

        ctx.manager.request_block_headers(
            ctx.io,
            Some(ctx.node_id.clone()),
            headers_to_request,
            // We have already checked db that these headers do not exist.
            true, /* ignore_db */
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_round_trip_empty() {
        let original = NewBlockHashes {
            block_hashes: vec![],
        };
        let encoded = rlp::encode(&original);
        let decoded: NewBlockHashes = rlp::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn rlp_round_trip_single_hash() {
        let original = NewBlockHashes {
            block_hashes: vec![H256::from_low_u64_be(42)],
        };
        let encoded = rlp::encode(&original);
        let decoded: NewBlockHashes = rlp::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn rlp_round_trip_multiple_hashes() {
        let original = NewBlockHashes {
            block_hashes: vec![
                H256::from_low_u64_be(1),
                H256::from_low_u64_be(2),
                H256::from_low_u64_be(3),
                H256::random(),
            ],
        };
        let encoded = rlp::encode(&original);
        let decoded: NewBlockHashes = rlp::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn rlp_decode_rejects_short_element() {
        // 0xc1 0x01 is an RLP list with one 1-byte element.
        // H256 requires 32 bytes, so this should fail to decode.
        let short_element: &[u8] = &[0xc1, 0x01];
        let result: Result<NewBlockHashes, _> = rlp::decode(short_element);
        assert!(result.is_err());
    }
}
