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

        // Log the source peer information for each NewBlockHashes message.
        // This is controlled by the log_block_source config flag and is
        // designed for bootnode deployment to track block propagation.
        if ctx.manager.protocol_config.log_block_source {
            let peer_addr = ctx
                .peer_addr
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            for hash in &self.block_hashes {
                info!(
                    "[BLOCK_SOURCE] hash={:#x} from_node={} from_addr={}",
                    hash, ctx.node_id, peer_addr
                );
            }
        }

        if ctx.manager.catch_up_mode() {
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

        let headers_to_request = self
            .block_hashes
            .iter()
            .filter(|hash| {
                ctx.manager
                    .graph
                    .data_man
                    .block_header_by_hash(&hash)
                    .is_none()
            })
            .cloned()
            .collect::<Vec<_>>();

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
