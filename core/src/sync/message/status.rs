// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        handleable::{Context, Handleable},
        DynamicCapability,
    },
    Error, ErrorKind, SynchronizationPeerState,
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{collections::HashSet, time::Instant};
use throttling::token_bucket::TokenBucketManager;

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct Status {
    pub protocol_version: u8,
    pub genesis_hash: H256,
    pub best_epoch: u64,
    pub terminal_block_hashes: Vec<H256>,
}

impl Handleable for Status {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_status, msg=:{:?}", self);

        let genesis_hash = ctx.manager.graph.data_man.true_genesis.hash();
        if genesis_hash != self.genesis_hash {
            debug!(
                "Peer {:?} genesis hash mismatches (ours: {:?}, theirs: {:?})",
                ctx.node_id, genesis_hash, self.genesis_hash
            );
            bail!(ErrorKind::InvalidStatus("genesis hash mismatches".into()));
        }

        let latest: HashSet<H256> =
            self.terminal_block_hashes.iter().cloned().collect();

        if let Ok(peer_info) = ctx.manager.syn.get_peer_info(&ctx.node_id) {
            let latest_updated = {
                let mut peer_info = peer_info.write();
                if peer_info.protocol_version != self.protocol_version {
                    warn!("Protocol versions do not match");
                    bail!(ErrorKind::InvalidStatus(
                        "protocol version mismatches".into()
                    ));
                }
                peer_info.heartbeat = Instant::now();

                let updated = self.best_epoch != peer_info.best_epoch
                    || latest != peer_info.latest_block_hashes;

                // NOTE: we need to update best_epoch even if it's smaller than
                // the previous value, otherwise sync will get stuck in tests
                // with large chain reorg (decreasing best epoch value)
                if updated {
                    peer_info.best_epoch = self.best_epoch;
                    peer_info.latest_block_hashes = latest;
                }

                updated
            };

            if latest_updated {
                ctx.manager.start_sync(ctx.io);
            }
        } else {
            if !ctx.manager.syn.on_status_in_handshaking(&ctx.node_id) {
                warn!("Unexpected Status message from peer={}", ctx.node_id);
                return Err(ErrorKind::UnknownPeer.into());
            }

            let throttling =
                match ctx.manager.protocol_config.throttling_config_file {
                    Some(ref file) => {
                        TokenBucketManager::load(file, Some("sync_protocol"))
                            .expect("invalid throttling configuration file")
                    }
                    None => TokenBucketManager::default(),
                };

            let mut peer_state = SynchronizationPeerState {
                node_id: ctx.node_id(),
                is_validator: false,
                protocol_version: self.protocol_version,
                genesis_hash,
                best_epoch: self.best_epoch,
                latest_block_hashes: latest,
                received_transaction_count: 0,
                heartbeat: Instant::now(),
                capabilities: Default::default(),
                notified_capabilities: Default::default(),
                throttling,
                throttled_msgs: Default::default(),
            };

            peer_state
                .capabilities
                .insert(DynamicCapability::TxRelay(true));

            debug!(
                "New peer (pv={:?}, gh={:?})",
                self.protocol_version, self.genesis_hash
            );

            debug!("Peer {:?} connected", ctx.node_id);
            ctx.manager
                .syn
                .peer_connected(ctx.node_id.clone(), peer_state);
            ctx.manager.request_manager.on_peer_connected(&ctx.node_id);

            ctx.manager.start_sync(ctx.io);
        }

        Ok(())
    }
}
