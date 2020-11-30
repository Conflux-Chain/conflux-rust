// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    sync::{
        message::{
            handleable::{Context, Handleable},
            DynamicCapability,
        },
        Error, ErrorKind, SynchronizationPeerState,
    },
    NodeType,
};
use cfx_internal_common::ChainIdParamsDeprecated;
use cfx_types::H256;
use network::{NODE_TAG_ARCHIVE, NODE_TAG_FULL, NODE_TAG_NODE_TYPE};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{collections::HashSet, time::Instant};
use throttling::token_bucket::TokenBucketManager;

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct StatusV2 {
    pub chain_id: ChainIdParamsDeprecated,
    pub genesis_hash: H256,
    pub best_epoch: u64,
    pub terminal_block_hashes: Vec<H256>,
}

impl Handleable for StatusV2 {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_status, msg=:{:?}", self);

        let chain_id = ctx.manager.graph.consensus.best_chain_id();
        if chain_id != self.chain_id.chain_id {
            debug!(
                "Peer {:?} chain_id mismatches (ours: {:?}, theirs: {:?})",
                ctx.node_id, chain_id, self.chain_id,
            );
            bail!(ErrorKind::InvalidStatus("chain_id mismatches".into()));
        }

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
                peer_info.update(
                    Some(NodeType::Unknown),
                    latest,
                    self.best_epoch,
                )
            };

            if latest_updated {
                ctx.manager.start_sync(ctx.io);
            }
        } else {
            let peer_protocol_version =
                match ctx.manager.syn.on_status_in_handshaking(&ctx.node_id) {
                    None => {
                        warn!(
                            "Unexpected Status message from peer={}",
                            ctx.node_id
                        );
                        return Err(ErrorKind::UnknownPeer.into());
                    }
                    Some(protocol_version) => protocol_version,
                };

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
                node_type: NodeType::Unknown,
                is_validator: false,
                protocol_version: peer_protocol_version,
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
                .insert(DynamicCapability::NormalPhase(true));

            debug!(
                "New peer (pv={:?}, gh={:?})",
                peer_protocol_version, self.genesis_hash
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

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct StatusV3 {
    pub chain_id: ChainIdParamsDeprecated,
    pub genesis_hash: H256,
    pub best_epoch: u64,
    pub node_type: NodeType,
    pub terminal_block_hashes: Vec<H256>,
}

impl Handleable for StatusV3 {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_status, msg=:{:?}", self);

        let chain_id = ctx.manager.graph.consensus.get_config().chain_id.read();
        if !chain_id.matches(&self.chain_id.clone().into(), self.best_epoch) {
            debug!(
                "Peer {:?} chain_id mismatches (ours: {:?}, theirs: {:?})",
                ctx.node_id, chain_id, self.chain_id,
            );
            bail!(ErrorKind::InvalidStatus("chain_id mismatches".into()));
        }
        drop(chain_id);

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

        match self.node_type {
            NodeType::Archive => {
                let key: String = NODE_TAG_NODE_TYPE.into();
                let value: String = NODE_TAG_ARCHIVE.into();
                ctx.insert_peer_node_tag(ctx.node_id(), &key, &value);
            }
            NodeType::Full => {
                let key: String = NODE_TAG_NODE_TYPE.into();
                let value: String = NODE_TAG_FULL.into();
                ctx.insert_peer_node_tag(ctx.node_id(), &key, &value);
            }
            _ => {}
        };

        if let Ok(peer_info) = ctx.manager.syn.get_peer_info(&ctx.node_id) {
            let latest_updated = {
                let mut peer_info = peer_info.write();
                peer_info.update(Some(self.node_type), latest, self.best_epoch)
            };

            if latest_updated {
                ctx.manager.start_sync(ctx.io);
            }
        } else {
            let peer_protocol_version =
                match ctx.manager.syn.on_status_in_handshaking(&ctx.node_id) {
                    None => {
                        warn!(
                            "Unexpected Status message from peer={}",
                            ctx.node_id
                        );
                        return Err(ErrorKind::UnknownPeer.into());
                    }
                    Some(protocol_version) => protocol_version,
                };

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
                node_type: self.node_type,
                is_validator: false,
                protocol_version: peer_protocol_version,
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
                .insert(DynamicCapability::NormalPhase(true));

            debug!(
                "New peer (pv={:?}, gh={:?})",
                peer_protocol_version, self.genesis_hash
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
