// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    Error, SharedSynchronizationGraph, SynchronizationProtocolHandler,
    SYNCHRONIZATION_PROTOCOL_VERSION,
};
use crate::{
    consensus::SharedConsensusGraph, pow::ProofOfWorkConfig,
    sync::synchronization_protocol_handler::ProtocolConfiguration,
    verification::VerificationConfig,
};
use cfx_types::H256;
use keylib::KeyPair;
use network::{
    node_table::{NodeEntry, NodeId},
    Error as NetworkError, NetworkService, PeerInfo, ProtocolId,
};
use primitives::{transaction::SignedTransaction, Block};
use std::sync::Arc;

pub struct SynchronizationService {
    network: NetworkService,
    protocol_handler: Arc<SynchronizationProtocolHandler>,
    protocol: ProtocolId,
}

impl SynchronizationService {
    pub fn new(
        is_full_node: bool, network: NetworkService,
        consensus_graph: SharedConsensusGraph,
        protocol_config: ProtocolConfiguration,
        verification_config: VerificationConfig, pow_config: ProofOfWorkConfig,
    ) -> Self
    {
        let sync_handler = Arc::new(SynchronizationProtocolHandler::new(
            is_full_node,
            protocol_config,
            consensus_graph,
            verification_config,
            pow_config,
        ));

        SynchronizationService {
            network,
            protocol_handler: sync_handler,
            protocol: *b"cfx",
        }
    }

    pub fn get_network_service(&self) -> &NetworkService { &self.network }

    pub fn catch_up_mode(&self) -> bool {
        self.protocol_handler.catch_up_mode()
    }

    pub fn get_synchronization_graph(&self) -> SharedSynchronizationGraph {
        self.protocol_handler.get_synchronization_graph()
    }

    pub fn append_received_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        self.protocol_handler
            .append_received_transactions(transactions);
    }

    pub fn start(&mut self) -> Result<(), Error> {
        self.network.start()?;
        self.network.register_protocol(
            self.protocol_handler.clone(),
            self.protocol,
            &[SYNCHRONIZATION_PROTOCOL_VERSION],
        )?;
        Ok(())
    }

    pub fn relay_blocks(&self, need_to_relay: Vec<H256>) {
        self.network.with_context(self.protocol, |io| {
            // FIXME: We may need to propagate the error up
            self.protocol_handler
                .relay_blocks(io, need_to_relay)
                .unwrap();
        });
    }

    pub fn on_mined_block(&self, block: Block) {
        let hash = block.hash();
        self.protocol_handler.on_mined_block(block);
        self.relay_blocks(vec![hash]);
    }

    pub fn add_peer(&self, node: NodeEntry) -> Result<(), NetworkError> {
        self.network.add_peer(node)
    }

    pub fn drop_peer(&self, node: NodeEntry) -> Result<(), NetworkError> {
        self.network.drop_peer(node)
    }

    pub fn get_peer_info(&self) -> Vec<PeerInfo> {
        self.network.get_peer_info().unwrap()
    }

    pub fn sign_challenge(
        &self, challenge: Vec<u8>,
    ) -> Result<Vec<u8>, NetworkError> {
        self.network.sign_challenge(challenge)
    }

    pub fn add_latency(
        &self, id: NodeId, latency_ms: f64,
    ) -> Result<(), NetworkError> {
        self.network.add_latency(id, latency_ms)
    }

    pub fn block_by_hash(&self, hash: &H256) -> Option<Arc<Block>> {
        self.protocol_handler.block_by_hash(hash)
    }

    pub fn net_key_pair(&self) -> Result<KeyPair, NetworkError> {
        self.network.net_key_pair()
    }
}

pub type SharedSynchronizationService = Arc<SynchronizationService>;
