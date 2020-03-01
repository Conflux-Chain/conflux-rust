// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    Error, SharedSynchronizationGraph, SynchronizationProtocolHandler,
};
use crate::{
    alliance_tree_graph::consensus::{
        NewCandidatePivotCallbackType, NextSelectedPivotCallbackType,
        SetPivotChainCallbackType, TreeGraphConsensus,
    },
    light_protocol::Provider as LightProvider,
    parameters::sync::SYNCHRONIZATION_PROTOCOL_VERSION,
    sync::{
        request_manager::RequestManager, synchronization_phases::SyncPhaseType,
        synchronization_protocol_handler::ProtocolConfiguration,
        StateSyncConfiguration, SynchronizationPhaseTrait,
    },
};
use cfx_types::H256;
use libra_types::{
    block_info::PivotBlockDecision, crypto_proxies::ValidatorVerifier,
};
use network::{NetworkService, PeerId, ProtocolId};
use primitives::{transaction::SignedTransaction, Block};
use std::sync::Arc;

pub struct SynchronizationService {
    network: Arc<NetworkService>,
    protocol_handler: Arc<SynchronizationProtocolHandler>,
    protocol: ProtocolId,
}

impl SynchronizationService {
    pub fn new(
        is_full_node: bool, network: Arc<NetworkService>,
        sync_graph: SharedSynchronizationGraph,
        protocol_config: ProtocolConfiguration,
        state_sync_config: StateSyncConfiguration,
        initial_sync_phase: SyncPhaseType, light_provider: Arc<LightProvider>,
    ) -> Self
    {
        let sync_handler = Arc::new(SynchronizationProtocolHandler::new(
            is_full_node,
            protocol_config,
            state_sync_config,
            initial_sync_phase,
            sync_graph.clone(),
            light_provider,
        ));

        assert_eq!(sync_handler.is_consortium(), sync_graph.is_consortium());

        SynchronizationService {
            network,
            protocol_handler: sync_handler,
            protocol: *b"cfx",
        }
    }

    pub fn update_validator_info(&self, validators: &ValidatorVerifier) {
        let validator_set =
            self.protocol_handler.update_validator_info(validators);
        self.network.update_validator_info(validator_set);
    }

    pub fn catch_up_mode(&self) -> bool {
        self.protocol_handler.catch_up_mode()
    }

    pub fn get_synchronization_graph(&self) -> SharedSynchronizationGraph {
        self.protocol_handler.get_synchronization_graph()
    }

    pub fn get_request_manager(&self) -> Arc<RequestManager> {
        self.protocol_handler.get_request_manager()
    }

    pub fn current_sync_phase(&self) -> Arc<dyn SynchronizationPhaseTrait> {
        self.protocol_handler.phase_manager.get_current_phase()
    }

    pub fn append_received_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        self.protocol_handler
            .append_received_transactions(transactions);
    }

    pub fn register(&self) -> Result<(), Error> {
        self.network.register_protocol(
            self.protocol_handler.clone(),
            self.protocol,
            &[SYNCHRONIZATION_PROTOCOL_VERSION],
        )?;
        Ok(())
    }

    fn relay_blocks(&self, need_to_relay: Vec<H256>) {
        // FIXME: We may need to propagate the error up
        let _res = self.network.with_context(self.protocol, |io| {
            self.protocol_handler.relay_blocks(io, need_to_relay)
        });
    }

    pub fn on_mined_block(&self, block: Block) {
        let hash = block.hash();
        self.protocol_handler.on_mined_block(block);
        self.relay_blocks(vec![hash]);
    }

    pub fn on_commit_blocks(&self, block_hashes: &Vec<H256>) {
        let sync_graph = self.get_synchronization_graph();
        let tg_consensus = sync_graph
            .consensus
            .as_any()
            .downcast_ref::<TreeGraphConsensus>()
            .expect("downcast to TreeGraphConsensus should success");
        tg_consensus.on_commit(block_hashes);
    }

    pub fn get_next_selected_pivot_block(
        &self, last_pivot_hash: Option<&H256>,
        callback: NextSelectedPivotCallbackType,
    )
    {
        let sync_graph = self.get_synchronization_graph();
        let tg_consensus = sync_graph
            .consensus
            .as_any()
            .downcast_ref::<TreeGraphConsensus>()
            .expect("downcast to TreeGraphConsensus should success");
        if let Some(block) =
            tg_consensus.on_next_selected_pivot_block(last_pivot_hash, callback)
        {
            self.on_mined_block(block);
        }
    }

    pub fn on_new_candidate_pivot(
        &self, pivot_decision: &PivotBlockDecision, peer_id: Option<PeerId>,
        callback: NewCandidatePivotCallbackType, ignore_db: bool,
    )
    {
        let sync_graph = self.get_synchronization_graph();
        let tg_consensus = sync_graph
            .consensus
            .as_any()
            .downcast_ref::<TreeGraphConsensus>()
            .expect("downcast to TreeGraphConsensus should success");
        if !tg_consensus.on_new_candidate_pivot(
            pivot_decision,
            peer_id,
            callback,
        ) {
            let _res = self.network.with_context(self.protocol, |io| {
                self.protocol_handler.request_block_headers(
                    io,
                    peer_id,
                    vec![pivot_decision.block_hash],
                    ignore_db, /* ignore_db */
                )
            });
        }
    }

    pub fn set_pivot_chain(
        &self, block_hash: &H256, callback: SetPivotChainCallbackType,
    ) {
        let sync_graph = self.get_synchronization_graph();
        sync_graph.recover_graph_from_db(false /* header_only */);
        let tg_consensus = sync_graph
            .consensus
            .as_any()
            .downcast_ref::<TreeGraphConsensus>()
            .expect("downcast to TreeGraphConsensus should success");
        if !tg_consensus.set_pivot_chain(block_hash, callback) {
            let _res = self.network.with_context(self.protocol, |io| {
                self.protocol_handler.request_block_headers(
                    io,
                    None, /* peer_id */
                    vec![*block_hash],
                    false, /* ignore_db */
                )
            });
        }
    }

    pub fn expire_block_gc(&self, timeout: u64) {
        let _res = self.network.with_context(self.protocol, |io| {
            self.protocol_handler.expire_block_gc(io, timeout)
        });
    }
}

pub type SharedSynchronizationService = Arc<SynchronizationService>;
