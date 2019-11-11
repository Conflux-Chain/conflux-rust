// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
mod error;
pub mod message;
pub mod request_manager;
mod state;

#[cfg(test)]
pub mod tests;

mod synchronization_graph;
mod synchronization_phases;
mod synchronization_protocol_handler;
mod synchronization_service;
mod synchronization_state;
pub mod utils;

pub use self::{
    error::{Error, ErrorKind},
    state::{delta, restore},
    synchronization_graph::{
        SharedSynchronizationGraph, SyncGraphConfig, SyncGraphStatistics,
        SynchronizationGraph, SynchronizationGraphInner,
        SynchronizationGraphNode,
    },
    synchronization_phases::{
        CatchUpCheckpointPhase, CatchUpRecoverBlockFromDbPhase,
        CatchUpRecoverBlockHeaderFromDbPhase, CatchUpSyncBlockHeaderPhase,
        CatchUpSyncBlockPhase, NormalSyncPhase, SyncPhaseType,
        SynchronizationPhaseManager, SynchronizationPhaseTrait,
    },
    synchronization_protocol_handler::{
        LocalMessageTask, ProtocolConfiguration, SyncHandlerWorkType,
        SynchronizationProtocolHandler,
    },
    synchronization_service::{
        SharedSynchronizationService, SynchronizationService,
    },
    synchronization_state::{SynchronizationPeerState, SynchronizationState},
};

pub mod random {
    use rand;
    pub fn new() -> rand::prelude::ThreadRng { rand::thread_rng() }
}

pub mod msg_sender {
    use super::message::msgid;
    use crate::message::MsgId;
    use metrics::{register_meter_with_group, Meter};
    use network::PeerId;
    use std::sync::Arc;

    pub const NULL: usize = !0;

    lazy_static! {
        static ref GET_BLOCK_TXN_RESPOPNSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_txn_response"
            );
        static ref GET_BLOCK_TXN_RESPOPNSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_txn_response_counter"
            );
        static ref DYNAMIC_CAPABILITY_CHANGE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "dynamic_capability_change"
            );
        static ref DYNAMIC_CAPABILITY_CHANGE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "dynamic_capability_change_counter"
            );
        static ref TRANSACTION_DIGESTS_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "transaction_digests"
            );
        static ref TRANSACTION_DIGESTS_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "transaction_digests_counter"
            );
        static ref GET_TRANSACTIONS_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_transactions"
            );
        static ref GET_TRANSACTIONS_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_transactions_counter"
            );
        static ref GET_TRANSACTIONS_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_transactions_response"
            );
        static ref GET_TRANSACTIONS_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_transactions_response_counter"
            );
        static ref GET_BLOCK_HASHES_BY_EPOCH_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_hashes_by_epoch"
            );
        static ref GET_BLOCK_HASHES_BY_EPOCH_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_hashes_by_epoch_counter"
            );
        static ref GET_BLOCK_HASHES_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_hashes_response"
            );
        static ref GET_BLOCK_HASHES_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_hashes_response_counter"
            );
        static ref OTHER_HIGH_METER: Arc<dyn Meter> = register_meter_with_group(
            "network_connection_data",
            "other_high_meter"
        );
        static ref OTHER_HIGH_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "other_high_meter_counter"
            );
    }
    lazy_static! {
        static ref ON_STATUS_METER: Arc<dyn Meter> =
            register_meter_with_group("network_connection_data", "on_status");
        static ref ON_STATUS_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "on_status_counter"
            );
        static ref GET_BLOCK_HEADER_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_header_response"
            );
        static ref GET_BLOCK_HEADER_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_header_response_counter"
            );
        static ref GET_BLOCK_HEADERS_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_headers"
            );
        static ref GET_BLOCK_HEADERS_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_headers_counter"
            );
        static ref GET_BLOCK_HEADER_CHAIN_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_header_chain"
            );
        static ref GET_BLOCK_HEADER_CHAIN_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_header_chain_counter"
            );
        static ref NEW_BLOCK_METER: Arc<dyn Meter> =
            register_meter_with_group("network_connection_data", "new_block");
        static ref NEW_BLOCK_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "new_block_counter"
            );
        static ref NEW_BLOCK_HASHES_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "new_block_hashes"
            );
        static ref NEW_BLOCK_HASHES_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "new_block_hashes_counter"
            );
        static ref GET_BLOCKS_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_blocks_response"
            );
        static ref GET_BLOCKS_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_blocks_response_counter"
            );
        static ref GET_BLOCKS_WITH_PUBLIC_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_blocks_with_public_response"
            );
        static ref GET_BLOCKS_WITH_PUBLIC_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_blocks_with_public_response_counter"
            );
        static ref GET_BLOCKS_METER: Arc<dyn Meter> =
            register_meter_with_group("network_connection_data", "get_blocks");
        static ref GET_BLOCKS_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_blocks_counter"
            );
        static ref GET_TERMINAL_BLOCK_HASHES_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_terminal_block_hashes_response"
            );
        static ref GET_TERMINAL_BLOCK_HASHES_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_terminal_block_hashes_response_counter"
            );
        static ref GET_TERMINAL_BLOCK_HASHES_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_terminal_block_hashes"
            );
        static ref GET_TERMINAL_BLOCK_HASHES_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_terminal_block_hashes_counter"
            );
        static ref TRANSACTIONS_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "transactions_counter"
            );
        static ref GET_CMPCT_BLOCKS_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_cmpct_blocks"
            );
        static ref GET_CMPCT_BLOCKS_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_cmpct_blocks_counter"
            );
        static ref GET_CMPCT_BLOCKS_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_cmpct_blocks_response"
            );
        static ref GET_CMPCT_BLOCKS_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_cmpct_blocks_response_counter"
            );
        static ref GET_BLOCK_TXN_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_txn"
            );
        static ref GET_BLOCK_TXN_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_txn_counter"
            );
    }
    lazy_static! {
        static ref GET_TRANSACTIONS_FROM_TX_HASHES_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_transactions_from_tx_hashes"
            );
        static ref GET_TRANSACTIONS_FROM_TX_HASHES_COUNTRER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_transactions_from_tx_hashes_counter"
            );
        static ref GET_TRANSACTIONS_FROM_TX_HASHES_RESPONSE_METER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_transactions_from_tx_hashes_response"
            );
        static ref GET_TRANSACTIONS_FROM_TX_HASHES_RESPONSE_COUNTER: Arc<dyn Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_transactions_from_tx_hashes_response_counter"
            );
    }

    pub fn metric_message(peer: PeerId, msg_id: MsgId, size: usize) {
        if peer == NULL {
            return;
        }

        match msg_id {
            msgid::STATUS => ON_STATUS_METER.mark(size),
            msgid::GET_BLOCK_HEADERS_RESPONSE => {
                GET_BLOCK_HEADER_RESPONSE_METER.mark(size);
                GET_BLOCK_HEADER_RESPONSE_COUNTER.mark(1);
            }
            msgid::GET_BLOCK_HEADERS => {
                GET_BLOCK_HEADERS_METER.mark(size);
                GET_BLOCK_HEADERS_COUNTER.mark(1);
            }
            msgid::GET_BLOCK_HEADER_CHAIN => {
                GET_BLOCK_HEADER_CHAIN_METER.mark(size);
                GET_BLOCK_HEADER_CHAIN_COUNTER.mark(1);
            }
            msgid::NEW_BLOCK => {
                NEW_BLOCK_METER.mark(size);
                NEW_BLOCK_COUNTER.mark(1);
            }
            msgid::NEW_BLOCK_HASHES => {
                NEW_BLOCK_HASHES_METER.mark(size);
                NEW_BLOCK_HASHES_COUNTER.mark(1);
            }
            msgid::GET_BLOCKS_RESPONSE => {
                GET_BLOCKS_RESPONSE_METER.mark(size);
                GET_BLOCKS_RESPONSE_COUNTER.mark(1);
            }
            msgid::GET_BLOCKS_WITH_PUBLIC_RESPONSE => {
                GET_BLOCKS_WITH_PUBLIC_RESPONSE_METER.mark(size);
                GET_BLOCKS_WITH_PUBLIC_RESPONSE_COUNTER.mark(1);
            }
            msgid::GET_BLOCKS => {
                GET_BLOCKS_METER.mark(size);
                GET_BLOCKS_COUNTER.mark(1);
            }
            msgid::GET_TERMINAL_BLOCK_HASHES_RESPONSE => {
                GET_TERMINAL_BLOCK_HASHES_RESPONSE_METER.mark(size);
                GET_TERMINAL_BLOCK_HASHES_RESPONSE_COUNTER.mark(1);
            }
            msgid::GET_TERMINAL_BLOCK_HASHES => {
                GET_TERMINAL_BLOCK_HASHES_METER.mark(size);
                GET_TERMINAL_BLOCK_HASHES_COUNTER.mark(1);
            }
            msgid::GET_CMPCT_BLOCKS => {
                GET_CMPCT_BLOCKS_METER.mark(size);
                GET_CMPCT_BLOCKS_COUNTER.mark(1);
            }
            msgid::GET_CMPCT_BLOCKS_RESPONSE => {
                GET_CMPCT_BLOCKS_RESPONSE_METER.mark(size);
                GET_CMPCT_BLOCKS_RESPONSE_COUNTER.mark(1);
            }
            msgid::GET_BLOCK_TXN => {
                GET_BLOCK_TXN_METER.mark(size);
                GET_BLOCK_TXN_COUNTER.mark(1);
            }
            msgid::GET_BLOCK_TXN_RESPONSE => {
                GET_BLOCK_TXN_RESPOPNSE_METER.mark(size);
                GET_BLOCK_TXN_RESPOPNSE_COUNTER.mark(1);
            }
            msgid::DYNAMIC_CAPABILITY_CHANGE => {
                DYNAMIC_CAPABILITY_CHANGE_METER.mark(size);
                DYNAMIC_CAPABILITY_CHANGE_COUNTER.mark(1);
            }
            msgid::TRANSACTION_DIGESTS => {
                TRANSACTION_DIGESTS_METER.mark(size);
                TRANSACTION_DIGESTS_COUNTER.mark(1);
            }
            msgid::GET_TRANSACTIONS => {
                GET_TRANSACTIONS_METER.mark(size);
                GET_TRANSACTIONS_COUNTER.mark(1);
            }
            msgid::GET_TRANSACTIONS_RESPONSE => {
                GET_TRANSACTIONS_RESPONSE_METER.mark(size);
                GET_TRANSACTIONS_RESPONSE_COUNTER.mark(1);
            }
            msgid::GET_BLOCK_HASHES_BY_EPOCH => {
                GET_BLOCK_HASHES_BY_EPOCH_METER.mark(size);
                GET_BLOCK_HASHES_BY_EPOCH_COUNTER.mark(1);
            }
            msgid::GET_BLOCK_HASHES_RESPONSE => {
                GET_BLOCK_HASHES_RESPONSE_METER.mark(size);
                GET_BLOCK_HASHES_RESPONSE_COUNTER.mark(1);
            }
            _ => {
                OTHER_HIGH_METER.mark(size);
                OTHER_HIGH_COUNTER.mark(1);
            }
        }
    }
}
