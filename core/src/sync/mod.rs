// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
mod error;
mod message;
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
    synchronization_graph::{
        SharedSynchronizationGraph, SyncGraphStatistics, SynchronizationGraph,
        SynchronizationGraphInner, SynchronizationGraphNode,
    },
    synchronization_phases::{
        CatchUpCheckpointPhase, CatchUpRecoverBlockFromDbPhase,
        CatchUpRecoverBlockHeaderFromDbPhase, CatchUpSyncBlockHeaderPhase,
        CatchUpSyncBlockPhase, NormalSyncPhase, SyncPhaseType,
        SynchronizationPhaseManager, SynchronizationPhaseTrait,
    },
    synchronization_protocol_handler::{
        LocalMessageTask, ProtocolConfiguration, SyncHandlerWorkType,
        SynchronizationProtocolHandler, CATCH_UP_EPOCH_LAG_THRESHOLD,
        SYNCHRONIZATION_PROTOCOL_VERSION,
    },
    synchronization_service::{
        SharedSynchronizationService, SynchronizationService,
    },
    synchronization_state::{SynchronizationPeerState, SynchronizationState},
};

pub mod random {
    use rand;
    pub fn new() -> rand::ThreadRng { rand::thread_rng() }
}

pub mod msg_sender {
    use super::message::msgid;
    use crate::message::Message;
    use metrics::{register_meter_with_group, Meter};
    use network::{Error as NetworkError, NetworkContext, PeerId};
    use priority_send_queue::SendQueuePriority;
    use std::sync::Arc;

    pub const NULL: usize = !0;

    lazy_static! {
        static ref GET_BLOCK_TXN_RESPOPNSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_txn_response"
            );
        static ref GET_BLOCK_TXN_RESPOPNSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_txn_response_counter"
            );
        static ref TRANSACTION_PROPAGATION_CONTROL_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "transaction_propagation_control"
            );
        static ref TRANSACTION_PROPAGATION_CONTROL_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "transaction_propagation_control_counter"
            );
        static ref TRANSACTION_DIGESTS_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "transaction_digests"
            );
        static ref TRANSACTION_DIGESTS_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "transaction_digests_counter"
            );
        static ref GET_TRANSACTIONS_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_transactions"
            );
        static ref GET_TRANSACTIONS_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_transactions_counter"
            );
        static ref GET_TRANSACTIONS_RESPONSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_transactions_response"
            );
        static ref GET_TRANSACTIONS_RESPONSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_transactions_response_counter"
            );
        static ref GET_BLOCK_HASHES_BY_EPOCH_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_hashes_by_epoch"
            );
        static ref GET_BLOCK_HASHES_BY_EPOCH_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_hashes_by_epoch_counter"
            );
        static ref GET_BLOCK_HASHES_RESPONSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_hashes_response"
            );
        static ref GET_BLOCK_HASHES_RESPONSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_hashes_response_counter"
            );
        static ref OTHER_HIGH_METER: Arc<Meter> = register_meter_with_group(
            "network_connection_data",
            "other_high_meter"
        );
        static ref OTHER_HIGH_COUNTER: Arc<Meter> = register_meter_with_group(
            "network_connection_data_counter",
            "other_high_meter_counter"
        );
    }
    lazy_static! {
        static ref ON_STATUS_METER: Arc<Meter> =
            register_meter_with_group("network_connection_data", "on_status");
        static ref ON_STATUS_COUNTER: Arc<Meter> = register_meter_with_group(
            "network_connection_data_counter",
            "on_status_counter"
        );
        static ref GET_BLOCK_HEADER_RESPONSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_header_response"
            );
        static ref GET_BLOCK_HEADER_RESPONSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_header_response_counter"
            );
        static ref GET_BLOCK_HEADERS_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_headers"
            );
        static ref GET_BLOCK_HEADERS_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_headers_counter"
            );
        static ref GET_BLOCK_HEADER_CHAIN_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_block_header_chain"
            );
        static ref GET_BLOCK_HEADER_CHAIN_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_header_chain_counter"
            );
        static ref NEW_BLOCK_METER: Arc<Meter> =
            register_meter_with_group("network_connection_data", "new_block");
        static ref NEW_BLOCK_COUNTER: Arc<Meter> = register_meter_with_group(
            "network_connection_data_counter",
            "new_block_counter"
        );
        static ref NEW_BLOCK_HASHES_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "new_block_hashes"
            );
        static ref NEW_BLOCK_HASHES_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "new_block_hashes_counter"
            );
        static ref GET_BLOCKS_RESPONSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_blocks_response"
            );
        static ref GET_BLOCKS_RESPONSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_blocks_response_counter"
            );
        static ref GET_BLOCKS_WITH_PUBLIC_RESPONSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_blocks_with_public_response"
            );
        static ref GET_BLOCKS_WITH_PUBLIC_RESPONSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_blocks_with_public_response_counter"
            );
        static ref GET_BLOCKS_METER: Arc<Meter> =
            register_meter_with_group("network_connection_data", "get_blocks");
        static ref GET_BLOCKS_COUNTER: Arc<Meter> = register_meter_with_group(
            "network_connection_data_counter",
            "get_blocks_counter"
        );
        static ref GET_TERMINAL_BLOCK_HASHES_RESPONSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_terminal_block_hashes_response"
            );
        static ref GET_TERMINAL_BLOCK_HASHES_RESPONSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_terminal_block_hashes_response_counter"
            );
        static ref GET_TERMINAL_BLOCK_HASHES_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_terminal_block_hashes"
            );
        static ref GET_TERMINAL_BLOCK_HASHES_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_terminal_block_hashes_counter"
            );
        static ref TRANSACTIONS_COUNTER: Arc<Meter> = register_meter_with_group(
            "network_connection_data_counter",
            "transactions_counter"
        );
        static ref GET_CMPCT_BLOCKS_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_cmpct_blocks"
            );
        static ref GET_CMPCT_BLOCKS_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_cmpct_blocks_counter"
            );
        static ref GET_CMPCT_BLOCKS_RESPONSE_METER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data",
                "get_cmpct_blocks_response"
            );
        static ref GET_CMPCT_BLOCKS_RESPONSE_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_cmpct_blocks_response_counter"
            );
        static ref GET_BLOCK_TXN_METER: Arc<Meter> = register_meter_with_group(
            "network_connection_data",
            "get_block_txn"
        );
        static ref GET_BLOCK_TXN_COUNTER: Arc<Meter> =
            register_meter_with_group(
                "network_connection_data_counter",
                "get_block_txn_counter"
            );
    }

    pub fn send_message(
        io: &NetworkContext, peer: PeerId, msg: &Message,
        priority: Option<SendQueuePriority>,
    ) -> Result<(), NetworkError>
    {
        send_message_with_throttling(io, peer, msg, priority, false)
    }

    pub fn send_message_with_throttling(
        io: &NetworkContext, peer: PeerId, msg: &Message,
        priority: Option<SendQueuePriority>, throttling_disabled: bool,
    ) -> Result<(), NetworkError>
    {
        let size =
            msg.send_with_throttling(io, peer, priority, throttling_disabled)?;

        if peer != NULL {
            match msg.msg_id().into() {
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
                msgid::TRANSACTION_PROPAGATION_CONTROL => {
                    TRANSACTION_PROPAGATION_CONTROL_METER.mark(size);
                    TRANSACTION_PROPAGATION_CONTROL_COUNTER.mark(1);
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

        Ok(())
    }
}
