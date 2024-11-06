// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Default)]
pub struct RpcImplConfiguration {
    pub get_logs_filter_max_limit: Option<usize>,
    /// If it's `true`, `DEFERRED_STATE_EPOCH_COUNT` blocks are generated after
    /// receiving a new tx through RPC calling to pack and execute this
    /// transaction.
    pub dev_pack_tx_immediately: bool,

    // maximum response payload size allowed
    // note: currently we only handle this for `cfx_getEpochReceipts`,
    // other APIs will disconnect on oversized response
    pub max_payload_bytes: usize,

    pub max_estimation_gas_limit: Option<U256>,

    pub enable_metrics: bool,

    pub poll_lifetime_in_seconds: Option<u32>,
}

pub mod cfx;
pub mod eth;
pub mod pos;

pub use cfx::{cfx_filter, common, light, pool, pubsub};
pub use cfx_rpc_cfx_types::FeeHistoryCacheEntry;
use cfx_types::U256;
pub use eth::{debug, eth_filter, eth_handler::EthHandler, eth_pubsub};
