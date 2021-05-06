// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Default)]
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
}

pub mod cfx;
pub mod common;
pub mod light;
pub mod pubsub;
pub mod trace;
