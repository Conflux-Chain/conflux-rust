// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use metrics::{register_meter_with_group, Meter};
use std::sync::Arc;

lazy_static! {
    pub static ref TX_HANDLE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync::on_tx_response");
    pub static ref CMPCT_BLOCK_HANDLE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync::on_compact_block");
    pub static ref BLOCK_TXN_HANDLE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync::on_block_txn");
    pub static ref BLOCK_HANDLE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync::on_blocks");
    pub static ref CMPCT_BLOCK_RECOVER_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync:recover_compact_block");
    pub static ref BLOCK_HEADER_HANDLE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync::on_block_headers");
}
