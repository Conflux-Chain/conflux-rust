use metrics::{register_meter_with_group, Gauge, GaugeUsize, Lock, Meter};
use std::sync::Arc;

// Metrics for transaction pool.
lazy_static! {
    pub static ref TX_POOL_DEFERRED_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_deferred_txs");
    pub static ref TX_POOL_UNPACKED_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_unpacked_txs");
    pub static ref TX_POOL_READY_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_ready_accounts");
    pub static ref INSERT_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_tps");
    pub static ref INSERT_TXS_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_tps");
    pub static ref INSERT_TXS_SUCCESS_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_success_tps");
    pub static ref INSERT_TXS_FAILURE_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_failure_tps");
    pub static ref TX_POOL_INSERT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::insert_new_tx");
    pub static ref TX_POOL_VERIFY_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::verify");
    pub static ref TX_POOL_GET_STATE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::get_state");
    pub static ref INSERT_TXS_QUOTA_LOCK: Lock =
        Lock::register("txpool_insert_txs_quota_lock");
    pub static ref INSERT_TXS_ENQUEUE_LOCK: Lock =
        Lock::register("txpool_insert_txs_enqueue_lock");
    pub static ref PACK_TRANSACTION_LOCK: Lock =
        Lock::register("txpool_pack_transactions");
    pub static ref NOTIFY_BEST_INFO_LOCK: Lock =
        Lock::register("txpool_notify_best_info");
    pub static ref NOTIFY_MODIFIED_LOCK: Lock =
        Lock::register("txpool_notify_modified_info");
}

// Metrics for transaction pool inner.
pub mod pool_inner_metrics {
    use metrics::{register_meter_with_group, Counter, CounterUsize, Meter};
    use std::sync::Arc;

    lazy_static! {
        pub static ref TX_POOL_RECALCULATE: Arc<dyn Meter> =
            register_meter_with_group("timer", "tx_pool::recalculate");
        pub static ref TX_POOL_INNER_INSERT_TIMER: Arc<dyn Meter> =
            register_meter_with_group("timer", "tx_pool::inner_insert");
        pub static ref DEFERRED_POOL_INNER_INSERT: Arc<dyn Meter> =
            register_meter_with_group("timer", "deferred_pool::inner_insert");
        pub static ref TX_POOL_GET_STATE_TIMER: Arc<dyn Meter> =
            register_meter_with_group(
                "timer",
                "tx_pool::get_nonce_and_storage"
            );
        pub static ref TX_POOL_INNER_WITHOUTCHECK_INSERT_TIMER: Arc<dyn Meter> =
            register_meter_with_group(
                "timer",
                "tx_pool::inner_without_check_inert"
            );
        pub static ref GC_UNEXECUTED_COUNTER: Arc<dyn Counter<usize>> =
            CounterUsize::register_with_group("txpool", "gc_unexecuted");
        pub static ref GC_READY_COUNTER: Arc<dyn Counter<usize>> =
            CounterUsize::register_with_group("txpool", "gc_ready");
        pub static ref GC_METER: Arc<dyn Meter> =
            register_meter_with_group("txpool", "gc_txs_tps");
    }
}
