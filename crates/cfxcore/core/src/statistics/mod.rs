use crate::{consensus::ConsensusGraphStatistics, sync::SyncGraphStatistics};
use metrics::{Gauge, GaugeUsize};
use parking_lot::RwLock;
use std::sync::Arc;
lazy_static! {
    static ref SYNC_INSERTED_HEADER_COUNT: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "graph_statistic",
            "sync_graph_inserted_header_count"
        );
    static ref SYNC_INSERTED_BLOCK_COUNT: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "graph_statistic",
            "sync_graph_inserted_block_count"
        );
    static ref CONSENSUS_INSERTED_BLOCK_COUNT: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "graph_statistic",
            "consensus_graph_inserted_header_count"
        );
}

pub type SharedStatistics = Arc<Statistics>;

#[derive(Debug)]
pub struct StatisticsInner {
    pub sync_graph: SyncGraphStatistics,
    pub consensus_graph: ConsensusGraphStatistics,
}

impl StatisticsInner {
    pub fn new() -> Self {
        StatisticsInner {
            sync_graph: SyncGraphStatistics::new(),
            consensus_graph: ConsensusGraphStatistics::new(),
        }
    }
}

pub struct Statistics {
    pub inner: RwLock<StatisticsInner>,
}

impl Statistics {
    pub fn new() -> Self {
        Statistics {
            inner: RwLock::new(StatisticsInner::new()),
        }
    }

    pub fn inc_sync_graph_inserted_block_count(&self) {
        let mut inner = self.inner.write();
        inner.sync_graph.inserted_block_count += 1;
        SYNC_INSERTED_BLOCK_COUNT.update(inner.sync_graph.inserted_block_count)
    }

    pub fn inc_sync_graph_inserted_header_count(&self) {
        let mut inner = self.inner.write();
        inner.sync_graph.inserted_header_count += 1;
        SYNC_INSERTED_HEADER_COUNT
            .update(inner.sync_graph.inserted_header_count)
    }

    pub fn inc_consensus_graph_processed_block_count(&self) {
        self.inner.write().consensus_graph.processed_block_count += 1;
    }

    pub fn inc_consensus_graph_activated_block_count(&self) {
        self.inner.write().consensus_graph.activated_block_count += 1;
    }

    pub fn set_consensus_graph_inserted_block_count(&self, count: usize) {
        let mut inner = self.inner.write();
        inner.consensus_graph.inserted_block_count = count;
        CONSENSUS_INSERTED_BLOCK_COUNT
            .update(inner.consensus_graph.inserted_block_count)
    }

    pub fn get_consensus_graph_processed_block_count(&self) -> usize {
        self.inner.read().consensus_graph.processed_block_count
    }

    pub fn clear_sync_and_consensus_graph_statistics(&self) {
        let mut inner = self.inner.write();
        inner.sync_graph.clear();
        inner.consensus_graph.clear();
    }

    pub fn log_statistics(&self) {
        let inner = self.inner.read();
        info!("Statistics: {:?}", *inner);
    }
}
