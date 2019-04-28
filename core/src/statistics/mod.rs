use crate::{consensus::ConsensusGraphStatistics, sync::SyncGraphStatistics};
use parking_lot::RwLock;
use std::sync::Arc;

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
}
