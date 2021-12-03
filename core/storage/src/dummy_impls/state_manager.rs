use super::{
    config::storage_manager::StorageConfiguration, state::State,
    state_index::StateIndex, state_trait::StateManagerTrait,
};
use crate::{Result, SnapshotInfo};
use cfx_internal_common::{
    consensus_api::StateMaintenanceTrait, StateAvailabilityBoundary,
};
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use primitives::{EpochId, MerkleHash};
use std::sync::Arc;

#[derive(MallocSizeOfDerive)]
pub struct StateManager {
    snapshot_epoch_count: u32,
}

impl StateManager {
    pub fn get_storage_manager(&self) -> &StateManager { &*self }

    pub fn new(conf: StorageConfiguration) -> Result<Self> {
        Ok(Self {
            snapshot_epoch_count: conf.snapshot_epoch_count,
        })
    }

    pub fn new_arc(storage_conf: StorageConfiguration) -> Result<Arc<Self>> {
        Ok(Arc::new(Self::new(storage_conf)?))
    }

    pub fn get_snapshot_epoch_count(&self) -> u32 { self.snapshot_epoch_count }

    pub fn maintain_state_confirmed<ConsensusInner: StateMaintenanceTrait>(
        &self, consensus_inner: &ConsensusInner, stable_checkpoint_height: u64,
        era_epoch_count: u64, confirmed_height: u64,
        state_availability_boundary: &RwLock<StateAvailabilityBoundary>,
    ) -> Result<()>
    {
        todo!()
    }

    pub fn get_snapshot_info_at_epoch(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<SnapshotInfo> {
        todo!()
    }

    pub fn log_usage(&self) {}
}

impl StateManagerTrait for StateManager {
    fn get_state_no_commit(
        self: &Arc<Self>, epoch_id: StateIndex, try_open: bool,
    ) -> Result<Option<State>> {
        todo!()
    }

    fn get_state_for_next_epoch(
        self: &Arc<Self>, parent_epoch_id: StateIndex,
    ) -> Result<Option<State>> {
        todo!()
    }

    fn get_state_for_genesis_write(self: &Arc<Self>) -> State { todo!() }
}
