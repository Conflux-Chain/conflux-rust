use cfx_storage_primitives::dummy::StateRootWithAuxInfo;
use primitives::EpochId;

pub struct StateIndex;

impl StateIndex {
    pub fn new_for_readonly(
        epoch_id: &EpochId, state_root: &StateRootWithAuxInfo,
    ) -> Self {
        todo!()
    }

    pub fn new_for_next_epoch(
        base_epoch_id: &EpochId, state_root: &StateRootWithAuxInfo,
        height: u64, snapshot_epoch_count: u32,
    ) -> Self
    {
        todo!()
    }
}
