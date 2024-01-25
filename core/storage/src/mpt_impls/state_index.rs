use cfx_storage_primitives::mpt::StateRootWithAuxInfo;
use primitives::EpochId;

#[derive(Debug)]
pub struct StateIndex {
    pub epoch_id: EpochId,
    pub height: Option<u64>,
    pub state_root: StateRootWithAuxInfo,
}

impl StateIndex {
    pub fn new_for_readonly(
        epoch_id: &EpochId, state_root: &StateRootWithAuxInfo,
    ) -> Self {
        StateIndex {
            epoch_id: epoch_id.clone(),
            height: None,
            state_root: state_root.clone(),
        }
    }

    pub fn new_for_next_epoch(
        base_epoch_id: &EpochId, state_root: &StateRootWithAuxInfo,
        height: u64, _snapshot_epoch_count: u32,
    ) -> Self
    {
        StateIndex {
            epoch_id: base_epoch_id.clone(),
            height: Some(height),
            state_root: state_root.clone(),
        }
    }

    pub(crate) fn is_read_only(&self) -> bool { self.height.is_none() }
}
