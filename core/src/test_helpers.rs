use crate::{
    evm::Factory,
    state::{CleanupMode, State, Substate},
    statedb::StateDb,
    storage::{
        new_storage_manager_for_testing, state::StateTrait, StorageManager,
        StorageManagerTrait,
    },
    vm::EnvInfo,
    vm_factory::VmFactory,
};

pub fn get_state_for_genesis_write(storage_manager: &StorageManager) -> State {
    State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        0.into(),
        VmFactory::default(),
    )
}

pub fn get_state_for_genesis_write_with_factory(
    storage_manager: &StorageManager, factory: Factory,
) -> State {
    State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        0.into(),
        factory.into(),
    )
}
