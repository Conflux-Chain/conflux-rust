use crate::{
    evm::Factory,
    state::State,
    statedb::StateDb,
    storage::{StorageManager, StorageManagerTrait},
    vm_factory::VmFactory,
};

pub fn get_state_for_genesis_write(storage_manager: &StorageManager) -> State {
    State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        0.into(), /* nonce */
        VmFactory::default(),
    )
}

pub fn get_state_for_genesis_write_with_factory(
    storage_manager: &StorageManager, factory: Factory,
) -> State {
    State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        0.into(), /* nonce */
        factory.into(),
    )
}
