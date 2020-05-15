use crate::{
    evm::{Factory, Spec},
    genesis::initialize_internal_contract_accounts,
    state::State,
    statedb::StateDb,
    storage::{StateIndex, StorageManager, StorageManagerTrait},
    vm_factory::VmFactory,
};
use primitives::EpochId;

pub fn get_state_for_genesis_write(storage_manager: &StorageManager) -> State {
    State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        VmFactory::default(),
        &Spec::new_spec(),
        0, /* block_number */
    )
}

pub fn get_state_for_genesis_write_with_factory(
    storage_manager: &StorageManager, factory: Factory,
) -> State {
    let mut statedb =
        StateDb::new(storage_manager.get_state_for_genesis_write());

    initialize_internal_contract_accounts(&mut statedb);
    let genesis_epoch_id = EpochId::default();
    statedb.commit(genesis_epoch_id).expect(
        // This is a comment to let cargo format the rest in a single line.
        &concat!(file!(), ":", line!(), ":", column!()),
    );

    State::new(
        StateDb::new(
            storage_manager
                .get_state_for_next_epoch(
                    StateIndex::new_for_test_only_delta_mpt(&genesis_epoch_id),
                )
                .expect(&concat!(file!(), ":", line!(), ":", column!()))
                // Unwrap is safe because Genesis state exists.
                .unwrap(),
        ),
        factory.into(),
        &Spec::new_spec(),
        0, /* block_number */
    )
}
