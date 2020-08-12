use crate::{
    evm::{Factory, Spec},
    genesis::initialize_internal_contract_accounts,
    state::State,
    statedb::StateDb,
};
use cfx_storage::{StateIndex, StorageManager, StorageManagerTrait};
use primitives::EpochId;
use std::sync::Arc;

pub fn get_state_for_genesis_write(
    storage_manager: &Arc<StorageManager>,
) -> State {
    get_state_for_genesis_write_with_factory(
        storage_manager,
        Factory::default(),
    )
}

pub fn get_state_for_genesis_write_with_factory(
    storage_manager: &Arc<StorageManager>, factory: Factory,
) -> State {
    let mut state = State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        factory.clone().into(),
        &Spec::new_spec(),
        0, /* block_number */
    );

    initialize_internal_contract_accounts(&mut state);
    let genesis_epoch_id = EpochId::default();
    state
        .commit(genesis_epoch_id, /* debug_record = */ None)
        .expect(
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
        1, /* block_number */
    )
}
