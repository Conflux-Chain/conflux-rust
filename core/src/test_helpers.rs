use crate::{
    evm::Spec, spec::genesis::initialize_internal_contract_accounts,
    state::State,
};
use cfx_state::StateTrait;
use cfx_statedb::StateDb;
use cfx_storage::{StateIndex, StorageManager, StorageManagerTrait};
use primitives::EpochId;
use std::sync::Arc;

pub fn get_state_for_genesis_write(
    storage_manager: &Arc<StorageManager>,
) -> State {
    let mut state =
        State::new(StateDb::new(storage_manager.get_state_for_genesis_write()))
            .expect("Failed to initialize state");

    initialize_internal_contract_accounts(
        &mut state,
        Spec::new_spec().contract_start_nonce(/* block_number = */ 0),
    );
    let genesis_epoch_id = EpochId::default();
    state
        .commit(genesis_epoch_id, /* debug_record = */ None)
        .expect(
            // This is a comment to let cargo format the rest in a single line.
            &concat!(file!(), ":", line!(), ":", column!()),
        );

    State::new(StateDb::new(
        storage_manager
            .get_state_for_next_epoch(StateIndex::new_for_test_only_delta_mpt(
                &genesis_epoch_id,
            ))
            .expect(&concat!(file!(), ":", line!(), ":", column!()))
            // Unwrap is safe because Genesis state exists.
            .unwrap(),
    ))
    .expect("Failed to initialize state")
}
