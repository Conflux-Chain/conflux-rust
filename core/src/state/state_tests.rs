// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{CleanupMode, CollateralCheckResult, State, Substate};

use crate::{
    parameters::staking::*,
    statedb::StateDb,
    storage::{
        tests::new_state_manager_for_unit_test, StateIndex, StorageManager,
        StorageManagerTrait,
    },
    vm_factory::VmFactory,
};
use cfx_types::{Address, BigEndianHash, H256, U256};
use primitives::{EpochId, StorageLayout};

fn get_state(storage_manager: &StorageManager, epoch_id: EpochId) -> State {
    State::new(
        StateDb::new(
            storage_manager
                .get_state_for_next_epoch(
                    StateIndex::new_for_test_only_delta_mpt(&epoch_id),
                )
                .unwrap()
                .unwrap(),
        ),
        VmFactory::default(),
        0, /* block_number */
    )
}

fn get_state_for_genesis_write(storage_manager: &StorageManager) -> State {
    State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        VmFactory::default(),
        0, /* block_number */
    )
}

#[test]
fn checkpoint_basic() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let address = Address::zero();
    state.checkpoint();
    state
        .add_balance(&address, &U256::from(1069u64), CleanupMode::NoEmpty)
        .unwrap();
    state
        .add_collateral_for_storage(&address, &U256::from(1000))
        .unwrap();
    assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(*state.total_storage_tokens(), U256::from(1000));
    state.discard_checkpoint();
    assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
    state.checkpoint();
    state
        .add_balance(&address, &U256::from(1u64), CleanupMode::NoEmpty)
        .unwrap();
    state
        .sub_collateral_for_storage(&address, &U256::from(1000))
        .unwrap();
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0)
    );
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.balance(&address).unwrap(), U256::from(1070u64));
    state.revert_to_checkpoint();
    assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(*state.total_storage_tokens(), U256::from(1000));
}

#[test]
fn checkpoint_nested() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let address = Address::zero();
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.balance(&address).unwrap(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0)
    );
    state.checkpoint();
    state.checkpoint();
    state
        .add_balance(&address, &U256::from(1069u64), CleanupMode::NoEmpty)
        .unwrap();
    state
        .add_collateral_for_storage(&address, &U256::from(1000))
        .unwrap();
    assert_eq!(*state.total_storage_tokens(), U256::from(1000));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
    state.discard_checkpoint();
    assert_eq!(*state.total_storage_tokens(), U256::from(1000));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
    state.revert_to_checkpoint();
    assert_eq!(state.balance(&address).unwrap(), U256::from(0));
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0)
    );
}

#[test]
fn checkpoint_revert_to_get_storage_at() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let address = Address::zero();
    let key = BigEndianHash::from_uint(&U256::from(0));
    let c0 = state.checkpoint();
    let c1 = state.checkpoint();
    state
        .set_storage(
            &address,
            key,
            BigEndianHash::from_uint(&U256::from(1)),
            address,
        )
        .unwrap();

    assert_eq!(
        state.checkpoint_storage_at(c0, &address, &key).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &address, &key).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.storage_at(&address, &key).unwrap(),
        BigEndianHash::from_uint(&U256::from(1))
    );

    state.revert_to_checkpoint();
    assert_eq!(
        state.checkpoint_storage_at(c0, &address, &key).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.storage_at(&address, &key).unwrap(),
        BigEndianHash::from_uint(&U256::from(0))
    );
}

#[test]
fn checkpoint_from_empty_get_storage_at() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut substate = Substate::new();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let a = Address::zero();
    let sponsor = Address::random();
    let k = BigEndianHash::from_uint(&U256::from(0));
    let k2 = BigEndianHash::from_uint(&U256::from(1));

    assert_eq!(
        state.storage_at(&a, &k).unwrap(),
        BigEndianHash::from_uint(&U256::from(0))
    );
    state.clear();

    let c0 = state.checkpoint();
    state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
    state
        .set_sponsor_for_collateral(
            &a,
            &sponsor,
            &(*COLLATERAL_PER_STORAGE_KEY * U256::from(2)),
        )
        .unwrap();
    assert_eq!(
        state
            .sponsor_for_collateral(&a)
            .unwrap()
            .unwrap_or_default(),
        sponsor
    );
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    let c1 = state.checkpoint();
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(1)), a)
        .unwrap();
    let c2 = state.checkpoint();
    let c3 = state.checkpoint();
    state
        .set_storage(&a, k2, BigEndianHash::from_uint(&U256::from(3)), a)
        .unwrap();
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(3)), a)
        .unwrap();
    let c4 = state.checkpoint();
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(4)), a)
        .unwrap();
    let c5 = state.checkpoint();

    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(3)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c5, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(4)))
    );

    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // Commit/discard c5.
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(3)))
    );

    state.revert_to_checkpoint(); // Revert to c4.
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );

    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // Commit/discard c3.
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );

    state.revert_to_checkpoint(); // Revert to c2.
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );

    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // Commit/discard c1.
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
}

#[test]
fn checkpoint_get_storage_at() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut substate = Substate::new();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let a = Address::zero();
    let sponsor = Address::random();
    let k = BigEndianHash::from_uint(&U256::from(0));
    let k2 = BigEndianHash::from_uint(&U256::from(1));

    state.checkpoint();
    state
        .add_balance(
            &a,
            &(*COLLATERAL_PER_STORAGE_KEY * U256::from(2)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(
        state.balance(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );

    // make sure strorage layout is present
    // (normally inserted during contract creation)
    state
        .set_storage_layout(&a, StorageLayout::Regular(0))
        .expect("should be able to set storage layout");

    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(0xffff)), a)
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(state.balance(&a).unwrap(), *COLLATERAL_PER_STORAGE_KEY,);
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    state
        .commit(BigEndianHash::from_uint(&U256::from(1u64)))
        .unwrap();
    state.clear();

    state = get_state(
        &storage_manager,
        BigEndianHash::from_uint(&U256::from(1u64)),
    );
    assert_eq!(
        state.storage_at(&a, &k).unwrap(),
        BigEndianHash::from_uint(&U256::from(0xffff))
    );
    assert_eq!(
        state.balance(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(1),
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    state.clear();

    let cm1 = state.checkpoint();
    let c0 = state.checkpoint();
    state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
    state
        .set_sponsor_for_collateral(
            &a,
            &sponsor,
            &(*COLLATERAL_PER_STORAGE_KEY * U256::from(2)),
        )
        .unwrap();
    assert_eq!(
        state
            .sponsor_for_collateral(&a)
            .unwrap()
            .unwrap_or_default(),
        sponsor
    );
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0),);
    let c1 = state.checkpoint();
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(1)), a)
        .unwrap();
    let c2 = state.checkpoint();
    let c3 = state.checkpoint();
    state
        .set_storage(&a, k2, BigEndianHash::from_uint(&U256::from(3)), a)
        .unwrap();
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(3)), a)
        .unwrap();
    let c4 = state.checkpoint();
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(4)), a)
        .unwrap();
    let c5 = state.checkpoint();

    assert_eq!(
        state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(3)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c5, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(4)))
    );

    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // Commit/discard c5.
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(3)))
    );

    state.revert_to_checkpoint(); // Revert to c4.
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );

    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // Commit/discard c3.

    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(1)))
    );

    state.revert_to_checkpoint(); // Revert to c2.
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0)))
    );

    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // Commit/discard c1.
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(BigEndianHash::from_uint(&U256::from(0xffff)))
    );
}

#[test]
fn kill_account_with_checkpoints() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let a = Address::zero();
    let k = BigEndianHash::from_uint(&U256::from(0));
    state.checkpoint();
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(1)), a)
        .unwrap();
    state.checkpoint();
    state.kill_account(&a);

    assert_eq!(
        state.storage_at(&a, &k).unwrap(),
        BigEndianHash::from_uint(&U256::from(0))
    );
    state.revert_to_checkpoint();
    assert_eq!(
        state.storage_at(&a, &k).unwrap(),
        BigEndianHash::from_uint(&U256::from(1))
    );
}

#[test]
fn create_contract_fail() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut substate = Substate::new();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let a = Address::from_low_u64_be(1000);

    state.checkpoint(); // c1
    state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
    state
        .add_balance(&a, &U256::from(1), CleanupMode::ForceCreate)
        .unwrap();
    state.checkpoint(); // c2
    state
        .add_balance(&a, &U256::from(1), CleanupMode::ForceCreate)
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // discard c2
    state.revert_to_checkpoint(); // revert to c1
    assert_eq!(state.exists(&a).unwrap(), false);

    state
        .commit(BigEndianHash::from_uint(&U256::from(1)))
        .unwrap();
}

#[test]
fn create_contract_fail_previous_storage() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut substate = Substate::new();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let a = Address::from_low_u64_be(1000);
    let k = BigEndianHash::from_uint(&U256::from(0));

    state.checkpoint();
    state
        .add_balance(&a, &COLLATERAL_PER_STORAGE_KEY, CleanupMode::NoEmpty)
        .unwrap();
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(state.balance(&a).unwrap(), *COLLATERAL_PER_STORAGE_KEY);

    // make sure strorage layout is present
    // (normally inserted during contract creation)
    state
        .set_storage_layout(&a, StorageLayout::Regular(0))
        .expect("should be able to set storage layout");

    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(0xffff)), a)
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a).unwrap(), U256::from(0));
    state
        .commit(BigEndianHash::from_uint(&U256::from(1)))
        .unwrap();
    state.clear();

    assert_eq!(
        state.storage_at(&a, &k).unwrap(),
        BigEndianHash::from_uint(&U256::from(0xffff))
    );
    state.clear();
    state =
        get_state(&storage_manager, BigEndianHash::from_uint(&U256::from(1)));
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a).unwrap(), U256::from(0));

    state.checkpoint(); // c1
    state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
    state.checkpoint(); // c2
    state
        .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(2)), a)
        .unwrap();
    state.revert_to_checkpoint(); // revert to c2
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0),);
    assert_eq!(state.balance(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.storage_at(&a, &k).unwrap(),
        BigEndianHash::from_uint(&U256::from(0))
    );
    state.revert_to_checkpoint(); // revert to c1
    assert_eq!(
        state.storage_at(&a, &k).unwrap(),
        BigEndianHash::from_uint(&U256::from(0xffff))
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a).unwrap(), U256::from(0));

    state
        .commit(BigEndianHash::from_uint(&U256::from(2)))
        .unwrap();
}

#[test]
fn test_automatic_collateral_normal_account() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut substate = Substate::new();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let normal_account = Address::from_low_u64_be(0);
    let contract_account = Address::from_low_u64_be(1);
    let k1: H256 = BigEndianHash::from_uint(&U256::from(0));
    let k2: H256 = BigEndianHash::from_uint(&U256::from(1));
    let k3: H256 = BigEndianHash::from_uint(&U256::from(3));

    state
        .add_balance(
            &normal_account,
            &(*COLLATERAL_PER_STORAGE_KEY * U256::from(2)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .new_contract(
            &contract_account,
            *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
            U256::zero(),
        )
        .unwrap();

    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&normal_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.balance(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.balance(&contract_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );

    // simple set one key with zero value for normal account
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k1,
            BigEndianHash::from_uint(&U256::from(0)),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &normal_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();

    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&normal_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.balance(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.balance(&contract_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );

    // simple set one key with nonzero value for normal account
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k1,
            BigEndianHash::from_uint(&U256::from(1)),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &normal_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.balance(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );

    // test not sufficient balance
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k2,
            BigEndianHash::from_uint(&U256::from(1)),
            normal_account,
        )
        .unwrap();
    state
        .set_storage(
            &contract_account,
            k3,
            BigEndianHash::from_uint(&U256::from(1)),
            normal_account,
        )
        .unwrap();
    assert_ne!(
        state
            .check_collateral_for_storage_finally(
                &normal_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.revert_to_checkpoint();
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.balance(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );

    // use all balance
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k2,
            BigEndianHash::from_uint(&U256::from(1)),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &normal_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.collateral_for_storage(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(state.balance(&normal_account).unwrap(), U256::from(0));

    // set one key to zero
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k2,
            BigEndianHash::from_uint(&U256::from(0)),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &normal_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.balance(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    // set another key to zero
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k1,
            BigEndianHash::from_uint(&U256::from(0)),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &normal_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&normal_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.balance(&normal_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
}

#[test]
fn test_automatic_collateral_contract_account() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut substate = Substate::new();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let contract_account = Address::from_low_u64_be(1);
    let sponsor = Address::random();
    let k1: H256 = BigEndianHash::from_uint(&U256::from(0));
    let k2: H256 = BigEndianHash::from_uint(&U256::from(1));
    let k3: H256 = BigEndianHash::from_uint(&U256::from(3));

    state
        .new_contract(&contract_account, U256::zero(), U256::zero())
        .unwrap();
    state
        .set_sponsor_for_collateral(
            &contract_account,
            &sponsor,
            &(*COLLATERAL_PER_STORAGE_KEY * U256::from(2)),
        )
        .unwrap();
    assert_eq!(
        state
            .sponsor_for_collateral(&contract_account)
            .unwrap()
            .unwrap_or_default(),
        sponsor
    );
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(state.balance(&contract_account).unwrap(), U256::from(0));
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&contract_account)
            .unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );

    // simple set one key with zero value for contract account
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k1,
            BigEndianHash::from_uint(&U256::from(0)),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &contract_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0),
    );
    assert_eq!(state.balance(&contract_account).unwrap(), U256::from(0));
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&contract_account)
            .unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );

    // simple set one key with nonzero value for contract account
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k1,
            BigEndianHash::from_uint(&U256::from(1)),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &contract_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(state.balance(&contract_account).unwrap(), U256::from(0));
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&contract_account)
            .unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);

    // test not sufficient balance
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k2,
            BigEndianHash::from_uint(&U256::from(1)),
            contract_account,
        )
        .unwrap();
    state
        .set_storage(
            &contract_account,
            k3,
            BigEndianHash::from_uint(&U256::from(1)),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &contract_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::NotEnoughBalance {
            required: *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
            got: *COLLATERAL_PER_STORAGE_KEY,
        }
    );

    state.revert_to_checkpoint();

    assert_eq!(state.balance(&contract_account).unwrap(), U256::from(0));
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&contract_account)
            .unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);

    // use all balance
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k2,
            BigEndianHash::from_uint(&U256::from(1)),
            contract_account,
        )
        .unwrap();

    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &contract_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid,
    );
    state.discard_checkpoint();
    assert_eq!(state.balance(&contract_account).unwrap(), U256::from(0));
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&contract_account)
            .unwrap(),
        U256::from(0)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );

    // set one key to zero
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k2,
            BigEndianHash::from_uint(&U256::from(0)),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &contract_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(state.balance(&contract_account).unwrap(), U256::from(0));
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&contract_account)
            .unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.increase_block_number(), U256::from(39637239));

    // set another key to zero
    state.checkpoint();
    state
        .set_storage(
            &contract_account,
            k1,
            BigEndianHash::from_uint(&U256::from(0)),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage_finally(
                &contract_account,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(state.balance(&contract_account).unwrap(), U256::from(0));
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&contract_account)
            .unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_account).unwrap(),
        U256::from(0)
    );
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.increase_block_number(), U256::from(0));
}
