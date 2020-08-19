// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{CleanupMode, CollateralCheckResult, State, Substate};

use crate::{
    genesis::DEV_GENESIS_KEY_PAIR, statedb::StateDb,
    test_helpers::get_state_for_genesis_write, vm::Spec, vm_factory::VmFactory,
};
use cfx_parameters::{consensus::ONE_CFX_IN_DRIP, staking::*};
use cfx_storage::{
    tests::new_state_manager_for_unit_test, StateIndex, StorageManager,
    StorageManagerTrait,
};
use cfx_types::{address_util::AddressUtil, Address, BigEndianHash, U256};
use keccak_hash::{keccak, KECCAK_EMPTY};
use primitives::{EpochId, StorageKey, StorageLayout};
use std::sync::Arc;

fn get_state(
    storage_manager: &Arc<StorageManager>, epoch_id: &EpochId,
) -> State {
    State::new(
        StateDb::new(
            storage_manager
                .get_state_for_next_epoch(
                    StateIndex::new_for_test_only_delta_mpt(epoch_id),
                )
                .unwrap()
                .unwrap(),
        ),
        VmFactory::default(),
        &Spec::new_spec(),
        0, /* block_number */
    )
}

fn u256_to_vec(val: &U256) -> Vec<u8> {
    let mut key = vec![0; 32];
    val.to_big_endian(key.as_mut());
    key
}

#[test]
fn checkpoint_basic() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut address = Address::zero();
    address.set_user_account_type_bits();
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
    let mut address = Address::zero();
    address.set_user_account_type_bits();
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
    let mut address = Address::zero();
    address.set_contract_type_bits();
    let key = u256_to_vec(&U256::from(0));
    let c0 = state.checkpoint();
    let c1 = state.checkpoint();
    state
        .new_contract(&address, U256::zero(), U256::one())
        .unwrap();
    state
        .set_storage(&address, key.clone(), U256::one(), address)
        .unwrap();

    assert_eq!(
        state.checkpoint_storage_at(c0, &address, &key).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &address, &key).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(state.storage_at(&address, &key).unwrap(), U256::one());

    state.revert_to_checkpoint();
    assert_eq!(
        state.checkpoint_storage_at(c0, &address, &key).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(state.storage_at(&address, &key).unwrap(), U256::zero());
}

#[test]
fn checkpoint_from_empty_get_storage_at() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut a = Address::zero();
    a.set_contract_type_bits();
    let sponsor = Address::random();
    let k = u256_to_vec(&U256::from(0));
    let k2 = u256_to_vec(&U256::from(1));

    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    state.clear();

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

    let c0 = state.checkpoint();
    substates.push(Substate::new());
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
    substates.push(Substate::new());
    state.set_storage(&a, k.clone(), U256::one(), a).unwrap();
    let c2 = state.checkpoint();
    substates.push(Substate::new());
    let c3 = state.checkpoint();
    substates.push(Substate::new());
    state.set_storage(&a, k2.clone(), U256::from(3), a).unwrap();
    state.set_storage(&a, k.clone(), U256::from(3), a).unwrap();
    let c4 = state.checkpoint();
    substates.push(Substate::new());
    state.set_storage(&a, k.clone(), U256::from(4), a).unwrap();
    let c5 = state.checkpoint();
    substates.push(Substate::new());

    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a, &k).unwrap(),
        Some(U256::from(3))
    );
    assert_eq!(
        state.checkpoint_storage_at(c5, &a, &k).unwrap(),
        Some(U256::from(4))
    );

    assert_eq!(
        state
            .collect_and_settle_collateral(
                &a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint(); // Commit/discard c5.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a, &k).unwrap(),
        Some(U256::from(3))
    );

    state.revert_to_checkpoint(); // Revert to c4.
    substates.pop();
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a, &k).unwrap(),
        Some(U256::one())
    );

    assert_eq!(
        state
            .collect_and_settle_collateral(
                &a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );

    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint(); // Commit/discard c3.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a, &k).unwrap(),
        Some(U256::one())
    );

    state.revert_to_checkpoint(); // Revert to c2.
    substates.pop();
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(c0, &a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a, &k).unwrap(),
        Some(U256::zero())
    );

    assert_eq!(
        state
            .collect_and_settle_collateral(
                &a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint(); // Commit/discard c1.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
        Some(U256::zero())
    );
}

#[test]
fn checkpoint_get_storage_at() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut a = Address::zero();
    a.set_user_account_type_bits();
    let mut contract_a = Address::zero();
    contract_a.set_contract_type_bits();
    let sponsor = Address::random();
    let k = u256_to_vec(&U256::from(0));
    let k2 = u256_to_vec(&U256::from(1));

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

    state.checkpoint();
    substates.push(Substate::new());
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

    state
        .new_contract(&contract_a, U256::zero(), U256::zero())
        .unwrap();

    state
        .set_storage(&contract_a, k.clone(), U256::from(0xffff), a)
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(state.balance(&a).unwrap(), *COLLATERAL_PER_STORAGE_KEY,);
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    state
        .commit(BigEndianHash::from_uint(&U256::from(1u64)), None)
        .unwrap();
    state.clear();
    substates.clear();
    substates.push(Substate::new());

    state = get_state(
        &storage_manager,
        &BigEndianHash::from_uint(&U256::from(1u64)),
    );
    assert_eq!(
        state.storage_at(&contract_a, &k).unwrap(),
        U256::from(0xffff)
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
    substates.clear();
    substates.push(Substate::new());
    let cm1 = state.checkpoint();
    substates.push(Substate::new());
    let c0 = state.checkpoint();
    substates.push(Substate::new());
    state
        .new_contract(&contract_a, U256::zero(), U256::zero())
        .unwrap();
    state
        .set_sponsor_for_collateral(
            &contract_a,
            &sponsor,
            &(*COLLATERAL_PER_STORAGE_KEY * U256::from(2)),
        )
        .unwrap();
    assert_eq!(
        state
            .sponsor_for_collateral(&contract_a)
            .unwrap()
            .unwrap_or_default(),
        sponsor
    );
    assert_eq!(state.balance(&contract_a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&contract_a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&contract_a).unwrap(),
        U256::zero(),
    );
    let c1 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(&contract_a, k.clone(), U256::one(), contract_a)
        .unwrap();
    let c2 = state.checkpoint();
    substates.push(Substate::new());
    let c3 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(&contract_a, k2.clone(), U256::from(3), contract_a)
        .unwrap();
    state
        .set_storage(&contract_a, k.clone(), U256::from(3), contract_a)
        .unwrap();
    let c4 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(&contract_a, k.clone(), U256::from(4), contract_a)
        .unwrap();
    let c5 = state.checkpoint();
    substates.push(Substate::new());

    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &contract_a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &contract_a, &k).unwrap(),
        Some(U256::from(3))
    );
    assert_eq!(
        state.checkpoint_storage_at(c5, &contract_a, &k).unwrap(),
        Some(U256::from(4))
    );

    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint(); // Commit/discard c5.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(state.balance(&contract_a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&contract_a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&contract_a).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &contract_a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &contract_a, &k).unwrap(),
        Some(U256::from(3))
    );

    state.revert_to_checkpoint(); // Revert to c4.
    substates.pop();
    assert_eq!(state.balance(&contract_a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&contract_a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&contract_a).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &contract_a, &k).unwrap(),
        Some(U256::one())
    );

    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint(); // Commit/discard c3.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);

    assert_eq!(state.balance(&contract_a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&contract_a).unwrap(),
        U256::from(0)
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a, &k).unwrap(),
        Some(U256::one())
    );

    state.revert_to_checkpoint(); // Revert to c2.
    substates.pop();
    assert_eq!(state.balance(&contract_a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&contract_a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&contract_a).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a, &k).unwrap(),
        Some(U256::zero())
    );

    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint(); // Commit/discard c1.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(state.balance(&contract_a).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&contract_a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a, &k).unwrap(),
        Some(U256::from(0xffff))
    );
}

#[test]
fn kill_account_with_checkpoints() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state_0 = get_state_for_genesis_write(&storage_manager);
    let mut a = Address::zero();
    a.set_contract_type_bits();
    let k = u256_to_vec(&U256::from(0));
    // Need the checkpoint for ownership commitment.
    state_0.checkpoint();
    state_0
        .new_contract(&a, *COLLATERAL_PER_STORAGE_KEY, U256::one())
        .unwrap();
    state_0.set_storage(&a, k.clone(), U256::one(), a).unwrap();
    state_0
        .set_storage_layout(&a, StorageLayout::Regular(0))
        .unwrap();
    // We don't charge the collateral in this test.
    state_0
        .require_exists(&a, /* require_code = */ false)
        .unwrap()
        .commit_ownership_change(&state_0.db, &mut Substate::new())
        .unwrap();
    state_0
        .add_sponsor_balance_for_collateral(&a, &COLLATERAL_PER_STORAGE_KEY)
        .unwrap();
    state_0
        .add_collateral_for_storage(&a, &COLLATERAL_PER_STORAGE_KEY)
        .unwrap();
    state_0.discard_checkpoint();
    let epoch_id_1 = EpochId::from_uint(&U256::from(1));
    state_0
        .commit(epoch_id_1, /* debug_record = */ None)
        .unwrap();

    let mut state = get_state(&storage_manager, &epoch_id_1);
    // Storage before the account is killed.
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::one());
    state.remove_contract(&a).unwrap();
    // The account is killed. The storage should be empty.
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    // The new contract in the same place should have empty storage.
    state.new_contract(&a, U256::zero(), U256::one()).unwrap();
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());

    // Commit the state and repeat the assertion.
    let epoch_id = EpochId::from_uint(&U256::from(2));
    state.commit(epoch_id, /* debug_record = */ None).unwrap();
    let state = get_state(&storage_manager, &epoch_id);
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());

    // Test checkpoint.
    let mut state = get_state(&storage_manager, &epoch_id_1);
    state.checkpoint();
    state.remove_contract(&a).unwrap();
    // The new contract in the same place should have empty storage.
    state.checkpoint();
    state.new_contract(&a, U256::zero(), U256::one()).unwrap();
    // The new contract in the same place should have empty storage.
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    state.revert_to_checkpoint();
    // The account is killed. The storage should be empty.
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    state.revert_to_checkpoint();
    // Storage before the account is killed.
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::one());
}

#[test]
fn check_result_of_simple_payment_to_killed_account() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state_0 = get_state_for_genesis_write(&storage_manager);
    let sender_addr = DEV_GENESIS_KEY_PAIR.address();
    state_0
        .require_or_new_basic_account(&sender_addr)
        .unwrap()
        .add_balance(&ONE_CFX_IN_DRIP.into());
    let mut a = Address::zero();
    a.set_contract_type_bits();
    let code = b"asdf"[..].into();
    let code_hash = keccak(&code);
    let code_key = StorageKey::new_code_key(&a, &code_hash);
    let k = u256_to_vec(&U256::from(0));
    // Need the checkpoint for ownership commitment.
    state_0.checkpoint();
    state_0.new_contract(&a, U256::zero(), U256::one()).unwrap();
    state_0.init_code(&a, code, sender_addr).unwrap();
    state_0
        .set_storage(&a, k.clone(), U256::one(), sender_addr)
        .unwrap();
    state_0
        .set_storage_layout(&a, StorageLayout::Regular(0))
        .unwrap();
    // We don't charge the collateral in this test.
    state_0
        .require_exists(&a, /* require_code = */ false)
        .unwrap()
        .commit_ownership_change(&state_0.db, &mut Substate::new())
        .unwrap();
    state_0
        .add_collateral_for_storage(&sender_addr, &COLLATERAL_PER_STORAGE_KEY)
        .unwrap();
    state_0.discard_checkpoint();
    let epoch_id_1 = EpochId::from_uint(&U256::from(1));
    state_0
        .commit(epoch_id_1, /* debug_record = */ None)
        .unwrap();

    let mut state = get_state(&storage_manager, &epoch_id_1);
    state.remove_contract(&a).unwrap();
    // The account is killed. The storage should be empty.
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    // Transfer balance to the killed account.
    state
        .transfer_balance(&sender_addr, &a, &U256::one(), CleanupMode::NoEmpty)
        .unwrap();
    let epoch_id = EpochId::from_uint(&U256::from(2));
    // Assert that the account has no storage and no code.
    assert_eq!(state.code_hash(&a).unwrap(), Some(KECCAK_EMPTY));
    assert_eq!(state.code(&a).unwrap(), None);
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    state.commit(epoch_id, /* debug_record = */ None).unwrap();

    // Commit the state and assert that the account has no storage and no code.
    let state = get_state(&storage_manager, &epoch_id);
    assert_eq!(state.code_hash(&a).unwrap(), Some(KECCAK_EMPTY));
    assert_eq!(state.code(&a).unwrap(), None);
    assert_eq!(state.db.get_raw(code_key).unwrap(), None);
    assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
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
            .collect_and_settle_collateral(&a, &U256::MAX, &mut substate)
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint(); // discard c2
    state.revert_to_checkpoint(); // revert to c1
    assert_eq!(state.exists(&a).unwrap(), false);

    state
        .commit(BigEndianHash::from_uint(&U256::from(1)), None)
        .unwrap();
}

#[test]
fn create_contract_fail_previous_storage() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut a = Address::from_low_u64_be(1000);
    a.set_user_account_type_bits();
    let mut contract_addr = a;
    contract_addr.set_contract_type_bits();
    let k = u256_to_vec(&U256::from(0));

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

    state.checkpoint();
    substates.push(Substate::new());

    state
        .add_balance(&a, &COLLATERAL_PER_STORAGE_KEY, CleanupMode::NoEmpty)
        .unwrap();
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(state.balance(&a).unwrap(), *COLLATERAL_PER_STORAGE_KEY);

    state
        .new_contract(&contract_addr, U256::zero(), U256::zero())
        .unwrap();
    state
        .set_storage(&contract_addr, k.clone(), U256::from(0xffff), a)
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &a,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );

    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a).unwrap(), U256::zero());
    state
        .commit(BigEndianHash::from_uint(&U256::from(1)), None)
        .unwrap();
    state.clear();
    substates.clear();
    substates.push(Substate::new());

    assert_eq!(
        state.storage_at(&contract_addr, &k).unwrap(),
        U256::from(0xffff)
    );
    state.clear();
    substates.clear();
    substates.push(Substate::new());
    state =
        get_state(&storage_manager, &BigEndianHash::from_uint(&U256::from(1)));
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a).unwrap(), U256::from(0));

    state.checkpoint(); // c1
    substates.push(Substate::new());
    state.remove_contract(&a).unwrap();
    // parking_lot::lock_api::MappedRwLockWriteGuard must be used, so we drop()
    // it.
    drop(state.require_or_new_basic_account(&a).unwrap());
    state
        .new_contract(&contract_addr, U256::zero(), U256::zero())
        .unwrap();
    state.checkpoint(); // c2
    substates.push(Substate::new());
    state
        .set_storage(&contract_addr, k.clone(), U256::from(2), a)
        .unwrap();
    state.revert_to_checkpoint();
    substates.pop(); // revert to c2
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(state.balance(&a).unwrap(), U256::from(0));
    assert_eq!(state.storage_at(&contract_addr, &k).unwrap(), U256::zero());
    state.revert_to_checkpoint();
    substates.pop(); // revert to c1
    assert_eq!(
        state.storage_at(&contract_addr, &k).unwrap(),
        U256::from(0xffff)
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a).unwrap(), U256::from(0));

    state
        .commit(BigEndianHash::from_uint(&U256::from(2)), None)
        .unwrap();
}

#[test]
fn test_automatic_collateral_normal_account() {
    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut normal_account = Address::from_low_u64_be(0);
    normal_account.set_user_account_type_bits();
    let mut contract_account = Address::from_low_u64_be(1);
    contract_account.set_contract_type_bits();
    let k1 = u256_to_vec(&U256::from(0));
    let k2 = u256_to_vec(&U256::from(1));
    let k3 = u256_to_vec(&U256::from(3));

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k1.clone(),
            U256::zero(),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &normal_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);

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
    substates.push(Substate::new());
    state
        .set_storage(&contract_account, k1.clone(), U256::one(), normal_account)
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &normal_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
    substates.push(Substate::new());

    state
        .set_storage(&contract_account, k2.clone(), U256::one(), normal_account)
        .unwrap();
    state
        .set_storage(&contract_account, k3.clone(), U256::one(), normal_account)
        .unwrap();
    assert_ne!(
        state
            .collect_and_settle_collateral(
                &normal_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
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
    substates.push(Substate::new());

    state
        .set_storage(&contract_account, k2.clone(), U256::one(), normal_account)
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &normal_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k2.clone(),
            U256::zero(),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &normal_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k1.clone(),
            U256::zero(),
            normal_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &normal_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
    let mut state = get_state_for_genesis_write(&storage_manager);
    let mut contract_account = Address::from_low_u64_be(1);
    contract_account.set_contract_type_bits();
    let sponsor = Address::random();
    let k1 = u256_to_vec(&U256::from(0));
    let k2 = u256_to_vec(&U256::from(1));
    let k3 = u256_to_vec(&U256::from(3));

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k1.clone(),
            U256::zero(),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    substates.pop();
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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k1.clone(),
            U256::one(),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);

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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k2.clone(),
            U256::one(),
            contract_account,
        )
        .unwrap();
    state
        .set_storage(
            &contract_account,
            k3.clone(),
            U256::one(),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::NotEnoughBalance {
            required: *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
            got: *COLLATERAL_PER_STORAGE_KEY,
        }
    );

    state.revert_to_checkpoint();
    substates.pop();

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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k2.clone(),
            U256::one(),
            contract_account,
        )
        .unwrap();

    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid,
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k2.clone(),
            U256::zero(),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_account,
            k1.clone(),
            U256::zero(),
            contract_account,
        )
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &contract_account,
                &U256::MAX,
                &mut substates.last_mut().unwrap()
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state
        .collect_ownership_changed(&mut substates.last_mut().unwrap())
        .unwrap();
    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
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
