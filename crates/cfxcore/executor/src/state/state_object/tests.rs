// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{State, Substate};
use crate::{
    internal_contract::{
        initialize_internal_contract_accounts, InternalContractMap,
    },
    state::CleanupMode,
};
use cfx_parameters::{
    consensus::ONE_CFX_IN_DRIP, genesis::DEV_GENESIS_KEY_PAIR, staking::*,
};
use cfx_statedb::StateDb;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, BigEndianHash, U256,
};
use keccak_hash::{keccak, KECCAK_EMPTY};
use primitives::{EpochId, StorageKey, StorageLayout};

pub fn get_state_by_epoch_id(epoch_id: &EpochId) -> State {
    State::new(StateDb::new_for_unit_test_with_epoch(epoch_id)).unwrap()
}

#[cfg(test)]
pub fn get_state_for_genesis_write() -> State {
    let mut state = State::new(StateDb::new_for_unit_test())
        .expect("Failed to initialize state");

    initialize_internal_contract_accounts(
        &mut state,
        InternalContractMap::initialize_for_test().as_slice(),
    )
    .expect("no db error");
    let genesis_epoch_id = EpochId::default();
    state.commit_for_test(genesis_epoch_id).expect(
        // This is a comment to let cargo format the rest in a single line.
        &concat!(file!(), ":", line!(), ":", column!()),
    );

    state
}

fn u256_to_vec(val: &U256) -> Vec<u8> {
    let mut key = vec![0; 32];
    val.to_big_endian(key.as_mut());
    key
}

#[test]
fn checkpoint_basic() {
    let mut state = get_state_for_genesis_write();
    let mut address = Address::zero();
    address.set_user_account_type_bits();
    let address_with_space = address.with_native_space();
    state.checkpoint();
    state
        .add_balance(
            &address_with_space,
            &U256::from(1069u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_collateral_for_storage(&address, &U256::from(1000))
        .unwrap();
    assert_eq!(
        state.balance(&address_with_space).unwrap(),
        U256::from(69u64)
    );
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(state.total_storage_tokens(), U256::from(1000));
    state.discard_checkpoint();
    assert_eq!(
        state.balance(&address_with_space).unwrap(),
        U256::from(69u64)
    );
    state.checkpoint();
    state
        .add_balance(
            &address_with_space,
            &U256::from(1u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .sub_collateral_for_storage(&address, &U256::from(1000))
        .unwrap();
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0)
    );
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.balance(&address_with_space).unwrap(),
        U256::from(1070u64)
    );
    state.revert_to_checkpoint();
    assert_eq!(
        state.balance(&address_with_space).unwrap(),
        U256::from(69u64)
    );
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(state.total_storage_tokens(), U256::from(1000));
}

#[test]
fn checkpoint_nested() {
    let mut state = get_state_for_genesis_write();
    let mut address = Address::zero();
    address.set_user_account_type_bits();
    let address_with_space = address.with_native_space();
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.balance(&address_with_space).unwrap(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0)
    );
    state.checkpoint();
    state.checkpoint();
    state
        .add_balance(
            &address_with_space,
            &U256::from(1069u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_collateral_for_storage(&address, &U256::from(1000))
        .unwrap();
    assert_eq!(state.total_storage_tokens(), U256::from(1000));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(
        state.balance(&address_with_space).unwrap(),
        U256::from(69u64)
    );
    state.discard_checkpoint();
    assert_eq!(state.total_storage_tokens(), U256::from(1000));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(1000)
    );
    assert_eq!(
        state.balance(&address_with_space).unwrap(),
        U256::from(69u64)
    );
    state.revert_to_checkpoint();
    assert_eq!(state.balance(&address_with_space).unwrap(), U256::from(0));
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0)
    );
}

#[test]
fn checkpoint_revert_to_get_storage_at() {
    let mut state = get_state_for_genesis_write();
    let mut address = Address::zero();
    address.set_contract_type_bits();
    let address_with_space = address.with_native_space();
    let key = u256_to_vec(&U256::from(0));
    let c0 = state.checkpoint();
    let c1 = state.checkpoint();
    state
        .new_contract_with_code(&address_with_space, U256::zero())
        .unwrap();
    state
        .set_storage(
            &address_with_space,
            key.clone(),
            U256::one(),
            address,
            &mut Substate::new(),
        )
        .unwrap();

    assert_eq!(
        state
            .checkpoint_storage_at(c0, &address_with_space, &key)
            .unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state
            .checkpoint_storage_at(c1, &address_with_space, &key)
            .unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.storage_at(&address_with_space, &key).unwrap(),
        U256::one()
    );

    state.revert_to_checkpoint();
    assert_eq!(
        state
            .checkpoint_storage_at(c0, &address_with_space, &key)
            .unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.storage_at(&address_with_space, &key).unwrap(),
        U256::zero()
    );
}

#[test]
fn checkpoint_from_empty_get_storage_at() {
    let mut state = get_state_for_genesis_write();
    let mut a = Address::zero();
    a.set_contract_type_bits();
    let a_s = a.with_native_space();
    let sponsor = Address::random();
    let k = u256_to_vec(&U256::from(0));
    let k2 = u256_to_vec(&U256::from(1));

    assert_eq!(state.storage_at(&a_s, &k).unwrap(), U256::zero());
    state.clear();

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

    let c0 = state.checkpoint();
    substates.push(Substate::new());
    state.new_contract_with_code(&a_s, U256::zero()).unwrap();
    state
        .set_sponsor_for_collateral(
            &a,
            &sponsor,
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)),
            false,
        )
        .unwrap();
    assert_eq!(
        state
            .sponsor_for_collateral(&a)
            .unwrap()
            .unwrap_or_default(),
        sponsor
    );
    assert_eq!(state.balance(&a_s).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );
    let c1 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(
            &a_s,
            k.clone(),
            U256::one(),
            a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    let c2 = state.checkpoint();
    substates.push(Substate::new());
    let c3 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(
            &a_s,
            k2.clone(),
            U256::from(3),
            a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    state
        .set_storage(
            &a_s,
            k.clone(),
            U256::from(3),
            a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    let c4 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(
            &a_s,
            k.clone(),
            U256::from(4),
            a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    let c5 = state.checkpoint();
    substates.push(Substate::new());

    assert_eq!(
        state.checkpoint_storage_at(c0, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a_s, &k).unwrap(),
        Some(U256::from(3))
    );
    assert_eq!(
        state.checkpoint_storage_at(c5, &a_s, &k).unwrap(),
        Some(U256::from(4))
    );

    state.discard_checkpoint(); // Commit/discard c5.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(state.balance(&a_s).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &a_s, &k).unwrap(),
        Some(U256::from(3))
    );

    state.revert_to_checkpoint(); // Revert to c4.
    substates.pop();
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.checkpoint_storage_at(c0, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &a_s, &k).unwrap(),
        Some(U256::one())
    );

    state.discard_checkpoint(); // Commit/discard c3.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(
        state.checkpoint_storage_at(c0, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &a_s, &k).unwrap(),
        Some(U256::one())
    );

    state.revert_to_checkpoint(); // Revert to c2.
    substates.pop();
    assert_eq!(
        state.checkpoint_storage_at(c0, &a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &a_s, &k).unwrap(),
        Some(U256::zero())
    );

    state.discard_checkpoint(); // Commit/discard c1.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);

    state
        .settle_collateral_and_assert(
            &a,
            &mut substates.last_mut().unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a_s).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &a_s, &k).unwrap(),
        Some(U256::zero())
    );

    // TODO(69): Consider checking owner
}

#[test]
fn checkpoint_get_storage_at() {
    let mut state = get_state_for_genesis_write();
    let mut a = Address::zero();
    a.set_user_account_type_bits();
    let a_s = a.with_native_space();
    let mut contract_a = Address::zero();
    contract_a.set_contract_type_bits();
    let contract_a_s = contract_a.with_native_space();
    let sponsor = Address::random();
    let k = u256_to_vec(&U256::from(0));
    let k2 = u256_to_vec(&U256::from(1));

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

    state.checkpoint();
    substates.push(Substate::new());
    state
        .add_balance(
            &a_s,
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(
        state.balance(&a_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );

    state
        .new_contract_with_code(&contract_a_s, U256::zero())
        .unwrap();

    state
        .set_storage(
            &contract_a_s,
            k.clone(),
            U256::from(0xffff),
            a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    state.inc_nonce(&contract_a_s).unwrap();

    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    state
        .settle_collateral_and_assert(
            &a_s.address,
            &mut substates.last_mut().unwrap(),
            true,
        )
        .unwrap();
    state
        .commit_for_test(BigEndianHash::from_uint(&U256::from(1u64)))
        .unwrap();

    substates.clear();
    substates.push(Substate::new());

    assert_eq!(
        state.storage_at(&contract_a_s, &k).unwrap(),
        U256::from(0xffff)
    );
    state.clear();
    substates.clear();
    substates.push(Substate::new());
    let cm1 = state.checkpoint();
    substates.push(Substate::new());
    let c0 = state.checkpoint();
    substates.push(Substate::new());
    state
        .new_contract_with_code(&contract_a_s, U256::zero())
        .unwrap();
    state
        .set_sponsor_for_collateral(
            &contract_a,
            &sponsor,
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)),
            false,
        )
        .unwrap();
    assert_eq!(
        state
            .sponsor_for_collateral(&contract_a)
            .unwrap()
            .unwrap_or_default(),
        sponsor
    );
    assert_eq!(state.balance(&contract_a_s).unwrap(), U256::zero());
    let c1 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_a_s,
            k.clone(),
            U256::one(),
            contract_a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    let c2 = state.checkpoint();
    substates.push(Substate::new());
    let c3 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_a_s,
            k2.clone(),
            U256::from(3),
            contract_a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    state
        .set_storage(
            &contract_a_s,
            k.clone(),
            U256::from(3),
            contract_a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    let c4 = state.checkpoint();
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_a_s,
            k.clone(),
            U256::from(4),
            contract_a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    let c5 = state.checkpoint();
    substates.push(Substate::new());

    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &contract_a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &contract_a_s, &k).unwrap(),
        Some(U256::from(3))
    );
    assert_eq!(
        state.checkpoint_storage_at(c5, &contract_a_s, &k).unwrap(),
        Some(U256::from(4))
    );

    state.discard_checkpoint(); // Commit/discard c5.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    assert_eq!(state.balance(&contract_a_s).unwrap(), U256::zero());
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &contract_a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c4, &contract_a_s, &k).unwrap(),
        Some(U256::from(3))
    );

    state.revert_to_checkpoint(); // Revert to c4.
    substates.pop();
    assert_eq!(state.balance(&contract_a_s).unwrap(), U256::zero());
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a_s, &k).unwrap(),
        Some(U256::one())
    );
    assert_eq!(
        state.checkpoint_storage_at(c3, &contract_a_s, &k).unwrap(),
        Some(U256::one())
    );

    state.discard_checkpoint(); // Commit/discard c3.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);

    assert_eq!(state.balance(&contract_a_s).unwrap(), U256::zero());
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a_s, &k).unwrap(),
        Some(U256::zero())
    );
    assert_eq!(
        state.checkpoint_storage_at(c2, &contract_a_s, &k).unwrap(),
        Some(U256::one())
    );

    state.revert_to_checkpoint(); // Revert to c2.
    substates.pop();
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c1, &contract_a_s, &k).unwrap(),
        Some(U256::zero())
    );

    state.discard_checkpoint(); // Commit/discard c1.
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    state
        .settle_collateral_and_assert(
            &contract_a,
            &mut substates.last_mut().unwrap(),
            true,
        )
        .unwrap();

    assert_eq!(state.balance(&contract_a_s).unwrap(), U256::zero());
    assert_eq!(
        state.sponsor_balance_for_collateral(&contract_a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.collateral_for_storage(&contract_a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.checkpoint_storage_at(cm1, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
    assert_eq!(
        state.checkpoint_storage_at(c0, &contract_a_s, &k).unwrap(),
        Some(U256::from(0xffff))
    );
}

#[test]
fn kill_account_with_checkpoints() {
    let mut state_0 = get_state_for_genesis_write();
    let mut a = Address::zero();
    a.set_contract_type_bits();
    let a_s = a.with_native_space();
    let k = u256_to_vec(&U256::from(0));
    // Need the checkpoint for ownership commitment.
    state_0.checkpoint();
    let mut substate = Substate::new();
    state_0
        .new_contract_with_code(&a_s, *COLLATERAL_DRIPS_PER_STORAGE_KEY)
        .unwrap();
    state_0
        .set_storage(&a_s, k.clone(), U256::one(), a, &mut substate)
        .unwrap();
    state_0
        .set_storage_layout(&a_s, StorageLayout::Regular(0))
        .unwrap();
    state_0
        .add_sponsor_balance_for_collateral(
            &a,
            &COLLATERAL_DRIPS_PER_STORAGE_KEY,
        )
        .unwrap();
    state_0.discard_checkpoint();

    let epoch_id_1 = EpochId::from_uint(&U256::from(1));
    state_0
        .commit(epoch_id_1, /* debug_record = */ None)
        .unwrap();

    let mut state = get_state_by_epoch_id(&epoch_id_1);
    // Storage before the account is killed.
    assert_eq!(state.storage_at(&a_s, &k).unwrap(), U256::one());
    state.remove_contract(&a_s).unwrap();
    // The account is killed. The storage should be empty.
    // assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    // The new contract in the same place should have empty storage.
    state.new_contract_with_code(&a_s, U256::zero()).unwrap();
    assert_eq!(state.storage_at(&a_s, &k).unwrap(), U256::zero());

    // Commit the state and repeat the assertion.
    let epoch_id = EpochId::from_uint(&U256::from(2));
    state.commit(epoch_id, /* debug_record = */ None).unwrap();
    let state = get_state_by_epoch_id(&epoch_id);
    assert_eq!(state.storage_at(&a_s, &k).unwrap(), U256::zero());

    // Test checkpoint.
    let mut state = get_state_by_epoch_id(&epoch_id_1);
    state.checkpoint();
    state.remove_contract(&a_s).unwrap();
    // The new contract in the same place should have empty storage.
    state.checkpoint();
    state.new_contract_with_code(&a_s, U256::zero()).unwrap();
    // The new contract in the same place should have empty storage.
    assert_eq!(state.storage_at(&a_s, &k).unwrap(), U256::zero());
    state.revert_to_checkpoint();
    // The account is killed. The storage should be empty.
    // assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    state.revert_to_checkpoint();
    // Storage before the account is killed.
    assert_eq!(state.storage_at(&a_s, &k).unwrap(), U256::one());
}

#[test]
fn check_result_of_simple_payment_to_killed_account() {
    let mut state_0 = get_state_for_genesis_write();
    let sender_addr = DEV_GENESIS_KEY_PAIR.address();
    let sender_addr_s = sender_addr.with_native_space();
    state_0
        .write_account_or_new_lock(&sender_addr_s)
        .unwrap()
        .add_balance(&ONE_CFX_IN_DRIP.into());
    let mut a = Address::zero();
    a.set_contract_type_bits();
    let a_s = a.with_native_space();
    let code = b"asdf"[..].into();
    let code_hash = keccak(&code);
    let code_key = StorageKey::new_code_key(&a, &code_hash).with_native_space();
    let k = u256_to_vec(&U256::from(0));
    // Need the checkpoint for ownership commitment.
    state_0.checkpoint();
    let mut substate = Substate::new();
    state_0.new_contract(&a_s, U256::zero()).unwrap();
    state_0.init_code(&a_s, code, sender_addr).unwrap();
    state_0
        .set_storage(&a_s, k.clone(), U256::one(), a, &mut substate)
        .unwrap();
    state_0
        .set_storage_layout(&a_s, StorageLayout::Regular(0))
        .unwrap();
    state_0
        .add_collateral_for_storage(
            &sender_addr,
            &COLLATERAL_DRIPS_PER_STORAGE_KEY,
        )
        .unwrap();
    state_0.discard_checkpoint();
    let epoch_id_1 = EpochId::from_uint(&U256::from(1));
    state_0
        .commit(epoch_id_1, /* debug_record = */ None)
        .unwrap();

    let mut state = get_state_by_epoch_id(&epoch_id_1);
    state.remove_contract(&a_s).unwrap();
    // The account is killed. The storage should be empty.
    // assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    // Transfer balance to the killed account.
    state
        .transfer_balance(
            &sender_addr_s,
            &a_s,
            &U256::one(),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let epoch_id = EpochId::from_uint(&U256::from(2));
    // Assert that the account has no storage and no code.
    assert_eq!(state.code_hash(&a_s).unwrap(), KECCAK_EMPTY);
    assert_eq!(state.code(&a_s).unwrap(), None);
    // assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
    state.commit(epoch_id, /* debug_record = */ None).unwrap();

    // Commit the state and assert that the account has no storage and no code.
    let state = get_state_by_epoch_id(&epoch_id);
    assert_eq!(state.code_hash(&a_s).unwrap(), KECCAK_EMPTY);
    assert_eq!(state.code(&a_s).unwrap(), None);
    assert_eq!(state.db.get_raw_test(code_key).unwrap(), None);
    // assert_eq!(state.storage_at(&a, &k).unwrap(), U256::zero());
}

#[test]
fn create_contract_fail() {
    let mut substate = Substate::new();
    let mut state = get_state_for_genesis_write();
    let a = Address::from_low_u64_be(1000);
    let a_s = a.with_native_space();

    state.checkpoint(); // c1
    state.new_contract_with_code(&a_s, U256::zero()).unwrap();
    state
        .add_balance(&a_s, &U256::from(1), CleanupMode::ForceCreate)
        .unwrap();
    state.checkpoint(); // c2
    state
        .add_balance(&a_s, &U256::from(1), CleanupMode::ForceCreate)
        .unwrap();
    state
        .settle_collateral_and_assert(&a, &mut substate, true)
        .unwrap();

    state.discard_checkpoint(); // discard c2
    state.revert_to_checkpoint(); // revert to c1
    assert_eq!(state.exists(&a_s).unwrap(), false);

    state
        .commit(BigEndianHash::from_uint(&U256::from(1)), None)
        .unwrap();
}

#[test]
fn create_contract_fail_previous_storage() {
    let mut state = get_state_for_genesis_write();
    let mut a = Address::from_low_u64_be(1000);
    a.set_user_account_type_bits();
    let a_s = a.with_native_space();
    let mut contract_addr = a;
    contract_addr.set_contract_type_bits();
    let contract_addr_s = contract_addr.with_native_space();
    let k = u256_to_vec(&U256::from(0));

    let mut substates = Vec::<Substate>::new();
    substates.push(Substate::new());

    state.checkpoint();
    substates.push(Substate::new());

    state
        .add_balance(
            &a_s,
            &COLLATERAL_DRIPS_PER_STORAGE_KEY,
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(state.collateral_for_storage(&a).unwrap(), U256::from(0));
    assert_eq!(
        state.balance(&a_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );

    state
        .new_contract_with_code(&contract_addr_s, U256::zero())
        .unwrap();
    state
        .set_storage(
            &contract_addr_s,
            k.clone(),
            U256::from(0xffff),
            a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();

    state.discard_checkpoint();
    let substate = substates.pop().unwrap();
    substates.last_mut().unwrap().accrue(substate);
    state
        .settle_collateral_and_assert(&a, substates.last_mut().unwrap(), true)
        .unwrap();
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a_s).unwrap(), U256::zero());
    state
        .commit_for_test(BigEndianHash::from_uint(&U256::from(1)))
        .unwrap();

    state.clear();
    substates.clear();
    substates.push(Substate::new());

    assert_eq!(
        state.storage_at(&contract_addr_s, &k).unwrap(),
        U256::from(0xffff)
    );
    state.clear();
    substates.clear();
    substates.push(Substate::new());
    state = get_state_by_epoch_id(&BigEndianHash::from_uint(&U256::from(1)));
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a_s).unwrap(), U256::from(0));

    state.checkpoint(); // c1
    substates.push(Substate::new());
    state.remove_contract(&a_s).unwrap();
    // parking_lot::lock_api::MappedRwLockWriteGuard must be used, so we drop()
    // it.
    drop(state.write_account_or_new_lock(&a_s).unwrap());
    state
        .new_contract_with_code(&contract_addr_s, U256::zero())
        .unwrap();
    state.checkpoint(); // c2
    substates.push(Substate::new());
    state
        .set_storage(
            &contract_addr_s,
            k.clone(),
            U256::from(2),
            a,
            &mut substates.last_mut().unwrap(),
        )
        .unwrap();
    state.revert_to_checkpoint();
    substates.pop(); // revert to c2
    state.revert_to_checkpoint();
    substates.pop(); // revert to c1

    state
        .settle_collateral_and_assert(&a, substates.last_mut().unwrap(), true)
        .unwrap();

    assert_eq!(
        state.storage_at(&contract_addr_s, &k).unwrap(),
        U256::from(0xffff)
    );
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.collateral_for_storage(&a).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&a_s).unwrap(), U256::from(0));

    state
        .commit(BigEndianHash::from_uint(&U256::from(2)), None)
        .unwrap();

    // TODO(69): checking ownership
}

#[test]
fn test_automatic_collateral_normal_account() {
    let mut state = get_state_for_genesis_write();
    let mut normal_account = Address::from_low_u64_be(0);
    normal_account.set_user_account_type_bits();
    let normal_account_s = normal_account.with_native_space();
    let mut contract_account = Address::from_low_u64_be(1);
    contract_account.set_contract_type_bits();
    let contract_account_s = contract_account.with_native_space();
    let k1 = u256_to_vec(&U256::from(0));
    let k2 = u256_to_vec(&U256::from(1));
    let k3 = u256_to_vec(&U256::from(3));

    state
        .add_balance(
            &normal_account_s,
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .new_contract_with_code(
            &contract_account_s,
            *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
        )
        .unwrap();

    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.balance(&normal_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.balance(&contract_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );

    // simple set one key with zero value for normal account
    state.checkpoint();
    let mut substate = Substate::new();
    state
        .set_storage(
            &contract_account_s,
            k1.clone(),
            U256::zero(),
            normal_account,
            &mut substate,
        )
        .unwrap();

    state
        .settle_collateral_and_assert(&normal_account, &mut substate, true)
        .unwrap();
    state.discard_checkpoint();
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.balance(&normal_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.balance(&contract_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );

    // simple set one key with nonzero value for normal account
    state.checkpoint();
    let mut substate = Substate::new();
    state
        .set_storage(
            &contract_account_s,
            k1.clone(),
            U256::one(),
            normal_account,
            &mut substate,
        )
        .unwrap();
    state
        .settle_collateral_and_assert(&normal_account, &mut substate, true)
        .unwrap();
    state.discard_checkpoint();
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.balance(&normal_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );

    // test not sufficient balance
    state.checkpoint();
    let mut substate = Substate::new();

    state
        .set_storage(
            &contract_account_s,
            k2.clone(),
            U256::one(),
            normal_account,
            &mut substate,
        )
        .unwrap();
    state
        .set_storage(
            &contract_account_s,
            k3.clone(),
            U256::one(),
            normal_account,
            &mut substate,
        )
        .unwrap();
    state
        .settle_collateral_and_assert(&normal_account, &mut substate, false)
        .unwrap();
    state.revert_to_checkpoint();
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.balance(&normal_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );

    // use all balance
    state.checkpoint();
    let mut substate = Substate::new();

    state
        .set_storage(
            &contract_account_s,
            k2.clone(),
            U256::one(),
            normal_account,
            &mut substate,
        )
        .unwrap();
    state
        .settle_collateral_and_assert(&normal_account, &mut substate, true)
        .unwrap();
    state.discard_checkpoint();
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(state.balance(&normal_account_s).unwrap(), U256::from(0));

    // set one key to zero
    state.checkpoint();
    let mut substate = Substate::new();
    state
        .set_storage(
            &contract_account_s,
            k2.clone(),
            U256::zero(),
            normal_account,
            &mut substate,
        )
        .unwrap();
    state
        .settle_collateral_and_assert(&normal_account, &mut substate, true)
        .unwrap();
    state.discard_checkpoint();
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.balance(&normal_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );

    // set another key to zero
    state.checkpoint();
    let mut substate = Substate::new();

    state
        .set_storage(
            &contract_account_s,
            k1.clone(),
            U256::zero(),
            normal_account,
            &mut substate,
        )
        .unwrap();
    state
        .settle_collateral_and_assert(&normal_account, &mut substate, true)
        .unwrap();
    state.discard_checkpoint();

    assert_eq!(state.total_storage_tokens(), U256::from(0));
    assert_eq!(
        state.balance(&normal_account_s).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
}

// #[test]
// fn test_automatic_collateral_contract_account() {
//     let storage_manager = new_state_manager_for_unit_test();
//     let mut state = get_state_for_genesis_write(&storage_manager);
//     let mut contract_account = Address::from_low_u64_be(1);
//     contract_account.set_contract_type_bits();
//     let contract_account_s = contract_account.with_native_space();
//     let sponsor = Address::random();
//     let k1 = u256_to_vec(&U256::from(0));
//     let k2 = u256_to_vec(&U256::from(1));
//     let k3 = u256_to_vec(&U256::from(3));

//     let mut substates = Vec::<Substate>::new();
//     substates.push(Substate::new());

//     state
//         .new_contract_with_code(&contract_account_s, U256::zero())
//         .unwrap();
//     state
//         .set_sponsor_for_collateral(
//             &contract_account,
//             &sponsor,
//             &(*COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)),
//             false,
//         )
//         .unwrap();
//     assert_eq!(
//         state
//             .sponsor_for_collateral(&contract_account)
//             .unwrap()
//             .unwrap_or_default(),
//         sponsor
//     );
//     assert_eq!(state.total_storage_tokens(), U256::from(0));
//     assert_eq!(
//         state.collateral_for_storage(&contract_account).unwrap(),
//         U256::from(0)
//     );
//     assert_eq!(state.balance(&contract_account_s).unwrap(), U256::from(0));
//     assert_eq!(
//         state
//             .sponsor_balance_for_collateral(&contract_account)
//             .unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
//     );

//     // simple set one key with zero value for contract account
//     state.checkpoint();
//     substates.push(Substate::new());
//     state
//         .set_storage(
//             &contract_account_s,
//             k1.clone(),
//             U256::zero(),
//             &mut substates.last_mut().unwrap(),
//         )
//         .unwrap();
//     state.discard_checkpoint();
//     substates.pop();
//     assert_eq!(state.total_storage_tokens(), U256::from(0));
//     assert_eq!(
//         state.collateral_for_storage(&contract_account).unwrap(),
//         U256::from(0),
//     );
//     assert_eq!(state.balance(&contract_account_s).unwrap(), U256::from(0));
//     assert_eq!(
//         state
//             .sponsor_balance_for_collateral(&contract_account)
//             .unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
//     );

//     // simple set one key with nonzero value for contract account
//     state.checkpoint();
//     substates.push(Substate::new());
//     state
//         .set_storage(
//             &contract_account_s,
//             k1.clone(),
//             U256::one(),
//             &mut substates.last_mut().unwrap(),
//         )
//         .unwrap();
//     state.discard_checkpoint();
//     let substate = substates.pop().unwrap();
//     substates.last_mut().unwrap().accrue(substate);

//     // test not sufficient balance
//     state.checkpoint();
//     substates.push(Substate::new());
//     state
//         .set_storage(
//             &contract_account_s,
//             k2.clone(),
//             U256::one(),
//             &mut substates.last_mut().unwrap(),
//         )
//         .unwrap();
//     state
//         .set_storage(
//             &contract_account_s,
//             k3.clone(),
//             U256::one(),
//             &mut substates.last_mut().unwrap(),
//         )
//         .unwrap();
//     assert_eq!(
//         state
//             .collect_and_settle_collateral(
//                 &contract_account,
//                 &U256::MAX,
//                 &mut substates.last_mut().unwrap(),
//                 &mut (),
//                 &Spec::new_spec_for_test(),
//                 false
//             )
//             .unwrap(),
//         CollateralCheckResult::NotEnoughBalance {
//             required: *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
//             got: *COLLATERAL_DRIPS_PER_STORAGE_KEY,
//         }
//     );

//     state.revert_to_checkpoint();
//     substates.pop();

//     assert_eq!(state.balance(&contract_account_s).unwrap(), U256::from(0));
//     assert_eq!(
//         state
//             .sponsor_balance_for_collateral(&contract_account)
//             .unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY
//     );
//     assert_eq!(
//         state.collateral_for_storage(&contract_account).unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY
//     );
//     assert_eq!(
//         state.total_storage_tokens(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY
//     );

//     // use all balance
//     state.checkpoint();
//     substates.push(Substate::new());
//     state
//         .set_storage(
//             &contract_account_s,
//             k2.clone(),
//             U256::one(),
//             &mut substates.last_mut().unwrap(),
//         )
//         .unwrap();

//     state.discard_checkpoint();
//     let substate = substates.pop().unwrap();
//     substates.last_mut().unwrap().accrue(substate);
//     assert_eq!(state.balance(&contract_account_s).unwrap(), U256::from(0));
//     assert_eq!(
//         state
//             .sponsor_balance_for_collateral(&contract_account)
//             .unwrap(),
//         U256::from(0)
//     );
//     assert_eq!(
//         state.collateral_for_storage(&contract_account).unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
//     );
//     assert_eq!(
//         state.total_storage_tokens(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
//     );

//     // set one key to zero
//     state.checkpoint();
//     substates.push(Substate::new());
//     state
//         .set_storage(
//             &contract_account_s,
//             k2.clone(),
//             U256::zero(),
//             &mut substates.last_mut().unwrap(),
//         )
//         .unwrap();
//     state.discard_checkpoint();
//     let substate = substates.pop().unwrap();
//     substates.last_mut().unwrap().accrue(substate);
//     assert_eq!(state.balance(&contract_account_s).unwrap(), U256::from(0));
//     assert_eq!(
//         state
//             .sponsor_balance_for_collateral(&contract_account)
//             .unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY
//     );
//     assert_eq!(
//         state.collateral_for_storage(&contract_account).unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY
//     );
//     assert_eq!(
//         state.total_storage_tokens(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY
//     );
//     assert_eq!(state.secondary_reward(), U256::from(39637239));

//     // set another key to zero
//     state.checkpoint();
//     substates.push(Substate::new());
//     state
//         .set_storage(
//             &contract_account_s,
//             k1.clone(),
//             U256::zero(),
//             &mut substates.last_mut().unwrap(),
//         )
//         .unwrap();
//     state.discard_checkpoint();
//     let substate = substates.pop().unwrap();
//     substates.last_mut().unwrap().accrue(substate);
//     assert_eq!(state.balance(&contract_account_s).unwrap(), U256::from(0));
//     assert_eq!(
//         state
//             .sponsor_balance_for_collateral(&contract_account)
//             .unwrap(),
//         *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
//     );
//     assert_eq!(
//         state.collateral_for_storage(&contract_account).unwrap(),
//         U256::from(0)
//     );
//     assert_eq!(state.total_storage_tokens(), U256::from(0));
//     assert_eq!(state.secondary_reward(), U256::from(0));

//     // TODO(69): checking
// }
