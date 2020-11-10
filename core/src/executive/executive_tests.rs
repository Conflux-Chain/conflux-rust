// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{executive::*, internal_contract::*, Executed, ExecutionError};
use crate::{
    evm::{Factory, FinalizationResult, VMType},
    executive::ExecutionOutcome,
    machine::Machine,
    state::{CleanupMode, CollateralCheckResult, State, Substate},
    test_helpers::{
        get_state_for_genesis_write, get_state_for_genesis_write_with_factory,
    },
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress, Env,
    },
};
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::{
    internal_contract_addresses::{
        SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    },
    staking::*,
};
use cfx_statedb::StateDb;
use cfx_storage::{
    state_manager::StateManagerTrait, tests::new_state_manager_for_unit_test,
    StateIndex,
};
use cfx_types::{
    address_util::AddressUtil, Address, BigEndianHash, U256, U512,
};
use keylib::{Generator, Random};
use primitives::{
    storage::STORAGE_LAYOUT_REGULAR_V0, transaction::Action, EpochId,
    Transaction,
};
use rustc_hex::FromHex;
use std::{
    cmp::{self, min},
    str::FromStr,
    sync::Arc,
};

fn make_byzantium_machine(max_depth: usize) -> Machine {
    let mut machine =
        crate::machine::new_machine_with_builtin(Default::default());
    machine
        .set_spec_creation_rules(Box::new(move |s, _| s.max_depth = max_depth));
    machine
}

#[test]
fn test_contract_address() {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let expected_address =
        Address::from_str("87ed868bd4e05f0be585961a5293a68cfb6ce60e").unwrap();
    assert_eq!(
        expected_address,
        contract_address(
            CreateContractAddress::FromSenderNonceAndCodeHash,
            /* block_number = */ 0.into(),
            &address,
            &U256::from(88),
            &[],
        )
        .0
    );
}

#[test]
fn test_sender_balance() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new("3331600055".from_hex().unwrap()));
    params.value = ActionValue::Transfer(U256::from(0x7));
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(
            &sender,
            &COLLATERAL_DRIPS_PER_STORAGE_KEY,
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(&sender, &U256::from(0x100u64), CleanupMode::NoEmpty)
        .unwrap();
    assert_eq!(
        state.balance(&sender).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(0x100)
    );
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        state.checkpoint();
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        let res = ex.create(params.clone(), &mut substate).unwrap();
        state
            .collect_and_settle_collateral(
                &params.storage_owner,
                &params.storage_limit_in_drip,
                &mut substate,
            )
            .unwrap()
            .into_vm_result()
            .unwrap();
        state.discard_checkpoint();
        res
    };

    assert_eq!(gas_left, U256::from(94_595));
    assert_eq!(
        state.storage_at(&address, &vec![0; 32]).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(0xf9)
    );
    assert_eq!(state.balance(&sender).unwrap(), U256::from(0xf9));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&address).unwrap(), U256::from(0x7));
    assert_eq!(substate.contracts_created.len(), 0);
}

#[test]
fn test_create_contract_out_of_depth() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 00 - push 0
    // 52
    // 60 1d - push 29
    // 60 03 - push 3
    // 60 17 - push 17
    // f0 - create
    // 60 00 - push 0
    // 55 sstore
    //
    // other code:
    //
    // 60 10 - push 16
    // 80 - duplicate first stack item
    // 60 0c - push 12
    // 60 00 - push 0
    // 39 - copy current code to memory
    // 60 00 - push 0
    // f3 - return

    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let sender =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender,
        &U256::zero(),
        &[],
    )
    .0;

    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(100));

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty)
        .unwrap();
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.create(params, &mut substate).unwrap()
    };

    assert_eq!(gas_left, U256::from(62_970));
    assert_eq!(substate.contracts_created.len(), 0);
}

#[test]
fn test_suicide_when_creation() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    // code:
    //
    // 33 - get caller address
    // ff - self-deconstruct

    let code = "33ff".from_hex().unwrap();

    let sender_addr =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let contract_addr = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender_addr,
        &U256::zero(),
        &[],
    )
    .0;

    let mut params = ActionParams::default();
    params.address = contract_addr;
    params.sender = sender_addr;
    params.original_sender = sender_addr;
    params.storage_owner = sender_addr;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(0));

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(&sender_addr, &U256::from(100_000), CleanupMode::NoEmpty)
        .unwrap();
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let mut ex = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    );
    let FinalizationResult {
        gas_left,
        apply_state,
        return_data: _,
    } = ex.create(params, &mut substate).unwrap();

    assert_eq!(gas_left, U256::from(94_998));
    assert_eq!(apply_state, true);

    assert!(substate.storage_collateralized.get(&sender_addr).is_none(),
            "Since the contract has not been created, the sender occupied no storage now. ");
    assert!(substate.storage_released.get(&sender_addr).is_none(),
            "Since the contract has not been created, no storage is released when contract suicides. ");
    assert!(substate.suicides.contains(&contract_addr));
}

#[test]
// Tracing is not suported in JIT
fn test_call_to_create() {
    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 00 - push 0
    // 52
    // 60 1d - push 29
    // 60 03 - push 3
    // 60 17 - push 23
    // f0 - create
    // 60 00 - push 0
    // 55 sstore
    //
    // other code:
    //
    // 60 10 - push 16
    // 80 - duplicate first stack item
    // 60 0c - push 12
    // 60 00 - push 0
    // 39 - copy current code to memory
    // 60 00 - push 0
    // f3 - return

    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();
    let code_len = code.len();

    let sender =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    // TODO: add tests for 'callcreate'
    let mut params = ActionParams::default();
    params.address = address;
    params.code_address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(100));
    params.call_type = CallType::Call;
    params.storage_limit_in_drip = *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        * code_collateral_units(code_len)
        + *COLLATERAL_DRIPS_PER_STORAGE_KEY;

    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    state
        .new_contract(&address, U256::zero(), U256::one())
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state
        .add_balance(
            &sender,
            &(U256::from(100) + params.storage_limit_in_drip),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        U256::from(0)
    );
    assert_eq!(*state.total_storage_tokens(), U256::from(0));
    let env = Env::default();
    let machine = make_byzantium_machine(5);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        state.checkpoint();
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        let res = ex.call(params.clone(), &mut substate).unwrap();
        state
            .collect_and_settle_collateral(
                &params.storage_owner,
                &params.storage_limit_in_drip,
                &mut substate,
            )
            .unwrap()
            .into_vm_result()
            .unwrap();
        state.discard_checkpoint();
        res
    };
    assert_eq!(state.balance(&sender).unwrap(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        params.storage_limit_in_drip
    );
    assert_eq!(*state.total_storage_tokens(), params.storage_limit_in_drip);

    assert_eq!(gas_left, U256::from(59_746));
}

#[test]
fn test_revert() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let contract_address =
        Address::from_str("8d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();

    let code = "6c726576657274656420646174616000557f726576657274206d657373616765000000000000000000000000000000000000600052600e6000fd".from_hex().unwrap();
    let returns = "726576657274206d657373616765".from_hex().unwrap();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(
        &storage_manager,
        factory.clone(),
    );
    state
        .add_balance(
            &sender,
            &U256::from_str("152d02c7e14af68000000").unwrap(),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .new_contract(&contract_address, U256::zero(), U256::one())
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state
        .commit(BigEndianHash::from_uint(&U256::from(1)), None)
        .unwrap();

    let mut params = ActionParams::default();
    params.address = contract_address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = contract_address;
    params.gas = U256::from(20025);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::zero());
    let env = Env::default();
    let machine = crate::machine::new_machine_with_builtin(Default::default());
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let mut output = [0u8; 14];
    let FinalizationResult {
        gas_left: result,
        return_data,
        ..
    } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params, &mut substate).unwrap()
    };
    (&mut output)
        .copy_from_slice(&return_data[..(cmp::min(14, return_data.len()))]);

    assert_eq!(result, U256::from(15_001));
    assert_eq!(output[..], returns[..]);
    assert_eq!(
        state.storage_at(&contract_address, &vec![0; 32]).unwrap(),
        U256::zero()
    );
}

#[test]
fn test_keccak() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let code = "6064640fffffffff20600055".from_hex().unwrap();

    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    // TODO: add tests for 'callcreate'
    //let next_address = contract_address(&address, &U256::zero());
    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = address;
    params.gas = U256::from(0x0186a0);
    params.code = Some(Arc::new(code));
    params.value =
        ActionValue::Transfer(U256::from_str("0de0b6b3a7640000").unwrap());

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(
            &sender,
            &U256::from_str("152d02c7e14af6800000").unwrap(),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();

    let result = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.create(params, &mut substate)
    };

    match result {
        Err(_) => {}
        _ => panic!("Expected OutOfGas"),
    }
}

#[test]
fn test_not_enough_cash() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let keypair = Random.generate().unwrap();
    let t = Transaction {
        action: Action::Create,
        value: U256::from(18),
        data: "3331600055".from_hex().unwrap(),
        gas: U256::from(100_000),
        gas_price: U256::one(),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 0,
        nonce: U256::zero(),
    }
    .sign(keypair.secret());
    let sender = t.sender();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(&sender, &U256::from(100_017), CleanupMode::NoEmpty)
        .unwrap();
    let correct_cost = min(t.gas_price * t.gas, 100_017.into());
    let mut env = Env::default();
    env.gas_limit = U256::from(100_000);
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let res = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.transact(&t).unwrap()
    };

    match res {
        ExecutionOutcome::ExecutionErrorBumpNonce(
            ExecutionError::NotEnoughCash {
                required,
                got,
                actual_gas_cost,
                max_storage_limit_cost,
            },
            _executed,
        ) if required == U512::from(100_018)
            && got == U512::from(100_017)
            && correct_cost == actual_gas_cost
            && max_storage_limit_cost.is_zero() =>
        {
            ()
        }
        _ => assert!(false, "Expected not enough cash error. {:?}", res),
    }
}

#[test]
fn test_deposit_withdraw_lock() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let mut sender = Address::zero();
    sender.set_user_account_type_bits();
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);
    let mut substate = Substate::new();
    state
        .add_balance(
            &sender,
            &U256::from(2_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state.add_total_issued(U256::from(2_000_000_000_000_000_000u64));
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(*state.total_staking_tokens(), U256::zero());
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );

    let mut params = ActionParams::default();
    params.code_address = STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS.clone();
    params.address = params.code_address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = params.code_address;
    params.gas = U256::from(1000000);
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a7640000".from_hex().unwrap());
    params.call_type = CallType::CallCode;

    // wrong call type
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("Incorrect call type.")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::zero());

    // deposit 10^18 - 1, not enough
    params.call_type = CallType::Call;
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a763ffff".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid deposit amount")
    );

    // deposit 10^18, it should work fine
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a7640000".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );

    // empty data
    params.data = None;
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("None call data")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );

    // less data
    params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e8".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("Incomplete static input parameter")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );

    // withdraw
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000000000ba43b7400".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    // withdraw more than staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288c01".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw"
        )
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );

    // lock until block_number = 0
    params.data = Some("44a51d6d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid unlock_block_number")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    // lock 1 until 106751991167301 blocks, should succeed
    params.data = Some("44a51d6d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000611722833944".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_949_999_999_999u64)
    );
    // lock 2 until block_number=2
    params.data = Some("44a51d6d00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_949_999_999_998u64)
    );
    // withdraw more than withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288bff".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw"
        )
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(999_999_949_999_999_998u64)
    );

    // withdraw exact withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288bfe".from_hex().unwrap());
    let result = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .call(params.clone(), &mut substate);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_999_999_999_999_999_998u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::from(2));
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(2));
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(0)
    );
}

#[test]
fn test_commission_privilege_all_whitelisted_across_epochs() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write_with_factory(
        &storage_manager,
        factory.clone(),
    );
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let spec = machine.spec(env.number);

    let sender = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender.address(),
        &U256::zero(),
        &[],
    )
    .0;

    state.checkpoint();
    state
        .new_contract_with_admin(
            &address,
            &sender.address(),
            U256::zero(),
            U256::one(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state
        .init_code(&address, code.clone(), sender.address())
        .unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    state
        .add_commission_privilege(address, sender.address(), Default::default())
        .unwrap();
    let epoch_id = EpochId::from_uint(&U256::from(1));
    state
        .collect_and_settle_collateral(
            &Address::default(),
            &0.into(),
            &mut Substate::new(),
        )
        .unwrap();
    state.discard_checkpoint();
    let mut debug_record = ComputeEpochDebugRecord::default();
    state.commit(epoch_id, Some(&mut debug_record)).unwrap();
    debug!("{:?}", debug_record);

    let mut state = State::new(
        StateDb::new(
            storage_manager
                .get_state_for_next_epoch(
                    StateIndex::new_for_test_only_delta_mpt(&epoch_id),
                )
                .unwrap()
                .unwrap(),
        ),
        factory.clone().into(),
        &spec,
        1, /* block_number */
    );
    state.checkpoint();
    assert_eq!(
        true,
        state
            .check_commission_privilege(&address, &sender.address())
            .unwrap()
    );
    assert_eq!(
        true,
        state
            .check_commission_privilege(&address, &Default::default())
            .unwrap()
    );
    let epoch_id = EpochId::from_uint(&U256::from(2));
    // Destroy the contract, then create again.
    state.remove_contract(&address).unwrap();
    state
        .new_contract_with_admin(
            &address,
            &sender.address(),
            U256::zero(),
            U256::one(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
        )
        .unwrap();
    state.init_code(&address, code, sender.address()).unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let whitelisted_caller = Address::random();
    state
        .add_commission_privilege(address, sender.address(), whitelisted_caller)
        .unwrap();
    assert_eq!(
        true,
        state
            .check_commission_privilege(&address, &whitelisted_caller)
            .unwrap()
    );
    assert_eq!(
        false,
        state
            .check_commission_privilege(&address, &Default::default())
            .unwrap()
    );
    state
        .collect_and_settle_collateral(
            &Address::default(),
            &0.into(),
            &mut Substate::new(),
        )
        .unwrap();
    state.discard_checkpoint();
    state.commit(epoch_id, None).unwrap();

    let state = State::new(
        StateDb::new(
            storage_manager
                .get_state_no_commit(
                    StateIndex::new_for_test_only_delta_mpt(&epoch_id),
                    /* try_open = */ false,
                )
                .unwrap()
                .unwrap(),
        ),
        factory.clone().into(),
        &spec,
        2, /* block_number */
    );
    assert_eq!(
        true,
        state
            .check_commission_privilege(&address, &whitelisted_caller)
            .unwrap()
    );
    assert_eq!(
        false,
        state
            .check_commission_privilege(&address, &Default::default())
            .unwrap()
    );
}

#[test]
fn test_commission_privilege() {
    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 00 - push 0
    // 52
    // 60 1d - push 29
    // 60 03 - push 3
    // 60 17 - push 23
    // f0 - create
    // 60 00 - push 0
    // 55 sstore

    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let sender = Random.generate().unwrap();
    let caller1 = Random.generate().unwrap();
    let caller2 = Random.generate().unwrap();
    let caller3 = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender.address(),
        &U256::zero(),
        &[],
    )
    .0;

    state
        .new_contract_with_admin(
            &address,
            &sender.address(),
            U256::zero(),
            U256::one(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state.init_code(&address, code, sender.address()).unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(1000000),
        action: Action::Call(address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(sender.secret());
    assert_eq!(tx.sender(), sender.address());
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(state.nonce(&sender.address()).unwrap(), U256::from(1));
    assert_eq!(state.balance(&address).unwrap(), U256::from(1_000_000));
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(999_999_999_998_925_000u64)
    );

    state
        .add_balance(
            &caller1.address(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller2.address(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller3.address(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    // add commission privilege to caller1 and caller2
    state
        .add_commission_privilege(address, sender.address(), caller1.address())
        .unwrap();
    state
        .add_commission_privilege(address, sender.address(), caller2.address())
        .unwrap();
    assert!(state
        .check_commission_privilege(&address, &caller1.address())
        .unwrap());
    assert!(state
        .check_commission_privilege(&address, &caller2.address())
        .unwrap());
    assert!(!state
        .check_commission_privilege(&address, &caller3.address())
        .unwrap());
    state
        .set_sponsor_for_gas(
            &address,
            &sender.address(),
            &U256::from(110_000),
            &U256::from(110_000),
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(110_000)
    );
    assert_eq!(
        state.sponsor_gas_bound(&address).unwrap(),
        U256::from(110_000)
    );

    // call with no commission privilege
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(60_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller3.secret());
    assert_eq!(tx.sender(), caller3.address());
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(100_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(state.nonce(&caller3.address()).unwrap(), U256::from(1));
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_970)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(110_000)
    );

    // call with commission privilege and enough commission balance
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller1.secret());
    assert_eq!(tx.sender(), caller1.address());
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        U256::from(100_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(state.nonce(&caller1.address()).unwrap(), U256::from(1));
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        U256::from(100_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(35_000)
    );

    // call with commission privilege and not enough commission balance
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller2.secret());
    assert_eq!(tx.sender(), caller2.address());
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(100_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(state.nonce(&caller2.address()).unwrap(), U256::from(1));
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(25_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(35_000)
    );

    // add more commission balance
    state
        .set_sponsor_for_gas(
            &address,
            &sender.address(),
            &U256::from(200_000),
            &U256::from(200_000),
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(200_000)
    );

    // call with commission privilege and enough commission balance
    let tx = Transaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller2.secret());
    assert_eq!(tx.sender(), caller2.address());
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(25_000)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(state.nonce(&caller2.address()).unwrap(), U256::from(2));
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(25_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(125_000)
    );

    // add commission privilege to caller3
    state
        .add_commission_privilege(address, sender.address(), caller3.address())
        .unwrap();
    assert!(state
        .check_commission_privilege(&address, &caller3.address())
        .unwrap());
    // call with commission privilege and enough commission balance
    let tx = Transaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller3.secret());
    assert_eq!(tx.sender(), caller3.address());
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_970)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(state.nonce(&caller3.address()).unwrap(), U256::from(2));
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_970)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address).unwrap(),
        U256::from(50_000)
    );
}

#[test]
fn test_storage_commission_privilege() {
    // code:
    //
    // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
    // 29 bytes? 60 01 - push 0
    // 52
    // 33 - caller
    // 60 01 - push 1
    // 55 sstore

    let privilege_control_address = &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let code = "7c601080600c6000396000f3006000355415600957005b6020356000355560005233600155".from_hex().unwrap();

    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let internal_contract_map = InternalContractMap::new();
    let spec = machine.spec(env.number);

    let sender = Random.generate().unwrap();
    let caller1 = Random.generate().unwrap();
    let caller2 = Random.generate().unwrap();
    let caller3 = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0.into(),
        &sender.address(),
        &U256::zero(),
        &[],
    )
    .0;

    state
        .new_contract_with_admin(
            &address,
            &sender.address(),
            U256::zero(),
            U256::one(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state.init_code(&address, code, sender.address()).unwrap();

    state
        .add_balance(
            &sender.address(),
            &U256::from(2_000_000_000_000_075_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // simple call to create a storage entry
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: *COLLATERAL_DRIPS_PER_STORAGE_KEY,
        action: Action::Call(address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(sender.secret());
    assert_eq!(tx.sender(), sender.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();
    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, sender.address());
    assert_eq!(
        storage_collateralized[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(storage_released.len(), 0);

    state
        .set_sponsor_for_collateral(
            &address,
            &sender.address(),
            &COLLATERAL_DRIPS_PER_STORAGE_KEY,
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );

    state
        .add_balance(
            &caller1.address(),
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller2.address(),
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller3.address(),
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // add privilege to caller1 and caller2
    let mut substate = Substate::new();
    state.checkpoint();
    state
        .add_commission_privilege(address, sender.address(), caller1.address())
        .unwrap();
    state
        .add_commission_privilege(address, sender.address(), caller2.address())
        .unwrap();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &privilege_control_address,
                &U256::MAX,
                &mut substate,
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(
        substate.storage_collateralized[&sender.address()],
        2 * COLLATERAL_UNITS_PER_STORAGE_KEY
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_750_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3),
    );
    assert!(state
        .check_commission_privilege(&address, &caller1.address())
        .unwrap());
    assert!(state
        .check_commission_privilege(&address, &caller2.address())
        .unwrap());
    assert!(!state
        .check_commission_privilege(&address, &caller3.address())
        .unwrap());

    // caller3 call with no privilege
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000),
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller3.secret());
    assert_eq!(tx.sender(), caller3.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, caller3.address());
    assert_eq!(
        storage_collateralized[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, sender.address());
    assert_eq!(
        storage_released[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(925_000)
    );
    assert_eq!(
        state.staking_balance(&caller3.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller3.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );

    // caller1 call with privilege
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000),
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller1.secret());
    assert_eq!(tx.sender(), caller1.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, address);
    assert_eq!(
        storage_collateralized[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, caller3.address());
    assert_eq!(
        storage_released[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(925_000),
    );
    assert_eq!(
        state.staking_balance(&caller1.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller1.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        U256::zero()
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(925_000)
    );
    assert_eq!(
        state.staking_balance(&caller3.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller3.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );

    // caller2 call with commission privilege and not enough sponsor
    // balance, the owner will transfer to caller2.
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000),
    );
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller2.secret());
    assert_eq!(tx.sender(), caller2.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, caller2.address());
    assert_eq!(
        storage_collateralized[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, address);
    assert_eq!(
        storage_released[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        U256::from(925_000)
    );
    assert_eq!(
        state.staking_balance(&caller2.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller2.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0),
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );

    // remove privilege from caller1
    state.checkpoint();
    state
        .remove_commission_privilege(
            address,
            sender.address(),
            caller1.address(),
        )
        .unwrap();
    let mut substate = Substate::new();
    assert_eq!(
        state
            .collect_and_settle_collateral(
                &privilege_control_address,
                &U256::MAX,
                &mut substate,
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );
    state.discard_checkpoint();
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(1),
    );
    assert_eq!(substate.storage_released.len(), 1);
    assert_eq!(
        substate.storage_released[&sender.address()],
        COLLATERAL_UNITS_PER_STORAGE_KEY
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.balance(&sender.address()).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );

    assert!(!state
        .check_commission_privilege(&address, &caller1.address())
        .unwrap());

    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(925_000),
    );
    let tx = Transaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller1.secret());
    assert_eq!(tx.sender(), caller1.address());
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx)
    .unwrap()
    .successfully_executed()
    .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, caller1.address());
    assert_eq!(
        storage_collateralized[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, caller2.address());
    assert_eq!(
        storage_released[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&caller1.address()).unwrap(),
        U256::from(850_000)
    );
    assert_eq!(
        state.staking_balance(&caller1.address()).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&caller1.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.collateral_for_storage(&caller2.address()).unwrap(),
        U256::from(0),
    );
    assert_eq!(
        state.balance(&caller2.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(925_000),
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::zero()
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
}
