// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{executive::*, internal_contract::*, Executed, ExecutionError};
use crate::{
    evm::{Factory, FinalizationResult, VMType},
    machine::Machine,
    parameters::staking::*,
    state::{CleanupMode, CollateralCheckResult, Substate},
    storage::tests::new_state_manager_for_unit_test,
    test_helpers::{
        get_state_for_genesis_write, get_state_for_genesis_write_with_factory,
    },
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress, Env,
    },
};
use cfx_types::{Address, BigEndianHash, H256, U256, U512};
use keylib::{Generator, Random};
use primitives::{transaction::Action, Transaction};
use rustc_hex::FromHex;
use std::{
    cmp::{self, min},
    str::FromStr,
    sync::Arc,
};

fn make_byzantium_machine(max_depth: usize) -> Machine {
    let mut machine = crate::machine::new_machine_with_builtin();
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
            &address,
            &U256::from(88),
            &[]
        )
        .0
    );
}

#[test]
fn test_sender_balance() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let sender =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.original_receiver = address;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new("3331600055".from_hex().unwrap()));
    params.value = ActionValue::Transfer(U256::from(0x7));
    let storage_manager = new_state_manager_for_unit_test();
    let mut state =
        get_state_for_genesis_write_with_factory(&storage_manager, factory);
    state
        .add_balance(&sender, &COLLATERAL_PER_STORAGE_KEY, CleanupMode::NoEmpty)
        .unwrap();
    state
        .add_balance(&sender, &U256::from(0x100u64), CleanupMode::NoEmpty)
        .unwrap();
    assert_eq!(
        state.balance(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(0x100)
    );
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

    assert_eq!(gas_left, U256::from(94_595));
    assert_eq!(
        state.storage_at(&address, &H256::zero()).unwrap(),
        BigEndianHash::from_uint(
            &(*COLLATERAL_PER_STORAGE_KEY + U256::from(0xf9))
        )
    );
    assert_eq!(state.balance(&sender).unwrap(), U256::from(0xf9));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);
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
        Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;

    let mut params = ActionParams::default();
    params.address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.original_receiver = address;
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

    assert_eq!(gas_left, U256::from(62_976));
    assert_eq!(substate.contracts_created.len(), 0);
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

    let sender =
        Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    // TODO: add tests for 'callcreate'
    //let next_address = contract_address(&address, &U256::zero());
    let mut params = ActionParams::default();
    params.address = address;
    params.code_address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.original_receiver = address;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(100));
    params.call_type = CallType::Call;

    let storage_manager = new_state_manager_for_unit_test();
    let mut state = get_state_for_genesis_write(&storage_manager);
    state
        .add_balance(
            &sender,
            &(U256::from(100)
                + *COLLATERAL_PER_STORAGE_KEY
                + U256::from(15_625_000_000_000_000u64)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(100)
            + *COLLATERAL_PER_STORAGE_KEY
            + U256::from(15_625_000_000_000_000u64)
    );
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
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params, &mut substate).unwrap()
    };
    assert_eq!(state.balance(&sender).unwrap(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(15_625_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY + U256::from(15_625_000_000_000_000u64)
    );

    assert_eq!(gas_left, U256::from(59_752));
}

#[test]
fn test_revert() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let contract_address =
        Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let sender =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();

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
        .commit(BigEndianHash::from_uint(&U256::from(1)))
        .unwrap();

    let mut params = ActionParams::default();
    params.address = contract_address;
    params.sender = sender;
    params.original_sender = sender;
    params.original_receiver = contract_address;
    params.gas = U256::from(20025);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::zero());
    let env = Env::default();
    let machine = crate::machine::new_machine_with_builtin();
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
        state
            .storage_at(
                &contract_address,
                &BigEndianHash::from_uint(&U256::zero())
            )
            .unwrap(),
        BigEndianHash::from_uint(&U256::zero())
    );
}

#[test]
fn test_keccak() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);

    let code = "6064640fffffffff20600055".from_hex().unwrap();

    let sender =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
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
    params.original_receiver = address;
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
        storage_limit: U256::MAX,
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
        let mut nonce_increased = false;
        ex.transact(&t, &mut nonce_increased)
    };

    match res {
        Err(ExecutionError::NotEnoughCash {
            required,
            got,
            actual_gas_cost,
        }) if required == U512::from(100_018)
            && got == U512::from(100_017)
            && correct_cost == actual_gas_cost =>
        {
            ()
        }
        _ => assert!(false, "Expected not enough cash error. {:?}", res),
    }
}

#[test]
fn test_deposit_withdraw_lock() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let sender = Address::zero();
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
            &U256::from(1_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state.add_block_rewards(U256::from(1_000_000_000_000u64));
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(*state.total_staking_tokens(), U256::zero());
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    let mut params = ActionParams::default();
    params.code_address = STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS.clone();
    params.address = params.code_address;
    params.sender = sender;
    params.original_sender = sender;
    params.original_receiver = params.code_address;
    params.gas = U256::from(100000);
    params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e800".from_hex().unwrap());

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
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::zero());
    assert_eq!(state.block_number(), 0);

    // everything is fine
    params.call_type = CallType::Call;
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
        U256::from(900_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

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
        vm::Error::InternalContract("invalid data")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(900_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

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
        vm::Error::InternalContract("invalid data")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(900_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

    // more data
    params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e80000".from_hex().unwrap());
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
        vm::Error::InternalContract("invalid data")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(900_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(
        *state.total_staking_tokens(),
        U256::from(100_000_000_000u64)
    );
    assert_eq!(state.block_number(), 0);

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
        U256::from(950_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(50_000_000_000u64));
    assert_eq!(state.block_number(), 0);
    // withdraw more than staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000000000ba43b7401".from_hex().unwrap());
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
        U256::from(950_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(50_000_000_000u64));
    assert_eq!(state.block_number(), 0);

    // lock 1 for 0 days
    params.data = Some("1338736f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap());
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
        vm::Error::InternalContract("invalid lock duration")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(950_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(50_000_000_000u64));
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    // lock 1 for 106751991167301 days should failed
    params.data = Some("1338736f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000611722833945".from_hex().unwrap());
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
        vm::Error::InternalContract("invalid lock duration")
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(950_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(50_000_000_000u64));
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    // lock 1 for 106751991167301 days, should succeed
    params.data = Some("1338736f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000611722833944".from_hex().unwrap());
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
        U256::from(950_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(50_000_000_000u64));
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(49_999_999_999u64)
    );
    // lock 2 for 1 days
    params.data = Some("1338736f00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001".from_hex().unwrap());
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
        U256::from(950_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(50_000_000_000u64));
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(49_999_999_998u64)
    );
    // withdraw more than withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000000000ba43b7400".from_hex().unwrap());
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
        U256::from(950_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(50_000_000_000u64)
    );
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(50_000_000_000u64));
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(49_999_999_998u64)
    );

    // withdraw exact withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000000000ba43b73fe".from_hex().unwrap());
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
        U256::from(999_999_999_998u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::from(2));
    assert_eq!(
        *state.total_issued_tokens(),
        U256::from(1_000_000_000_000u64)
    );
    assert_eq!(*state.total_staking_tokens(), U256::from(2));
    assert_eq!(
        state.withdrawable_staking_balance(&sender).unwrap(),
        U256::from(0)
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
        &sender.address(),
        &U256::zero(),
        &[],
    )
    .0;

    state.init_code(&address, code, sender.address()).unwrap();
    state
        .add_balance(
            &sender.address(),
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    let mut nonce_increased: bool = false;
    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(1000000),
        action: Action::Call(address),
        storage_limit: U256::MAX,
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
    .transact(&tx, &mut nonce_increased)
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
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
        storage_limit: U256::MAX,
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
    .transact(&tx, &mut nonce_increased)
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&caller3.address()).unwrap(), U256::from(1));
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_976)
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
        storage_limit: U256::MAX,
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
    .transact(&tx, &mut nonce_increased)
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
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
        storage_limit: U256::MAX,
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
    .transact(&tx, &mut nonce_increased)
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
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
        storage_limit: U256::MAX,
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
    .transact(&tx, &mut nonce_increased)
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
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
        storage_limit: U256::MAX,
        epoch_height: 0,
        chain_id: 0,
        data: vec![],
    }
    .sign(caller3.secret());
    assert_eq!(tx.sender(), caller3.address());
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_976)
    );
    let Executed { gas_used, .. } = Executive::new(
        &mut state,
        &env,
        &machine,
        &spec,
        &internal_contract_map,
    )
    .transact(&tx, &mut nonce_increased)
    .unwrap();

    assert_eq!(gas_used, U256::from(58_024));
    assert_eq!(state.nonce(&caller3.address()).unwrap(), U256::from(2));
    assert_eq!(
        state.balance(&caller3.address()).unwrap(),
        U256::from(41_976)
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

    let sender = Address::from_low_u64_ne(1);
    let caller1 = Address::from_low_u64_le(2);
    let caller2 = Address::from_low_u64_le(3);
    let caller3 = Address::from_low_u64_le(4);
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        &sender,
        &U256::zero(),
        &[],
    )
    .0;
    let mut params = ActionParams::default();
    params.address = address;
    params.code_address = address;
    params.sender = sender;
    params.original_sender = sender;
    params.original_receiver = address;
    params.gas = U256::from(100_000);
    params.gas_price = U256::from(1);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(*COLLATERAL_PER_STORAGE_KEY);

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
    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.create(params.clone(), &mut substate).unwrap()
    };
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(substate.storage_collateralized[&sender], 64);

    state
        .set_sponsor_for_collateral(
            &address,
            &sender,
            &COLLATERAL_PER_STORAGE_KEY,
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(gas_left, U256::from(94_983));
    assert_eq!(substate.contracts_created.len(), 0);
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(*state.total_storage_tokens(), *COLLATERAL_PER_STORAGE_KEY);

    state
        .add_balance(
            &caller1,
            &COLLATERAL_PER_STORAGE_KEY,
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller2,
            &COLLATERAL_PER_STORAGE_KEY,
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller3,
            &COLLATERAL_PER_STORAGE_KEY,
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // add privilege to caller1 and caller2
    state.checkpoint();
    state
        .add_commission_privilege(address, sender, caller1)
        .unwrap();
    state
        .add_commission_privilege(address, sender, caller2)
        .unwrap();
    assert_eq!(
        state
            .check_collateral_for_storage(
                &privilege_control_address,
                &U256::MAX,
                &mut substate
            )
            .unwrap(),
        CollateralCheckResult::Valid
    );
    state.discard_checkpoint();
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(substate.storage_collateralized[&sender], 3 * 64);
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_750_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3),
    );
    assert!(state
        .check_commission_privilege(&address, &caller1)
        .unwrap());
    assert!(state
        .check_commission_privilege(&address, &caller2)
        .unwrap());
    assert!(!state
        .check_commission_privilege(&address, &caller3)
        .unwrap());

    params.call_type = CallType::Call;
    params.value = ActionValue::Transfer(U256::zero());

    // call with no privilege
    assert_eq!(
        state.balance(&caller3).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    params.sender = caller3;
    params.original_sender = caller3;
    let mut substate = Substate::new();
    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params.clone(), &mut substate).unwrap()
    };
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(substate.storage_collateralized[&caller3], 64);
    assert_eq!(substate.storage_released.len(), 1);
    assert_eq!(substate.storage_released[&sender], 64);
    assert_eq!(gas_left, U256::from(94983));
    assert_eq!(state.balance(&caller3).unwrap(), U256::zero());
    assert_eq!(state.staking_balance(&caller3).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&caller3).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );

    // call with privilege
    assert_eq!(
        state.balance(&caller1).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    params.sender = caller1;
    params.original_sender = caller1;
    let mut substate = Substate::new();
    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params.clone(), &mut substate).unwrap()
    };
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(substate.storage_collateralized[&address], 64);
    assert_eq!(substate.storage_released.len(), 1);
    assert_eq!(substate.storage_released[&caller3], 64);
    assert_eq!(gas_left, U256::from(94983));
    assert_eq!(
        state.balance(&caller1).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(state.staking_balance(&caller1).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&caller1).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        U256::zero()
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&caller3).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.staking_balance(&caller3).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&caller3).unwrap(),
        U256::zero()
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );

    // another caller call with commission privilege and not enough sponsor
    // balance, the owner will transfer to caller2.
    assert_eq!(
        state.balance(&caller2).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    params.sender = caller2;
    params.original_sender = caller2;
    let mut substate = Substate::new();
    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params.clone(), &mut substate).unwrap()
    };
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(substate.storage_collateralized[&caller2], 64);
    assert_eq!(substate.storage_released.len(), 1);
    assert_eq!(substate.storage_released[&address], 64);
    assert_eq!(gas_left, U256::from(94983));
    assert_eq!(state.balance(&caller2).unwrap(), U256::from(0),);
    assert_eq!(state.staking_balance(&caller2).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&caller2).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::from(0),
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2),
    );

    // remove privilege from caller1
    state
        .remove_commission_privilege(address, sender, caller1)
        .unwrap();
    assert!(!state
        .check_commission_privilege(&address, &caller1)
        .unwrap());
    assert_eq!(
        state.balance(&caller1).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    params.sender = caller1;
    params.original_sender = caller1;
    let mut substate = Substate::new();
    let FinalizationResult { gas_left, .. } = {
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        ex.call(params.clone(), &mut substate).unwrap()
    };
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(substate.storage_collateralized[&caller1], 64);
    assert_eq!(substate.storage_released.len(), 2);
    assert_eq!(substate.storage_released[&sender], 64);
    assert_eq!(substate.storage_released[&caller2], 64);
    assert_eq!(gas_left, U256::from(94983));
    assert_eq!(state.balance(&caller1).unwrap(), U256::zero());
    assert_eq!(state.staking_balance(&caller1).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&caller1).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.collateral_for_storage(&caller2).unwrap(),
        U256::from(0),
    );
    assert_eq!(
        state.balance(&caller2).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY
    );
    assert_eq!(
        state.sponsor_balance_for_collateral(&address).unwrap(),
        *COLLATERAL_PER_STORAGE_KEY,
    );
    assert_eq!(state.staking_balance(&address).unwrap(), U256::zero());
    assert_eq!(
        state.collateral_for_storage(&address).unwrap(),
        U256::zero()
    );
    assert_eq!(
        *state.total_storage_tokens(),
        *COLLATERAL_PER_STORAGE_KEY * U256::from(2)
    );
}
