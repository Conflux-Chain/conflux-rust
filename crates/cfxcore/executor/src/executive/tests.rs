// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use crate::{
    machine::{Machine, VmFactory},
    state::{get_state_by_epoch_id, get_state_for_genesis_write, CleanupMode},
    substate::Substate,
};
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::{
    internal_contract_addresses::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    staking::*,
};
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, BigEndianHash, U256,
    U512,
};
use cfx_vm_interpreter::{FinalizationResult, GasPriceTier};
use cfx_vm_types::{
    self as vm, ActionParams, ActionValue, CallType, CreateContractAddress,
    CreateType, Env,
};
use cfxkey::{Generator, Random};
use primitives::{
    storage::STORAGE_LAYOUT_REGULAR_V0,
    transaction::{native_transaction::NativeTransaction, Action},
    EpochId, Transaction,
};
use rustc_hex::FromHex;
use std::{
    cmp::{self, min},
    str::FromStr,
    sync::Arc,
};

#[cfg(test)]
fn make_byzantium_machine(max_depth: usize) -> Machine {
    let mut machine = crate::machine::Machine::new_with_builtin(
        Default::default(),
        VmFactory::new(1024 * 32),
    );
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
            /* block_number = */ 0,
            &address.with_native_space(),
            &U256::from(88),
            &[],
        )
        .0
        .address
    );
}

#[test]
fn test_sender_balance() {
    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let sender_with_space = sender.with_native_space();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;
    let mut params = ActionParams::default();
    params.address = address.address;
    params.code_address = address.address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new("3331600055".from_hex().unwrap()));
    params.value = ActionValue::Transfer(U256::from(0x7));
    params.create_type = CreateType::CREATE;
    let storage_limit_in_drip = U256::MAX;
    let mut state = get_state_for_genesis_write();
    state
        .add_balance(
            &sender_with_space,
            &COLLATERAL_DRIPS_PER_STORAGE_KEY,
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &sender_with_space,
            &U256::from(0x100u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(0x100)
    );
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        state.checkpoint();
        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let mut tracer = ();
        let res = ex
            .call_for_test(params.clone(), &mut substate, &mut tracer)
            .expect("no db error")
            .expect("no vm error");
        state
            .settle_collateral_and_check(
                &params.storage_owner,
                &storage_limit_in_drip,
                &mut substate,
                &mut tracer,
                &spec,
                false,
            )
            .unwrap()
            .unwrap();
        state.discard_checkpoint();
        res
    };

    assert_eq!(gas_left, U256::from(94_595));
    assert_eq!(
        state.storage_at(&address, &vec![0; 32]).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(0xf9)
    );
    assert_eq!(state.balance(&sender_with_space).unwrap(), U256::from(0xf9));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(state.balance(&address).unwrap(), U256::from(0x7));
    // We create a contract successfully, the substate contracts_created length
    // should be 1?
    assert_eq!(substate.contracts_created.len(), 1);
}

#[test]
fn test_create_contract_out_of_depth() {
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
    let sender_with_space = sender.with_native_space();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;

    let mut params = ActionParams::default();
    params.address = address.address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(100));
    params.create_type = CreateType::CREATE;

    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);

    let mut state = get_state_for_genesis_write();
    state
        .add_balance(&sender_with_space, &U256::from(100), CleanupMode::NoEmpty)
        .unwrap();
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let mut tracer = ();
        ex.call_for_test(params, &mut substate, &mut tracer)
            .expect("no db error")
            .expect("no vm error")
    };

    assert_eq!(gas_left, U256::from(62_970));
    // We create a contract successfully, the substate contracts_created length
    // should be 1?
    assert_eq!(substate.contracts_created.len(), 1);
}

#[test]
fn test_suicide_when_creation() {
    // code:
    //
    // 33 - get caller address
    // ff - self-deconstruct

    let code = "33ff".from_hex().unwrap();

    let sender_addr =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let sender_with_space = sender_addr.with_native_space();
    let contract_addr = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;

    let mut params = ActionParams::default();
    params.address = contract_addr.address;
    params.sender = sender_addr;
    params.original_sender = sender_addr;
    params.storage_owner = sender_addr;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(0));

    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);

    let mut state = get_state_for_genesis_write();
    state
        .add_balance(
            &sender_with_space,
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let mut substate = Substate::new();

    let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
    let mut tracer = ();
    let FinalizationResult {
        gas_left,
        apply_state,
        return_data: _,
        ..
    } = ex
        .call_for_test(params, &mut substate, &mut tracer)
        .expect("no db error")
        .expect("no vm error");

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

    let code: Vec<u8> = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();
    let code_len = code.len();

    let sender =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let sender_with_space = sender.with_native_space();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;
    // TODO: add tests for 'callcreate'
    let mut params = ActionParams::default();
    params.address = address.address;
    params.code_address = address.address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = sender;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::from(100));
    params.call_type = CallType::Call;
    let storage_limit_in_drip = *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        * code_collateral_units(code_len)
        + *COLLATERAL_DRIPS_PER_STORAGE_KEY;

    let env = Env::default();
    let machine = make_byzantium_machine(5);
    let spec = machine.spec_for_test(env.number);

    let mut state = get_state_for_genesis_write();
    state
        .new_contract_with_code(&address, U256::zero())
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state
        .add_balance(
            &sender_with_space,
            &(U256::from(100) + storage_limit_in_drip),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        U256::from(0)
    );
    assert_eq!(state.total_storage_tokens(), U256::from(0));
    let mut substate = Substate::new();

    let FinalizationResult { gas_left, .. } = {
        state.checkpoint();
        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let mut tracer = ();
        let res = ex
            .call_for_test(params.clone(), &mut substate, &mut tracer)
            .expect("no db error")
            .expect("no vm error");
        state
            .settle_collateral_and_check(
                &params.storage_owner,
                &storage_limit_in_drip,
                &mut substate,
                &mut tracer,
                &spec,
                false,
            )
            .unwrap()
            .unwrap();
        state.discard_checkpoint();
        res
    };
    assert_eq!(state.balance(&sender_with_space).unwrap(), U256::from(0));
    assert_eq!(
        state.collateral_for_storage(&sender).unwrap(),
        storage_limit_in_drip
    );
    assert_eq!(state.total_storage_tokens(), storage_limit_in_drip);

    assert_eq!(gas_left, U256::from(59_746));
}

#[test]
fn test_revert() {
    let contract_address =
        Address::from_str("8d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let contract_address_with_space = contract_address.with_native_space();
    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let sender_with_space = sender.with_native_space();

    let code: Vec<u8> = "6c726576657274656420646174616000557f726576657274206d657373616765000000000000000000000000000000000000600052600e6000fd".from_hex().unwrap();
    let returns: Vec<u8> = "726576657274206d657373616765".from_hex().unwrap();

    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);
    let mut substate = Substate::new();

    let mut state = get_state_for_genesis_write();
    state
        .add_balance(
            &sender_with_space,
            &U256::from_str("152d02c7e14af68000000").unwrap(),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .new_contract_with_code(&contract_address_with_space, U256::zero())
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state
        .commit_for_test(BigEndianHash::from_uint(&U256::from(1)))
        .unwrap();

    let mut params = ActionParams::default();
    params.address = contract_address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = contract_address;
    params.gas = U256::from(20025);
    params.code = Some(Arc::new(code));
    params.value = ActionValue::Transfer(U256::zero());
    let mut output = [0u8; 14];
    let FinalizationResult {
        gas_left: result,
        return_data,
        ..
    } = {
        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let mut tracer = ();
        ex.call_for_test(params, &mut substate, &mut tracer)
            .expect("no db error")
            .expect("no vm error")
    };
    (&mut output)
        .copy_from_slice(&return_data[..(cmp::min(14, return_data.len()))]);

    assert_eq!(result, U256::from(15_001));
    assert_eq!(output[..], returns[..]);
    assert_eq!(
        state
            .storage_at(&contract_address_with_space, &vec![0; 32])
            .unwrap(),
        U256::zero()
    );
}

#[test]
fn test_keccak() {
    let code = "6064640fffffffff20600055".from_hex().unwrap();

    let sender =
        Address::from_str("1f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let sender_with_space = sender.with_native_space();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;
    // TODO: add tests for 'callcreate'
    //let next_address = contract_address(&address, &U256::zero());
    let mut params = ActionParams::default();
    params.address = address.address;
    params.sender = sender;
    params.original_sender = sender;
    params.storage_owner = address.address;
    params.gas = U256::from(0x0186a0);
    params.code = Some(Arc::new(code));
    params.value =
        ActionValue::Transfer(U256::from_str("0de0b6b3a7640000").unwrap());

    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);

    let mut state = get_state_for_genesis_write();
    state
        .add_balance(
            &sender_with_space,
            &U256::from_str("152d02c7e14af6800000").unwrap(),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let mut substate = Substate::new();

    let mut tracer = ();
    let result = {
        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        ex.call_for_test(params, &mut substate, &mut tracer)
            .expect("no db error")
    };

    match result {
        Err(_) => {}
        _ => panic!("Expected OutOfGas"),
    }
}

#[test]
fn test_not_enough_cash() {
    let keypair = Random.generate().unwrap();
    let t = Transaction::from(NativeTransaction {
        action: Action::Create,
        value: U256::from(18),
        data: "3331600055".from_hex().unwrap(),
        gas: U256::from(100_000),
        gas_price: U256::one(),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        nonce: U256::zero(),
    })
    .sign(keypair.secret());
    let sender = t.sender();

    let mut env = Env::default();
    env.gas_limit = U256::from(100_000);
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);

    let mut state = get_state_for_genesis_write();
    state
        .add_balance(&sender, &U256::from(100_017), CleanupMode::NoEmpty)
        .unwrap();
    let correct_cost = min(t.gas_price() * t.gas(), 100_017.into());

    let res = {
        let ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let options = TransactOptions::default();
        ex.transact(&t, options).unwrap()
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
    let mut sender = Address::zero();
    sender.set_user_account_type_bits();
    let sender_with_space = sender.with_native_space();
    let mut state = get_state_for_genesis_write();
    let env = Env::default();
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);
    let mut substate = Substate::new();
    state
        .add_balance(
            &sender_with_space,
            &U256::from(2_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state.add_total_issued(U256::from(2_000_000_000_000_000_000u64));
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(state.total_staking_tokens(), U256::zero());
    assert_eq!(
        state.total_issued_tokens(),
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
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer)
        .expect("no db error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("Incorrect call type.".into())
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::zero());
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.total_staking_tokens(), U256::zero());

    // deposit 10^18 - 1, not enough
    params.call_type = CallType::Call;
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a763ffff".from_hex().unwrap());

    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer)
        .expect("no db error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid deposit amount".into())
    );

    // deposit 10^18, it should work fine
    params.data = Some("b6b55f250000000000000000000000000000000000000000000000000de0b6b3a7640000".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );

    // empty data
    params.data = None;
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer)
        .expect("no db error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("ABI decode error: None call data".into())
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );

    // less data
    params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e8".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer)
        .expect("no db error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract(
            "ABI decode error: Incomplete static input parameter".into()
        )
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(1_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(1_000_000_000_000_000_000u64)
    );

    // withdraw
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000000000ba43b7400".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    // withdraw more than staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288c01".from_hex().unwrap());

    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer)
        .expect("no db error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw".into()
        )
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );

    // lock until block_number = 0
    params.data = Some("44a51d6d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer)
        .expect("no db error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract("invalid unlock_block_number".into())
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state
            .withdrawable_staking_balance(&sender, env.number)
            .unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    // lock 1 until 106751991167301 blocks, should succeed
    params.data = Some("44a51d6d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000611722833944".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state
            .withdrawable_staking_balance(&sender, env.number)
            .unwrap(),
        U256::from(999_999_949_999_999_999u64)
    );
    // lock 2 until block_number=2
    params.data = Some("44a51d6d00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state
            .withdrawable_staking_balance(&sender, env.number)
            .unwrap(),
        U256::from(999_999_949_999_999_998u64)
    );
    // withdraw more than withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288bff".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer)
        .expect("no db error");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw".into()
        )
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_000_000_050_000_000_000u64)
    );
    assert_eq!(
        state.staking_balance(&sender).unwrap(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(
        state.total_staking_tokens(),
        U256::from(999_999_950_000_000_000u64)
    );
    assert_eq!(
        state
            .withdrawable_staking_balance(&sender, env.number)
            .unwrap(),
        U256::from(999_999_949_999_999_998u64)
    );

    // withdraw exact withdrawable staking balance
    params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000de0b6a803288bfe".from_hex().unwrap());
    let mut tracer = ();
    let result = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .call_for_test(params.clone(), &mut substate, &mut tracer);
    assert!(result.is_ok());
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_999_999_999_999_999_998u64)
    );
    assert_eq!(state.staking_balance(&sender).unwrap(), U256::from(2));
    assert_eq!(
        state.total_issued_tokens(),
        U256::from(2_000_000_000_000_000_000u64)
    );
    assert_eq!(state.total_staking_tokens(), U256::from(2));
    assert_eq!(
        state
            .withdrawable_staking_balance(&sender, env.number)
            .unwrap(),
        U256::from(0)
    );
}

#[test]
fn test_commission_privilege_all_whitelisted_across_epochs() {
    let code: Vec<u8> = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let mut state = get_state_for_genesis_write();
    let machine = make_byzantium_machine(0);
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let spec = machine.spec_for_test(env.number);

    let sender = Random.generate().unwrap().address();
    let sender_with_space = sender.with_native_space();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;

    state.checkpoint();
    let mut substate = Substate::new();
    state
        .new_contract_with_admin(
            &address,
            &sender,
            U256::zero(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
            false,
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state.init_code(&address, code.clone(), sender).unwrap();
    state
        .add_balance(
            &sender_with_space,
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    state
        .add_to_contract_whitelist(
            address.address,
            sender,
            Default::default(),
            &mut substate,
        )
        .unwrap();
    let epoch_id = EpochId::from_uint(&U256::from(1));
    state
        .settle_collateral_and_check(
            &Address::default(),
            &0.into(),
            &mut substate,
            &mut (),
            &spec,
            false,
        )
        .unwrap()
        .unwrap();
    state.discard_checkpoint();
    let mut debug_record = ComputeEpochDebugRecord::default();
    state.commit(epoch_id, Some(&mut debug_record)).unwrap();
    debug!("{:?}", debug_record);

    let mut state = get_state_by_epoch_id(&epoch_id);

    state.checkpoint();
    let mut substate = Substate::new();
    assert_eq!(
        true,
        state
            .check_contract_whitelist(&address.address, &sender)
            .unwrap()
    );
    assert_eq!(
        true,
        state
            .check_contract_whitelist(&address.address, &Default::default())
            .unwrap()
    );
    let epoch_id = EpochId::from_uint(&U256::from(2));
    // Destroy the contract, then create again.
    state.remove_contract(&address).unwrap();
    state.discard_checkpoint();
    state
        .settle_collateral_and_check(
            &sender,
            &U256::MAX,
            &mut substate,
            &mut (),
            &spec,
            false,
        )
        .unwrap()
        .unwrap();
    state
        .clear_contract_whitelist(&address.address, &mut substate)
        .unwrap();

    state.checkpoint();
    let mut substate = Substate::new();
    state
        .new_contract_with_admin(
            &address,
            &sender,
            U256::zero(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
            false,
        )
        .unwrap();
    state.init_code(&address, code, sender).unwrap();
    state
        .add_balance(
            &sender_with_space,
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    let whitelisted_caller = Address::random();
    state
        .add_to_contract_whitelist(
            address.address,
            sender,
            whitelisted_caller,
            &mut substate,
        )
        .unwrap();
    assert_eq!(
        true,
        state
            .check_contract_whitelist(&address.address, &whitelisted_caller)
            .unwrap()
    );
    assert_eq!(
        false,
        state
            .check_contract_whitelist(&address.address, &Default::default())
            .unwrap()
    );
    state
        .settle_collateral_and_check(
            &Address::default(),
            &0.into(),
            &mut substate,
            &mut (),
            &spec,
            false,
        )
        .unwrap()
        .unwrap();
    state.discard_checkpoint();
    state.commit_for_test(epoch_id).unwrap();

    assert_eq!(
        true,
        state
            .check_contract_whitelist(&address.address, &whitelisted_caller)
            .unwrap()
    );
    assert_eq!(
        false,
        state
            .check_contract_whitelist(&address.address, &Default::default())
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

    let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

    let mut state = get_state_for_genesis_write();
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);

    let sender_key = Random.generate().unwrap();
    let sender = sender_key.address();
    let sender_with_space = sender.with_native_space();
    let caller1 = Random.generate().unwrap();
    let caller2 = Random.generate().unwrap();
    let caller3 = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;

    state
        .new_contract_with_admin(
            &address,
            &sender,
            U256::zero(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
            false,
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state.init_code(&address, code, sender).unwrap();
    state
        .add_balance(
            &sender_with_space,
            &U256::from(1_000_000_000_000_000_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(1000000),
        action: Action::Call(address.address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(sender_key.secret());
    assert_eq!(tx.sender().address, sender);
    let options = TransactOptions::default();
    let Executed { gas_used, .. } =
        ExecutiveContext::new(&mut state, &env, &machine, &spec)
            .transact(&tx, options)
            .unwrap()
            .into_success_executed()
            .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(state.nonce(&sender_with_space).unwrap(), U256::from(1));
    assert_eq!(state.balance(&address).unwrap(), U256::from(1_000_000));
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(999_999_999_998_925_000u64)
    );

    state
        .add_balance(
            &caller1.address().with_native_space(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller2.address().with_native_space(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller3.address().with_native_space(),
            &U256::from(100_000),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    // add commission privilege to caller1 and caller2
    state
        .add_to_contract_whitelist(
            address.address,
            sender,
            caller1.address(),
            &mut Substate::new(),
        )
        .unwrap();
    state
        .add_to_contract_whitelist(
            address.address,
            sender,
            caller2.address(),
            &mut Substate::new(),
        )
        .unwrap();
    assert!(state
        .check_contract_whitelist(&address.address, &caller1.address())
        .unwrap());
    assert!(state
        .check_contract_whitelist(&address.address, &caller2.address())
        .unwrap());
    assert!(!state
        .check_contract_whitelist(&address.address, &caller3.address())
        .unwrap());
    state
        .set_sponsor_for_gas(
            &address.address,
            &sender,
            &U256::from(110_000),
            &U256::from(110_000),
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_gas(&address.address).unwrap(),
        U256::from(110_000)
    );
    assert_eq!(
        state.sponsor_gas_bound(&address.address).unwrap(),
        U256::from(110_000)
    );

    // call with no commission privilege
    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(60_000),
        value: U256::zero(),
        action: Action::Call(address.address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller3.secret());
    assert_eq!(tx.sender().address, caller3.address());
    assert_eq!(
        state
            .balance(&caller3.address().with_native_space())
            .unwrap(),
        U256::from(100_000)
    );
    let options = TransactOptions::default();
    let Executed { gas_used, .. } =
        ExecutiveContext::new(&mut state, &env, &machine, &spec)
            .transact(&tx, options)
            .unwrap()
            .into_success_executed()
            .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(
        state.nonce(&caller3.address().with_native_space()).unwrap(),
        U256::from(1)
    );
    assert_eq!(
        state
            .balance(&caller3.address().with_native_space())
            .unwrap(),
        U256::from(41_970)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address.address).unwrap(),
        U256::from(110_000)
    );

    // call with commission privilege and enough commission balance
    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address.address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller1.secret());
    assert_eq!(tx.sender().address, caller1.address());
    assert_eq!(
        state
            .balance(&caller1.address().with_native_space())
            .unwrap(),
        U256::from(100_000)
    );
    let options = TransactOptions::default();
    let Executed { gas_used, .. } =
        ExecutiveContext::new(&mut state, &env, &machine, &spec)
            .transact(&tx, options)
            .unwrap()
            .into_success_executed()
            .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(
        state.nonce(&caller1.address().with_native_space()).unwrap(),
        U256::from(1)
    );
    assert_eq!(
        state
            .balance(&caller1.address().with_native_space())
            .unwrap(),
        U256::from(100_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address.address).unwrap(),
        U256::from(35_000)
    );

    // call with commission privilege and not enough commission balance
    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address.address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller2.secret());
    assert_eq!(tx.sender().address, caller2.address());
    assert_eq!(
        state
            .balance(&caller2.address().with_native_space())
            .unwrap(),
        U256::from(100_000)
    );
    let options = TransactOptions::default();
    let Executed { gas_used, .. } =
        ExecutiveContext::new(&mut state, &env, &machine, &spec)
            .transact(&tx, options)
            .unwrap()
            .into_success_executed()
            .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(
        state.nonce(&caller2.address().with_native_space()).unwrap(),
        U256::from(1)
    );
    assert_eq!(
        state
            .balance(&caller2.address().with_native_space())
            .unwrap(),
        U256::from(25_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address.address).unwrap(),
        U256::from(35_000)
    );

    // add more commission balance
    state
        .set_sponsor_for_gas(
            &address.address,
            &sender,
            &U256::from(200_000),
            &U256::from(200_000),
        )
        .unwrap();
    assert_eq!(
        state.sponsor_balance_for_gas(&address.address).unwrap(),
        U256::from(200_000)
    );

    // call with commission privilege and enough commission balance
    let tx = Transaction::from(NativeTransaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address.address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller2.secret());
    assert_eq!(tx.sender().address, caller2.address());
    assert_eq!(
        state
            .balance(&caller2.address().with_native_space())
            .unwrap(),
        U256::from(25_000)
    );
    let options = TransactOptions::default();
    let Executed { gas_used, .. } =
        ExecutiveContext::new(&mut state, &env, &machine, &spec)
            .transact(&tx, options)
            .unwrap()
            .into_success_executed()
            .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(
        state.nonce(&caller2.address().with_native_space()).unwrap(),
        U256::from(2)
    );
    assert_eq!(
        state
            .balance(&caller2.address().with_native_space())
            .unwrap(),
        U256::from(25_000)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address.address).unwrap(),
        U256::from(125_000)
    );

    // add commission privilege to caller3
    state
        .add_to_contract_whitelist(
            address.address,
            sender,
            caller3.address(),
            &mut Substate::new(),
        )
        .unwrap();
    assert!(state
        .check_contract_whitelist(&address.address, &caller3.address())
        .unwrap());
    // call with commission privilege and enough commission balance
    let tx = Transaction::from(NativeTransaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::zero(),
        action: Action::Call(address.address),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller3.secret());
    assert_eq!(tx.sender().address, caller3.address());
    assert_eq!(
        state
            .balance(&caller3.address().with_native_space())
            .unwrap(),
        U256::from(41_970)
    );
    let options = TransactOptions::default();
    let Executed { gas_used, .. } =
        ExecutiveContext::new(&mut state, &env, &machine, &spec)
            .transact(&tx, options)
            .unwrap()
            .into_success_executed()
            .unwrap();

    assert_eq!(gas_used, U256::from(58_030));
    assert_eq!(
        state.nonce(&caller3.address().with_native_space()).unwrap(),
        U256::from(2)
    );
    assert_eq!(
        state
            .balance(&caller3.address().with_native_space())
            .unwrap(),
        U256::from(41_970)
    );
    assert_eq!(
        state.sponsor_balance_for_gas(&address.address).unwrap(),
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

    // let privilege_control_address =
    // &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
    let code = "7c601080600c6000396000f3006000355415600957005b6020356000355560005233600155".from_hex().unwrap();

    let mut state = get_state_for_genesis_write();
    let mut env = Env::default();
    env.gas_limit = U256::MAX;
    let machine = make_byzantium_machine(0);
    let spec = machine.spec_for_test(env.number);

    let sender = Random.generate().unwrap();
    let sender_with_space = sender.address().with_native_space();
    let caller1 = Random.generate().unwrap();
    let caller2 = Random.generate().unwrap();
    let caller3 = Random.generate().unwrap();
    let address = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;

    state
        .new_contract_with_admin(
            &address,
            &sender.address(),
            U256::zero(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
            false,
        )
        .expect(&concat!(file!(), ":", line!(), ":", column!()));
    state.init_code(&address, code, sender.address()).unwrap();

    state
        .add_balance(
            &sender_with_space,
            &U256::from(2_000_000_000_000_075_000u64),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // simple call to create a storage entry
    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: *COLLATERAL_DRIPS_PER_STORAGE_KEY,
        action: Action::Call(address.address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(sender.secret());
    assert_eq!(tx.sender().address, sender.address());
    let options = TransactOptions::default();
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .transact(&tx, options)
        .unwrap()
        .into_success_executed()
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
            &address.address,
            &sender.address(),
            &COLLATERAL_DRIPS_PER_STORAGE_KEY,
            false,
        )
        .unwrap();
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&address.address)
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state.balance(&address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );

    state
        .add_balance(
            &caller1.address().with_native_space(),
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller2.address().with_native_space(),
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();
    state
        .add_balance(
            &caller3.address().with_native_space(),
            &(*COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000)),
            CleanupMode::NoEmpty,
        )
        .unwrap();

    // add privilege to caller1 and caller2
    let mut substate = Substate::new();
    state.checkpoint();
    state
        .add_to_contract_whitelist(
            address.address,
            sender.address(),
            caller1.address(),
            &mut substate,
        )
        .unwrap();
    state
        .add_to_contract_whitelist(
            address.address,
            sender.address(),
            caller2.address(),
            &mut substate,
        )
        .unwrap();

    state
        .settle_collateral_and_check(
            &sender.address(),
            &U256::MAX,
            &mut substate,
            &mut (),
            &spec,
            false,
        )
        .unwrap()
        .unwrap();

    state.discard_checkpoint();
    assert_eq!(substate.storage_collateralized.len(), 1);
    assert_eq!(
        substate.storage_collateralized[&sender.address()],
        2 * COLLATERAL_UNITS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_750_000_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3),
    );
    assert!(state
        .check_contract_whitelist(&address.address, &caller1.address())
        .unwrap());
    assert!(state
        .check_contract_whitelist(&address.address, &caller2.address())
        .unwrap());
    assert!(!state
        .check_contract_whitelist(&address.address, &caller3.address())
        .unwrap());

    // caller3 call with no privilege
    assert_eq!(
        state
            .balance(&caller3.address().with_native_space())
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000),
    );
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&address.address)
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address.address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller3.secret());
    assert_eq!(tx.sender().address, caller3.address());
    let options = TransactOptions::default();
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .transact(&tx, options)
        .unwrap()
        .into_success_executed()
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
        state
            .sponsor_balance_for_collateral(&address.address)
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state
            .balance(&caller3.address().with_native_space())
            .unwrap(),
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
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );

    // caller1 call with privilege
    assert_eq!(
        state
            .balance(&caller1.address().with_native_space())
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000),
    );
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&address.address)
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address.address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller1.secret());
    assert_eq!(tx.sender().address, caller1.address());
    let options = TransactOptions::default();
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .transact(&tx, options)
        .unwrap()
        .into_success_executed()
        .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, address.address);
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
        state
            .balance(&caller1.address().with_native_space())
            .unwrap(),
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
        state
            .sponsor_balance_for_collateral(&address.address)
            .unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.staking_balance(&address.address).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&address.address).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state
            .balance(&caller3.address().with_native_space())
            .unwrap(),
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
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );

    // caller2 call with commission privilege and not enough sponsor
    // balance, the owner will transfer to caller2.
    assert_eq!(
        state
            .balance(&caller2.address().with_native_space())
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(1000_000),
    );
    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address.address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller2.secret());
    assert_eq!(tx.sender().address, caller2.address());
    let options = TransactOptions::default();
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .transact(&tx, options)
        .unwrap()
        .into_success_executed()
        .unwrap();

    assert_eq!(storage_collateralized.len(), 1);
    assert_eq!(storage_collateralized[0].address, caller2.address());
    assert_eq!(
        storage_collateralized[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(storage_released.len(), 1);
    assert_eq!(storage_released[0].address, address.address);
    assert_eq!(
        storage_released[0].collaterals,
        COLLATERAL_UNITS_PER_STORAGE_KEY.into()
    );
    assert_eq!(gas_used, U256::from(26_017));
    assert_eq!(
        state
            .balance(&caller2.address().with_native_space())
            .unwrap(),
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
        state
            .sponsor_balance_for_collateral(&address.address)
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY
    );
    assert_eq!(
        state.staking_balance(&address.address).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&address.address).unwrap(),
        U256::from(0),
    );
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(3)
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_812_500_000_000_000_000u64)
    );
    assert_eq!(
        state.collateral_for_storage(&sender.address()).unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2),
    );

    // remove privilege from caller1
    state.checkpoint();
    let mut substate = Substate::new();
    state
        .remove_from_contract_whitelist(
            address.address,
            sender.address(),
            caller1.address(),
            &mut substate,
        )
        .unwrap();
    state
        .settle_collateral_and_check(
            &sender.address(),
            &U256::MAX,
            &mut substate,
            &mut (),
            &spec,
            false,
        )
        .unwrap()
        .unwrap();

    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
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
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
    assert_eq!(
        state.balance(&sender_with_space).unwrap(),
        U256::from(1_875_000_000_000_000_000u64)
    );

    assert!(!state
        .check_contract_whitelist(&address.address, &caller1.address())
        .unwrap());

    assert_eq!(
        state
            .balance(&caller1.address().with_native_space())
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(925_000),
    );
    let tx = Transaction::from(NativeTransaction {
        nonce: 1.into(),
        gas_price: U256::from(1),
        gas: U256::from(100_000),
        value: U256::from(0),
        action: Action::Call(address.address),
        storage_limit: COLLATERAL_UNITS_PER_STORAGE_KEY,
        epoch_height: 0,
        chain_id: 1,
        data: vec![],
    })
    .sign(caller1.secret());
    assert_eq!(tx.sender().address, caller1.address());
    let options = TransactOptions::default();
    let Executed {
        gas_used,
        storage_collateralized,
        storage_released,
        ..
    } = ExecutiveContext::new(&mut state, &env, &machine, &spec)
        .transact(&tx, options)
        .unwrap()
        .into_success_executed()
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
        state
            .balance(&caller1.address().with_native_space())
            .unwrap(),
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
        state
            .balance(&caller2.address().with_native_space())
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY + U256::from(925_000),
    );
    assert_eq!(
        state
            .sponsor_balance_for_collateral(&address.address)
            .unwrap(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY,
    );
    assert_eq!(
        state.staking_balance(&address.address).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.collateral_for_storage(&address.address).unwrap(),
        U256::zero()
    );
    assert_eq!(
        state.total_storage_tokens(),
        *COLLATERAL_DRIPS_PER_STORAGE_KEY * U256::from(2)
    );
}

#[test]
fn test_push0() {
    let sender_addr =
        Address::from_str("1d1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let sender_with_space = sender_addr.with_native_space();
    let contract_addr = contract_address(
        CreateContractAddress::FromSenderNonceAndCodeHash,
        /* block_number = */ 0,
        &sender_with_space,
        &U256::zero(),
        &[],
    )
    .0;

    let mut params = ActionParams::default();
    params.address = contract_addr.address;
    params.sender = sender_addr;
    params.original_sender = sender_addr;
    params.storage_owner = sender_addr;
    params.gas = U256::from(10000);
    params.value = ActionValue::Transfer(U256::from(0));

    let env = Env::default();
    let machine = make_byzantium_machine(0);

    let mut state = get_state_for_genesis_write();

    // Test case 1 in EIP-3855
    {
        let mut spec = machine.spec_for_test(env.number);
        spec.cip119 = true;

        // code:
        //
        // 5f - push0
        let mut params = params.clone();
        params.code = Some(Arc::new([0x5f].to_vec()));

        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let FinalizationResult {
            gas_left,
            apply_state,
            return_data: _,
            ..
        } = ex
            .call_for_test(params, &mut Substate::new(), &mut ())
            .expect("no db error")
            .expect("no vm error");

        let base_gas = spec.tier_step_gas[GasPriceTier::Base.idx()];
        assert_eq!(gas_left, U256::from(10000 - base_gas));
        assert_eq!(apply_state, true);
    }

    // Test case 2 in EIP-3855
    {
        let mut spec = machine.spec_for_test(env.number);
        spec.cip119 = true;

        // code:
        //
        // 5f * 1024 - push0 * 1024
        let mut params = params.clone();
        params.code = Some(Arc::new([0x5f; 1024].to_vec()));

        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let FinalizationResult {
            gas_left,
            apply_state,
            return_data: _,
            ..
        } = ex
            .call_for_test(params, &mut Substate::new(), &mut ())
            .expect("no db error")
            .expect("no vm error");

        let base_gas = spec.tier_step_gas[GasPriceTier::Base.idx()];
        assert_eq!(gas_left, U256::from(10000 - base_gas * 1024));
        assert_eq!(apply_state, true);
    }

    // Test case 2 in EIP-3855
    {
        let mut spec = machine.spec_for_test(env.number);
        spec.cip119 = true;

        // code:
        //
        // 5f * 1025 - push0 * 1025
        let mut params = params.clone();
        params.code = Some(Arc::new([0x5f; 1025].to_vec()));

        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let error = ex
            .call_for_test(params, &mut Substate::new(), &mut ())
            .expect("no db error")
            .expect_err("should fail");

        assert!(matches!(error, vm::Error::OutOfStack { .. }));
    }

    // Before activation of EIP-3855 (CIP119)
    {
        let mut spec = machine.spec_for_test(env.number);
        spec.cip119 = false;

        // code:
        //
        // 5f - push0
        let mut params = params.clone();
        params.code = Some(Arc::new([0x5f; 1025].to_vec()));

        let mut ex = ExecutiveContext::new(&mut state, &env, &machine, &spec);
        let error = ex
            .call_for_test(params, &mut Substate::new(), &mut ())
            .expect("no db error")
            .expect_err("should fail");

        assert!(matches!(error, vm::Error::BadInstruction { .. }));
    }
}
