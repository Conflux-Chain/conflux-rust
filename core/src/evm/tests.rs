// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{factory::Factory, vmtype::VMType};
use crate::{
    evm::interpreter::MAX_SUB_STACK_SIZE,
    vm::{
        self,
        tests::{test_finalize, MockCall, MockCallType, MockContext},
        ActionParams, ActionValue, Context,
    },
};
use cfx_types::{Address, H256, U256};
use rustc_hex::FromHex;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    str::FromStr,
    sync::Arc,
};

evm_test! {test_add: test_add_int}
fn test_add(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let code = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_988));
    assert_store(
        &ctx,
        0,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    );
}

evm_test! {test_sha3: test_sha3_int}
fn test_sha3(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let code = "6000600020600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_961));
    assert_store(
        &ctx,
        0,
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    );
}

evm_test! {test_address: test_address_int}
fn test_address(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let code = "30600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000f572e5295c57f15886f9b263e2f6d2d6c7b5ec6",
    );
}

evm_test! {test_origin: test_origin_int}
fn test_origin(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let origin =
        Address::from_str("cd1722f2947def4cf144679da39c4c32bdc35681").unwrap();
    let code = "32600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address;
    params.original_sender = origin;
    params.storage_owner = address;
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut context = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, context.spec(), context.depth());
        test_finalize(vm.exec(&mut context).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &context,
        0,
        "000000000000000000000000cd1722f2947def4cf144679da39c4c32bdc35681",
    );
}

evm_test! {test_selfbalance: test_selfbalance_int}
fn test_selfbalance(factory: super::Factory) {
    let own_addr =
        Address::from_str("1337000000000000000000000000000000000000").unwrap();
    // 47       SELFBALANCE
    // 60 ff    PUSH ff
    // 55       SSTORE
    let code = "47 60 ff 55".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = own_addr.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    ctx.balances = {
        let mut x = HashMap::new();
        x.insert(own_addr, U256::from(1_025)); // 0x401
        x
    };
    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };
    assert_eq!(gas_left, U256::from(94_992));
    assert_store(
        &ctx,
        0xff,
        "0000000000000000000000000000000000000000000000000000000000000401",
    );
}

evm_test! {test_sender: test_sender_int}
fn test_sender(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let sender =
        Address::from_str("cd1722f2947def4cf144679da39c4c32bdc35681").unwrap();
    let code = "33600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.sender = sender.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "000000000000000000000000cd1722f2947def4cf144679da39c4c32bdc35681",
    );
}

evm_test! {test_chain_id: test_chain_id_int}
fn test_chain_id(factory: super::Factory) {
    // 46       CHAINID
    // 60 00    PUSH 0
    // 55       SSTORE
    let code = "46 60 00 55".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new().with_chain_id(9);

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000009",
    );
}

evm_test! {test_extcodecopy: test_extcodecopy_int}
fn test_extcodecopy(factory: super::Factory) {
    // 33 - sender
    // 3b - extcodesize
    // 60 00 - push 0
    // 60 00 - push 0
    // 33 - sender
    // 3c - extcodecopy
    // 60 00 - push 0
    // 51 - load word from memory
    // 60 00 - push 0
    // 55 - sstore

    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let sender =
        Address::from_str("cd1722f2947def4cf144679da39c4c32bdc35681").unwrap();
    let code = "333b60006000333c600051600055".from_hex().unwrap();
    let sender_code = "6005600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.sender = sender.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();
    ctx.codes.insert(sender, Arc::new(sender_code));

    //let gas_left = {
    {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    //assert_eq!(gas_left, U256::from(79_935));
    assert_store(
        &ctx,
        0,
        "6005600055000000000000000000000000000000000000000000000000000000",
    );
}

evm_test! {test_log_empty: test_log_empty_int}
fn test_log_empty(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let code = "60006000a0".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(99_619));
    assert_eq!(ctx.logs.len(), 1);
    assert_eq!(ctx.logs[0].topics.len(), 0);
    assert!(ctx.logs[0].data.is_empty());
}

evm_test! {test_log_sender: test_log_sender_int}
fn test_log_sender(factory: super::Factory) {
    // 60 ff - push ff
    // 60 00 - push 00
    // 53 - mstore
    // 33 - sender
    // 60 20 - push 20
    // 60 00 - push 0
    // a1 - log with 1 topic

    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let sender =
        Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
    let code = "60ff6000533360206000a1".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.sender = sender.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(98_974));
    assert_eq!(ctx.logs.len(), 1);
    assert_eq!(ctx.logs[0].topics.len(), 1);
    assert_eq!(
        ctx.logs[0].topics[0],
        H256::from_str(
            "000000000000000000000000cd1722f3947def4cf144679da39c4c32bdc35681"
        )
        .unwrap()
    );
    assert_eq!(
        ctx.logs[0].data,
        "ff00000000000000000000000000000000000000000000000000000000000000"
            .from_hex()
            .unwrap()
    );
}

evm_test! {test_blockhash: test_blockhash_int}
fn test_blockhash(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let code = "600040600055".from_hex().unwrap();
    let blockhash = H256::from_str(
        "123400000000000000000000cd1722f2947def4cf144679da39c4c32bdc35681",
    )
    .unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();
    ctx.blockhashes.insert(U256::zero(), blockhash.clone());

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_974));
    assert_eq!(ctx.store.get(&H256::zero()).unwrap(), &blockhash);
}

evm_test! {test_calldataload: test_calldataload_int}
fn test_calldataload(factory: super::Factory) {
    let address =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let code = "600135600055".from_hex().unwrap();
    let data =
        "0123ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff23"
            .from_hex()
            .unwrap();

    let mut params = ActionParams::default();
    params.address = address.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.data = Some(data);
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_991));
    assert_store(
        &ctx,
        0,
        "23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff23",
    );
}

evm_test! {test_author: test_author_int}
fn test_author(factory: super::Factory) {
    let author =
        Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
    let code = "41600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();
    ctx.env.author = author;

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000f572e5295c57f15886f9b263e2f6d2d6c7b5ec6",
    );
}

evm_test! {test_timestamp: test_timestamp_int}
fn test_timestamp(factory: super::Factory) {
    let timestamp = 0x1234;
    let code = "42600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();
    ctx.env.timestamp = timestamp;

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000001234",
    );
}

evm_test! {test_number: test_number_int}
fn test_number(factory: super::Factory) {
    let number = 0x1234;
    let code = "43600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();
    ctx.env.number = number;

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000001234",
    );
}

evm_test! {test_difficulty: test_difficulty_int}
fn test_difficulty(factory: super::Factory) {
    let difficulty = U256::from(0x1234);
    let code = "44600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();
    ctx.env.difficulty = difficulty;

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000001234",
    );
}

evm_test! {test_gas_limit: test_gas_limit_int}
fn test_gas_limit(factory: super::Factory) {
    let gas_limit = U256::from(0x1234);
    let code = "45600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();
    ctx.env.gas_limit = gas_limit;

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(94_995));
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000001234",
    );
}

evm_test! {test_mul: test_mul_int}
fn test_mul(factory: super::Factory) {
    let code = "65012365124623626543219002600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "000000000000000000000000000000000000000000000000734349397b853383",
    );
    assert_eq!(gas_left, U256::from(94_983));
}

evm_test! {test_sub: test_sub_int}
fn test_sub(factory: super::Factory) {
    let code = "65012365124623626543219003600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000012364ad0302",
    );
    assert_eq!(gas_left, U256::from(94_985));
}

evm_test! {test_div: test_div_int}
fn test_div(factory: super::Factory) {
    let code = "65012365124623626543219004600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "000000000000000000000000000000000000000000000000000000000002e0ac",
    );
    assert_eq!(gas_left, U256::from(94_983));
}

evm_test! {test_div_zero: test_div_zero_int}
fn test_div_zero(factory: super::Factory) {
    let code = "6501236512462360009004600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(gas_left, U256::from(94_983));
}

evm_test! {test_mod: test_mod_int}
fn test_mod(factory: super::Factory) {
    let code = "650123651246236265432290066000556501236512462360009006600155"
        .from_hex()
        .unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000076b4b",
    );
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(gas_left, U256::from(89_966));
}

evm_test! {test_smod: test_smod_int}
fn test_smod(factory: super::Factory) {
    let code = "650123651246236265432290076000556501236512462360009007600155"
        .from_hex()
        .unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000076b4b",
    );
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(gas_left, U256::from(89_966));
}

evm_test! {test_sdiv: test_sdiv_int}
fn test_sdiv(factory: super::Factory) {
    let code = "650123651246236265432290056000556501236512462360009005600155"
        .from_hex()
        .unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "000000000000000000000000000000000000000000000000000000000002e0ac",
    );
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(gas_left, U256::from(89_966));
}

evm_test! {test_exp: test_exp_int}
fn test_exp(factory: super::Factory) {
    let code = "6016650123651246230a6000556001650123651246230a6001556000650123651246230a600255".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    //let gas_left = {
    {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "90fd23767b60204c3d6fc8aec9e70a42a3f127140879c133a20129a597ed0c59",
    );
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000012365124623",
    );
    assert_store(
        &ctx,
        2,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    //assert_eq!(gas_left, U256::from(39_923));
}

evm_test! {test_comparison: test_comparison_int}
fn test_comparison(factory: super::Factory) {
    let code = "601665012365124623818181811060005511600155146002556415235412358014600355".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    assert_store(
        &ctx,
        2,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_store(
        &ctx,
        3,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    assert_eq!(gas_left, U256::from(79_952));
}

evm_test! {test_signed_comparison: test_signed_comparison_int}
fn test_signed_comparison(factory: super::Factory) {
    let code =
        "60106000036010818112600055136001556010601060000381811260025513600355"
            .from_hex()
            .unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    assert_store(
        &ctx,
        2,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    assert_store(
        &ctx,
        3,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(gas_left, U256::from(79_940));
}

evm_test! {test_bitops: test_bitops_int}
fn test_bitops(factory: super::Factory) {
    let code = "60ff610ff08181818116600055176001551860025560008015600355198015600455600555".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(150_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "00000000000000000000000000000000000000000000000000000000000000f0",
    );
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000000000000fff",
    );
    assert_store(
        &ctx,
        2,
        "0000000000000000000000000000000000000000000000000000000000000f0f",
    );
    assert_store(
        &ctx,
        3,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    assert_store(
        &ctx,
        4,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_store(
        &ctx,
        5,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    assert_eq!(gas_left, U256::from(119_937));
}

evm_test! {test_addmod_mulmod: test_addmod_mulmod_int}
fn test_addmod_mulmod(factory: super::Factory) {
    let code = "60ff60f060108282820860005509600155600060f0601082828208196002550919600355".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    assert_store(
        &ctx,
        1,
        "000000000000000000000000000000000000000000000000000000000000000f",
    );
    assert_store(
        &ctx,
        2,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    assert_store(
        &ctx,
        3,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    assert_eq!(gas_left, U256::from(79_914));
}

evm_test! {test_byte: test_byte_int}
fn test_byte(factory: super::Factory) {
    let code = "60f061ffff1a600055610fff601f1a600155".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_store(
        &ctx,
        1,
        "00000000000000000000000000000000000000000000000000000000000000ff",
    );
    assert_eq!(gas_left, U256::from(89_976));
}

evm_test! {test_signextend: test_signextend_int}
fn test_signextend(factory: super::Factory) {
    let code = "610fff60020b60005560ff60200b600155".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000fff",
    );
    assert_store(
        &ctx,
        1,
        "00000000000000000000000000000000000000000000000000000000000000ff",
    );
    assert_eq!(gas_left, U256::from(89_972));
}

#[test] // JIT just returns out of gas
fn test_badinstruction_int() {
    let factory = Factory::new(VMType::Interpreter, 1024 * 32);
    let code = "af".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let err = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap_err()
    };

    match err {
        vm::Error::BadInstruction { instruction: 0xaf } => (),
        _ => assert!(false, "Expected bad instruction"),
    }
}

evm_test! {test_pop: test_pop_int}
fn test_pop(factory: super::Factory) {
    let code = "60f060aa50600055".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "00000000000000000000000000000000000000000000000000000000000000f0",
    );
    assert_eq!(gas_left, U256::from(94_989));
}

evm_test! {test_extops: test_extops_int}
fn test_extops(factory: super::Factory) {
    let code =
        "5a6001555836553a600255386003553460045560016001526016590454600555"
            .from_hex()
            .unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(150_000);
    params.gas_price = U256::from(0x32);
    params.value = ActionValue::Transfer(U256::from(0x99));
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    //let gas_left = {
    {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000004",
    ); // PC / CALLDATASIZE
    assert_store(
        &ctx,
        1,
        "00000000000000000000000000000000000000000000000000000000000249ee",
    ); // GAS
    assert_store(
        &ctx,
        2,
        "0000000000000000000000000000000000000000000000000000000000000032",
    ); // GASPRICE
    assert_store(
        &ctx,
        3,
        "0000000000000000000000000000000000000000000000000000000000000020",
    ); // CODESIZE
    assert_store(
        &ctx,
        4,
        "0000000000000000000000000000000000000000000000000000000000000099",
    ); // CALLVALUE
    assert_store(
        &ctx,
        5,
        "0000000000000000000000000000000000000000000000000000000000000032",
    );
    //assert_eq!(gas_left, U256::from(29_898));
}

evm_test! {test_jumps: test_jumps_int}
fn test_jumps(factory: super::Factory) {
    let code = "600160015560066000555b60016000540380806000551560245760015402600155600a565b".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(150_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    //let gas_left = {
    {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    // assert_eq!(ctx.sstore_clears, ctx.spec().sstore_refund_gas as i128);
    assert_store(
        &ctx,
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ); // 5!
    assert_store(
        &ctx,
        1,
        "0000000000000000000000000000000000000000000000000000000000000078",
    ); // 5!
       //assert_eq!(gas_left, U256::from(54_117));
}

evm_test! {test_subs_simple: test_subs_simple_int}
fn test_subs_simple(factory: super::Factory) {
    // as defined in https://eips.ethereum.org/EIPS/eip-2315
    let code = "6004b300b2b7".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(13);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(0));
}

evm_test! {test_subs_two_levels: test_subs_two_levels_int}
fn test_subs_two_levels(factory: super::Factory) {
    // as defined in https://eips.ethereum.org/EIPS/eip-2315
    let code = "6800000000000000000cb300b26011b3b7b2b7".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(26);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(0));
}

evm_test! {test_subs_invalid_jump: test_subs_invalid_jump_int}
fn test_subs_invalid_jump(factory: super::Factory) {
    // as defined in https://eips.ethereum.org/EIPS/eip-2315
    let code = "6801000000000000000cb300b26011b3b7b2b7".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(24);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let current = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap())
    };

    let expected =
        Result::Err(vm::Error::BadJumpDestination { destination: 0xc });
    assert_eq!(current, expected);
}

evm_test! {test_subs_shallow_return_stack: test_subs_shallow_return_stack_int}
fn test_subs_shallow_return_stack(factory: super::Factory) {
    // as defined in https://eips.ethereum.org/EIPS/eip-2315
    let code = "b75858".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(24);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let current = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap())
    };

    let expected = Result::Err(vm::Error::SubStackUnderflow {
        wanted: 1,
        on_stack: 0,
    });
    assert_eq!(current, expected);
}

evm_test! {test_subs_substack_limit: test_subs_substack_limit_int}
fn test_subs_substack_limit(factory: super::Factory) {
    //    PUSH2 <recursion_limit>
    //    PUSH1
    //    JUMP :b
    // :s BEGINSUB
    // :b JUMPDEST
    //    DUP1
    //    JUMPI :c
    //    STOP
    // :c JUMPDEST
    //    PUSH1 1
    //    SWAP
    //    SUB
    //    JUMPSUB :s

    let mut code = "610400600756b25b80600d57005b600190036006b3"
        .from_hex()
        .unwrap();
    code[1..3].copy_from_slice(&(MAX_SUB_STACK_SIZE as u16).to_be_bytes()[..]);

    let mut params = ActionParams::default();
    params.gas = U256::from(1_000_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(961_057));
}

evm_test! {test_subs_substack_out: test_subs_substack_out_int}
fn test_subs_substack_out(factory: super::Factory) {
    let mut code = "610400600756b25b80600d57005b600190036006b3"
        .from_hex()
        .unwrap();
    code[1..3]
        .copy_from_slice(&((MAX_SUB_STACK_SIZE + 1) as u16).to_be_bytes()[..]);

    let mut params = ActionParams::default();
    params.gas = U256::from(1_000_000);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let current = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap())
    };

    let expected = Result::Err(vm::Error::OutOfSubStack {
        wanted: 1,
        limit: MAX_SUB_STACK_SIZE,
    });
    assert_eq!(current, expected);
}

evm_test! {test_subs_sub_at_end: test_subs_sub_at_end_int}
fn test_subs_sub_at_end(factory: super::Factory) {
    let code = "600556b2b75b6003b3".from_hex().unwrap();

    let mut params = ActionParams::default();
    params.gas = U256::from(25);
    params.code = Some(Arc::new(code));
    let mut ctx = MockContext::new();

    let gas_left = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_eq!(gas_left, U256::from(0));
}

evm_test! {test_calls: test_calls_int}
fn test_calls(factory: super::Factory) {
    let code = "600054602d57600160005560006000600060006050610998610100f160006000600060006050610998610100f25b".from_hex().unwrap();

    let address = Address::from_low_u64_be(0x155);
    let code_address = Address::from_low_u64_be(0x998);
    let mut params = ActionParams::default();
    params.gas = U256::from(150_000);
    params.code = Some(Arc::new(code));
    params.address = address.clone();
    let mut ctx = MockContext::new();
    ctx.balances = {
        let mut s = HashMap::new();
        s.insert(params.address.clone(), params.gas);
        s
    };

    //let gas_left = {
    {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap()
    };

    assert_set_contains(
        &ctx.calls,
        &MockCall {
            call_type: MockCallType::Call,
            create_scheme: None,
            gas: U256::from(2556),
            sender_address: Some(address.clone()),
            receive_address: Some(code_address.clone()),
            value: Some(U256::from(0x50)),
            data: vec![],
            code_address: Some(code_address.clone()),
        },
    );
    assert_set_contains(
        &ctx.calls,
        &MockCall {
            call_type: MockCallType::Call,
            create_scheme: None,
            gas: U256::from(2556),
            sender_address: Some(address.clone()),
            receive_address: Some(address.clone()),
            value: Some(U256::from(0x50)),
            data: vec![],
            code_address: Some(code_address.clone()),
        },
    );
    //assert_eq!(gas_left, U256::from(91_405));
    assert_eq!(ctx.calls.len(), 2);
}

evm_test! {test_create_in_staticcall: test_create_in_staticcall_int}
fn test_create_in_staticcall(factory: super::Factory) {
    let code = "600060006064f000".from_hex().unwrap();

    let address = Address::from_low_u64_be(0x155);
    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code));
    params.address = address.clone();
    let mut ctx = MockContext::new_spec();
    ctx.is_static = true;

    let err = {
        let vm = factory.create(params, ctx.spec(), ctx.depth());
        test_finalize(vm.exec(&mut ctx).ok().unwrap()).unwrap_err()
    };

    assert_eq!(err, vm::Error::MutableCallInStaticContext);
    assert_eq!(ctx.calls.len(), 0);
}

fn assert_set_contains<T: Debug + Eq + PartialEq + Hash>(
    set: &HashSet<T>, val: &T,
) {
    let contains = set.contains(val);
    if !contains {
        println!("Set: {:?}", set);
        println!("Elem: {:?}", val);
    }
    assert!(contains, "Element not found in HashSet");
}

fn assert_store(ctx: &MockContext, pos: u64, val: &str) {
    assert_eq!(
        ctx.store.get(&H256::from_low_u64_be(pos)).unwrap(),
        &H256::from_str(val).unwrap()
    );
}
