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

use super::{
    error::TrapKind, CallType, Context, ContractCreateResult,
    CreateContractAddress, Env, Error, GasLeft, MessageCallResult, Result,
    ReturnData, Spec,
};
use cfx_bytes::Bytes;
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use hash::keccak;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub struct MockLogEntry {
    pub topics: Vec<H256>,
    pub data: Bytes,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum MockCallType {
    Call,
    Create,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct MockCall {
    pub call_type: MockCallType,
    pub create_scheme: Option<CreateContractAddress>,
    pub gas: U256,
    pub sender_address: Option<Address>,
    pub receive_address: Option<Address>,
    pub value: Option<U256>,
    pub data: Bytes,
    pub code_address: Option<Address>,
}

/// Mock context test structure.
///
/// Can't do recursive calls.
#[derive(Default)]
pub struct MockContext {
    pub store: HashMap<Vec<u8>, U256>,
    pub suicides: HashSet<Address>,
    pub calls: HashSet<MockCall>,
    pub sstore_clears: i128,
    pub depth: usize,
    pub blockhashes: HashMap<U256, H256>,
    pub codes: HashMap<Address, Arc<Bytes>>,
    pub logs: Vec<MockLogEntry>,
    pub env: Env,
    pub spec: Spec,
    pub balances: HashMap<Address, U256>,
    pub tracing: bool,
    pub is_static: bool,

    chain_id: u64,
}

// similar to the normal `finalize` function, but ignoring NeedsReturn.
#[allow(dead_code)]
pub fn test_finalize(res: Result<GasLeft>) -> Result<U256> {
    match res {
        Ok(GasLeft::Known(gas)) => Ok(gas),
        Ok(GasLeft::NeedsReturn { .. }) => unimplemented!(), /* since ret is */
        // unimplemented.
        Err(e) => Err(e),
    }
}

impl MockContext {
    /// New mock context
    #[allow(dead_code)]
    pub fn new() -> Self { MockContext::default() }

    /// New mock context with byzantium spec rules
    #[allow(dead_code)]
    pub fn new_spec() -> Self {
        let mut context = MockContext::default();
        context.spec = Spec::new_spec();
        context
    }

    /// Alter mock context to allow wasm
    #[allow(dead_code)]
    pub fn with_wasm(mut self) -> Self {
        self.spec.wasm = Some(Default::default());
        self
    }

    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }
}

impl Context for MockContext {
    fn storage_at(&self, key: &Vec<u8>) -> Result<U256> {
        Ok(self.store.get(key).unwrap_or(&U256::zero()).clone())
    }

    fn set_storage(&mut self, key: Vec<u8>, value: U256) -> Result<()> {
        self.store.insert(key, value);
        Ok(())
    }

    fn exists(&self, address: &Address) -> Result<bool> {
        Ok(self.balances.contains_key(address))
    }

    fn exists_and_not_null(&self, address: &Address) -> Result<bool> {
        Ok(self.balances.get(address).map_or(false, |b| !b.is_zero()))
    }

    fn origin_balance(&self) -> Result<U256> { unimplemented!() }

    fn balance(&self, address: &Address) -> Result<U256> {
        Ok(self.balances[address])
    }

    fn blockhash(&mut self, number: &U256) -> H256 {
        self.blockhashes
            .get(number)
            .unwrap_or(&H256::zero())
            .clone()
    }

    fn create(
        &mut self, gas: &U256, value: &U256, code: &[u8],
        address: CreateContractAddress, _trap: bool,
    ) -> cfx_statedb::Result<
        ::std::result::Result<ContractCreateResult, TrapKind>,
    >
    {
        self.calls.insert(MockCall {
            call_type: MockCallType::Create,
            create_scheme: Some(address),
            gas: *gas,
            sender_address: None,
            receive_address: None,
            value: Some(*value),
            data: code.to_vec(),
            code_address: None,
        });
        // TODO: support traps in testing.
        Ok(Ok(ContractCreateResult::Failed))
    }

    fn call(
        &mut self, gas: &U256, sender_address: &Address,
        receive_address: &Address, value: Option<U256>, data: &[u8],
        code_address: &Address, _call_type: CallType, _trap: bool,
    ) -> cfx_statedb::Result<::std::result::Result<MessageCallResult, TrapKind>>
    {
        self.calls.insert(MockCall {
            call_type: MockCallType::Call,
            create_scheme: None,
            gas: *gas,
            sender_address: Some(sender_address.clone()),
            receive_address: Some(receive_address.clone()),
            value,
            data: data.to_vec(),
            code_address: Some(code_address.clone()),
        });
        // TODO: support traps in testing.
        Ok(Ok(MessageCallResult::Success(*gas, ReturnData::empty())))
    }

    fn extcode(&self, address: &Address) -> Result<Option<Arc<Bytes>>> {
        Ok(self.codes.get(address).cloned())
    }

    fn extcodesize(&self, address: &Address) -> Result<Option<usize>> {
        Ok(self.codes.get(address).map(|c| c.len()))
    }

    fn extcodehash(&self, address: &Address) -> Result<Option<H256>> {
        Ok(self.codes.get(address).map(|c| keccak(c.as_ref())))
    }

    fn log(&mut self, topics: Vec<H256>, data: &[u8]) -> Result<()> {
        self.logs.push(MockLogEntry {
            topics,
            data: data.to_vec(),
        });
        Ok(())
    }

    fn ret(
        self, _gas: &U256, _data: &ReturnData, _apply_state: bool,
    ) -> Result<U256> {
        unimplemented!();
    }

    fn suicide(&mut self, refund_address: &Address) -> Result<()> {
        if !refund_address.is_valid_address() {
            return Err(Error::InvalidAddress(*refund_address));
        }
        // The following code is from Parity, but it confuse me. Why refund
        // address is pushed to suicides list.
        self.suicides.insert(refund_address.clone());
        Ok(())
    }

    fn spec(&self) -> &Spec { &self.spec }

    fn env(&self) -> &Env { &self.env }

    fn chain_id(&self) -> u64 { self.chain_id }

    fn depth(&self) -> usize { self.depth }

    fn is_static(&self) -> bool { self.is_static }

    fn add_sstore_refund(&mut self, value: usize) {
        self.sstore_clears += value as i128;
    }

    fn sub_sstore_refund(&mut self, value: usize) {
        self.sstore_clears -= value as i128;
    }

    fn trace_next_instruction(
        &mut self, _pc: usize, _instruction: u8, _gas: U256,
    ) -> bool {
        self.tracing
    }

    fn is_reentrancy(&self, _: &Address, _: &Address) -> bool {
        // The MockContext doesn't have message call
        false
    }
}
