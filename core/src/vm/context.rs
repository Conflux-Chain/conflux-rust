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

//! Interface for Evm externalities.

use super::{
    call_type::CallType,
    env::Env,
    error::{Result, TrapKind},
    return_data::ReturnData,
    spec::Spec,
    Error,
};
use crate::trace::{trace::ExecTrace, Tracer};
use cfx_bytes::Bytes;
use cfx_types::{Address, H256, U256};
use std::sync::Arc;

#[derive(Debug)]
/// Result of externalities create function.
pub enum ContractCreateResult {
    /// Returned when creation was successful.
    /// Contains an address of newly created contract and gas left.
    Created(Address, U256),
    /// Returned when contract creation failed.
    /// Returns the reason so block trace can record it.
    Failed(Error),
    /// Reverted with REVERT.
    Reverted(U256, ReturnData),
}

#[derive(Debug)]
/// Result of externalities call function.
pub enum MessageCallResult {
    /// Returned when message call was successful.
    /// Contains gas left and output data.
    Success(U256, ReturnData),
    /// Returned when message call failed.
    /// Returns the reason so block trace can record it.
    Failed(Error),
    /// Returned when message call was reverted.
    /// Contains gas left and output data.
    Reverted(U256, ReturnData),
}

/// Specifies how an address is calculated for a new contract.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum CreateContractAddress {
    /// Address is calculated from sender, nonce, and code hash. Conflux
    /// `create` scheme.
    FromSenderNonceAndCodeHash,
    /// Address is calculated from block_hash, sender, nonce and code_hash.
    /// Potential new Conflux `create` scheme when kill_dust is enabled.
    FromBlockNumberSenderNonceAndCodeHash,
    /// Address is calculated from sender, salt and code hash. pWASM `create2`
    /// scheme.
    FromSenderSaltAndCodeHash(H256),
}

/// Context for VMs
pub trait Context {
    /// Returns a value for given key.
    fn storage_at(&self, key: &Vec<u8>) -> Result<U256>;

    /// Stores a value for given key.
    fn set_storage(&mut self, key: Vec<u8>, value: U256) -> Result<()>;

    /// Determine whether an account exists.
    fn exists(&self, address: &Address) -> Result<bool>;

    /// Determine whether an account exists and is not null (zero
    /// balance/nonce, no code).
    fn exists_and_not_null(&self, address: &Address) -> Result<bool>;

    /// Balance of the origin account.
    fn origin_balance(&self) -> Result<U256>;

    /// Returns address balance.
    fn balance(&self, address: &Address) -> Result<U256>;

    /// Returns the hash of one of the 256 most recent complete blocks.
    fn blockhash(&mut self, number: &U256) -> H256;

    /// Creates new contract.
    ///
    /// Returns gas_left and contract address if contract creation was
    /// succesfull.
    fn create(
        &mut self, gas: &U256, value: &U256, code: &[u8],
        address: CreateContractAddress, trap: bool,
    ) -> cfx_statedb::Result<
        ::std::result::Result<ContractCreateResult, TrapKind>,
    >;

    /// Message call.
    ///
    /// Returns Err, if we run out of gas.
    /// Otherwise returns call_result which contains gas left
    /// and true if subcall was successful.
    fn call(
        &mut self, gas: &U256, sender_address: &Address,
        receive_address: &Address, value: Option<U256>, data: &[u8],
        code_address: &Address, call_type: CallType, trap: bool,
    ) -> cfx_statedb::Result<::std::result::Result<MessageCallResult, TrapKind>>;

    /// Returns code at given address
    fn extcode(&self, address: &Address) -> Result<Option<Arc<Bytes>>>;

    /// Returns code hash at given address
    fn extcodehash(&self, address: &Address) -> Result<Option<H256>>;

    /// Returns code size at given address
    fn extcodesize(&self, address: &Address) -> Result<Option<usize>>;

    /// Creates log entry with given topics and data
    fn log(&mut self, topics: Vec<H256>, data: &[u8]) -> Result<()>;

    /// Should be called when transaction calls `RETURN` opcode.
    /// Returns gas_left if cost of returning the data is not too high.
    fn ret(
        self, gas: &U256, data: &ReturnData, apply_state: bool,
    ) -> Result<U256>;

    /// Should be called when contract commits suicide.
    /// Address to which funds should be refunded.
    fn suicide(
        &mut self, refund_address: &Address,
        tracer: &mut dyn Tracer<Output = ExecTrace>, account_start_nonce: U256,
    ) -> Result<()>;

    /// Returns specification.
    fn spec(&self) -> &Spec;

    /// Returns environment.
    fn env(&self) -> &Env;

    /// Returns the chain ID of the blockchain
    fn chain_id(&self) -> u64;

    /// Returns current depth of execution.
    ///
    /// If contract A calls contract B, and contract B calls C,
    /// then A depth is 0, B is 1, C is 2 and so on.
    fn depth(&self) -> usize;

    /// Increments sstore refunds counter.
    fn add_sstore_refund(&mut self, value: usize);

    /// Decrements sstore refunds counter.
    fn sub_sstore_refund(&mut self, value: usize);

    /// Decide if any more operations should be traced. Passthrough for the VM
    /// trace.
    fn trace_next_instruction(
        &mut self, _pc: usize, _instruction: u8, _current_gas: U256,
    ) -> bool {
        false
    }

    /// Prepare to trace an operation. Passthrough for the VM trace.
    fn trace_prepare_execute(
        &mut self, _pc: usize, _instruction: u8, _gas_cost: U256,
        _mem_written: Option<(usize, usize)>,
        _store_written: Option<(U256, U256)>,
    )
    {
    }

    /// Trace the finalised execution of a single instruction.
    fn trace_executed(
        &mut self, _gas_used: U256, _stack_push: &[U256], _mem: &[u8],
    ) {
    }

    /// Check if running in static context.
    fn is_static(&self) -> bool;

    /// Check if running in static context or reentrancy context
    fn is_static_or_reentrancy(&self) -> bool;

    /// Check if reentrancy happens in the next call
    /// The call stack doesn't have the current executive, so the caller address
    /// should be passed.
    fn is_reentrancy(&self, caller: &Address, callee: &Address) -> bool;
}
