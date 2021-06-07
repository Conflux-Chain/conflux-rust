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

//! VM errors module

use super::{action_params::ActionParams, ResumeCall, ResumeCreate};
use cfx_statedb::{Error as DbError, Result as DbResult};
use cfx_types::{Address, U256};
use solidity_abi::ABIDecodeError;
use std::fmt;

#[derive(Debug)]
pub enum TrapKind {
    Call(ActionParams),
    Create(ActionParams, Address),
}

pub enum TrapError<Call, Create> {
    Call(ActionParams, Call),
    Create(ActionParams, Create),
}

/// VM errors.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// `OutOfGas` is returned when transaction execution runs out of gas.
    /// The state should be reverted to the state from before the
    /// transaction execution. But it does not mean that transaction
    /// was invalid. Balance still should be transfered and nonce
    /// should be increased.
    OutOfGas,
    /// `BadJumpDestination` is returned when execution tried to move
    /// to position that wasn't marked with JUMPDEST instruction
    BadJumpDestination {
        /// Position the code tried to jump to.
        destination: usize,
    },
    /// `BadInstructions` is returned when given instruction is not supported
    BadInstruction {
        /// Unrecognized opcode
        instruction: u8,
    },
    /// `StackUnderflow` when there is not enough stack elements to execute
    /// instruction
    StackUnderflow {
        /// Invoked instruction
        instruction: &'static str,
        /// How many stack elements was requested by instruction
        wanted: usize,
        /// How many elements were on stack
        on_stack: usize,
    },
    /// When execution would exceed defined Stack Limit
    OutOfStack {
        /// Invoked instruction
        instruction: &'static str,
        /// How many stack elements instruction wanted to push
        wanted: usize,
        /// What was the stack limit
        limit: usize,
    },
    /// `SubStackUnderflow` when there is not enough stack elements to execute
    /// a subroutine return
    SubStackUnderflow {
        /// How many stack elements was requested by instruction
        wanted: usize,
        /// How many elements were on stack
        on_stack: usize,
    },
    /// When execution would exceed defined subroutine Stack Limit
    OutOfSubStack {
        /// How many stack elements instruction wanted to pop
        wanted: usize,
        /// What was the stack limit
        limit: usize,
    },
    InvalidSubEntry,
    /// When balance is not enough for `collateral_for_storage`.
    /// The state should be reverted to the state from before the
    /// transaction execution.
    NotEnoughBalanceForStorage {
        required: U256,
        got: U256,
    },
    /// `ExceedStorageLimit` is returned when the `collateral_for_storage`
    /// exceed the `storage_limit`.
    ExceedStorageLimit,
    /// Built-in contract failed on given input
    BuiltIn(&'static str),
    /// Internal contract failed
    InternalContract(&'static str),
    /// When execution tries to modify the state in static context
    MutableCallInStaticContext,
    /// Error from storage.
    StateDbError(PartialEqWrapper<DbError>),
    /// Wasm runtime error
    Wasm(String),
    /// Out of bounds access in RETURNDATACOPY.
    OutOfBounds,
    /// Execution has been reverted with REVERT.
    Reverted,
    /// Invalid address
    InvalidAddress(Address),
    /// Create a contract on an address with existing contract
    ConflictAddress(Address),
}

#[derive(Debug)]
pub struct PartialEqWrapper<T: std::fmt::Debug>(pub T);

impl<T: std::fmt::Debug> PartialEq for PartialEqWrapper<T> {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.0) == format!("{:?}", other.0)
    }
}

impl From<DbError> for Error {
    fn from(err: DbError) -> Self { Error::StateDbError(PartialEqWrapper(err)) }
}

impl From<ABIDecodeError> for Error {
    fn from(err: ABIDecodeError) -> Self { Error::InternalContract(err.0) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match *self {
            OutOfGas => write!(f, "Out of gas"),
            BadJumpDestination { destination } => {
                write!(f, "Bad jump destination {:x}", destination)
            }
            BadInstruction { instruction } => {
                write!(f, "Bad instruction {:x}", instruction)
            }
            StackUnderflow {
                instruction,
                wanted,
                on_stack,
            } => write!(
                f,
                "Stack underflow {} {}/{}",
                instruction, wanted, on_stack
            ),
            OutOfStack {
                instruction,
                wanted,
                limit,
            } => write!(f, "Out of stack {} {}/{}", instruction, wanted, limit),
            SubStackUnderflow { wanted, on_stack } => {
                write!(f, "Subroutine stack underflow {}/{}", wanted, on_stack)
            }
            InvalidSubEntry => {
                write!(f, "Invalid Subroutine Entry via BEGINSUB")
            }
            OutOfSubStack { wanted, limit } => {
                write!(f, "Out of subroutine stack {}/{}", wanted, limit)
            }
            NotEnoughBalanceForStorage { required, got } => {
                write!(f, "Not enough balance for storage {}/{}", required, got)
            }
            ExceedStorageLimit => write!(f, "Exceed storage limit"),
            BuiltIn(name) => write!(f, "Built-in failed: {}", name),
            InternalContract(name) => {
                write!(f, "InternalContract failed: {}", name)
            }
            StateDbError(ref msg) => {
                write!(f, "Irrecoverable state db error: {}", msg.0)
            }
            MutableCallInStaticContext => {
                write!(f, "Mutable call in static context")
            }
            Wasm(ref msg) => write!(f, "Internal error: {}", msg),
            OutOfBounds => write!(f, "Out of bounds"),
            Reverted => write!(f, "Reverted by bytecode"),
            InvalidAddress(ref addr) => write!(f, "InvalidAddress: {}", addr),
            ConflictAddress(ref addr) => {
                write!(f, "Contract creation on an existing address: {}", addr)
            }
        }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

pub fn separate_out_db_error<T>(result: Result<T>) -> DbResult<Result<T>> {
    match result {
        Err(Error::StateDbError(err)) => Err(err.0),
        x => Ok(x),
    }
}

pub enum TrapResult<T, Call, Create> {
    Return(Result<T>),
    SubCallCreate(TrapError<Call, Create>),
}

impl<T, Call, Create> TrapResult<T, Call, Create> {
    #[cfg(test)]
    pub fn ok(self) -> Option<Result<T>> {
        if let TrapResult::Return(result) = self {
            Some(result)
        } else {
            None
        }
    }
}

pub type ExecTrapResult<T> =
    TrapResult<T, Box<dyn ResumeCall>, Box<dyn ResumeCreate>>;

pub type ExecTrapError = TrapError<Box<dyn ResumeCall>, Box<dyn ResumeCreate>>;
