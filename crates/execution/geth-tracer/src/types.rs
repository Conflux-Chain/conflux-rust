// Copyright 2023-2024 Paradigm.xyz
// This file is part of reth.
// Reth is a modular, contributor-friendly and blazing-fast implementation of
// the Ethereum protocol

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Types for representing call trace items.
use crate::{config::TraceStyle, utils, utils::convert_memory};
use alloy_primitives::{Address, Bytes, LogData, U256};
use alloy_rpc_types_trace::geth::{
    CallFrame, CallLogFrame, GethDefaultTracingOptions, GethTrace, StructLog,
};
use cfx_types::{Space, H256};
use cfx_vm_types::CallType as CfxCallType;
use primitives::{block::BlockHeight, BlockNumber};
use revm::interpreter::{
    opcode, CallContext, CallScheme, CreateScheme, InstructionResult, OpCode,
};
use std::collections::VecDeque;

/// A trace of a call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CallTrace {
    /// The depth of the call
    pub depth: usize,
    /// Whether the call was successful
    pub success: bool,
    /// caller of this call
    pub caller: Address,
    /// The destination address of the call or the address from the created
    /// contract.
    ///
    /// In other words, this is the callee if the [CallKind::Call] or the
    /// address of the created contract if [CallKind::Create].
    pub address: Address,
    /// Whether this is a call to a precompile
    ///
    /// Note: This is an Option because not all tracers make use of this
    pub maybe_precompile: Option<bool>,
    /// Holds the target for the __selfdestruct__ refund target
    ///
    /// This is only set if a selfdestruct was executed.
    ///
    /// Note: This not necessarily guarantees that the status is
    /// [InstructionResult::SelfDestruct] There's an edge case where a new
    /// created contract is immediately selfdestructed.
    pub selfdestruct_refund_target: Option<Address>,
    /// The kind of call this is
    pub kind: CallKind,
    /// The value transferred in the call
    pub value: U256,
    /// The calldata for the call, or the init code for contract creations
    pub data: Bytes,
    /// The return data of the call if this was not a contract creation,
    /// otherwise it is the runtime bytecode of the created contract
    pub output: Bytes,
    /// The gas cost of the call
    pub gas_used: u64,
    /// The gas limit of the call
    pub gas_limit: u64,
    /// The status of the trace's call
    pub status: InstructionResult,
    /// call context of the runtime
    pub call_context: Option<Box<CallContext>>,
    /// Opcode-level execution steps
    pub steps: Vec<CallTraceStep>,
}

impl CallTrace {
    /// Returns true if the status code is an error or revert, See
    /// [InstructionResult::Revert]
    #[inline]
    pub const fn is_error(&self) -> bool { !self.status.is_ok() }

    /// Returns true if the status code is a revert
    #[inline]
    pub fn is_revert(&self) -> bool { self.status == InstructionResult::Revert }

    /// Returns the error message if it is an erroneous result.
    pub(crate) fn as_error_msg(&self, kind: TraceStyle) -> Option<String> {
        // See also <https://github.com/ethereum/go-ethereum/blob/34d507215951fb3f4a5983b65e127577989a6db8/eth/tracers/native/call_flat.go#L39-L55>
        self.is_error().then(|| match self.status {
            InstructionResult::Revert => if kind.is_parity() {
                "Reverted"
            } else {
                "execution reverted"
            }
            .to_string(),
            InstructionResult::OutOfGas | InstructionResult::MemoryOOG => {
                if kind.is_parity() {
                    "Out of gas"
                } else {
                    "out of gas"
                }
                .to_string()
            }
            InstructionResult::OpcodeNotFound => if kind.is_parity() {
                "Bad instruction"
            } else {
                "invalid opcode"
            }
            .to_string(),
            InstructionResult::StackOverflow => "Out of stack".to_string(),
            InstructionResult::InvalidJump => if kind.is_parity() {
                "Bad jump destination"
            } else {
                "invalid jump destination"
            }
            .to_string(),
            InstructionResult::PrecompileError => if kind.is_parity() {
                "Built-in failed"
            } else {
                "precompiled failed"
            }
            .to_string(),
            status => format!("{:?}", status),
        })
    }
}

/// A node in the arena
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CallTraceNode {
    /// Parent node index in the arena
    pub parent: Option<usize>,
    /// Children node indexes in the arena
    pub children: Vec<usize>,
    /// This node's index in the arena
    pub idx: usize,
    /// The call trace
    pub trace: CallTrace,
    /// Recorded logs, if enabled
    pub logs: Vec<LogData>,
    /// Ordering of child calls and logs
    pub ordering: Vec<LogCallOrder>,
}

impl CallTraceNode {
    /// Returns the call context's execution address
    ///
    /// See `Inspector::call` impl of
    /// [TracingInspector](crate::tracing::TracingInspector)
    pub const fn execution_address(&self) -> Address {
        if self.trace.kind.is_delegate() {
            self.trace.caller
        } else {
            self.trace.address
        }
    }

    /// Pushes all steps onto the stack in reverse order
    /// so that the first step is on top of the stack
    pub(crate) fn push_steps_on_stack<'a>(
        &'a self, stack: &mut VecDeque<CallTraceStepStackItem<'a>>,
    ) {
        stack.extend(self.call_step_stack().into_iter().rev());
    }

    /// Returns a list of all steps in this trace in the order they were
    /// executed
    ///
    /// If the step is a call, the id of the child trace is set.
    pub(crate) fn call_step_stack(&self) -> Vec<CallTraceStepStackItem<'_>> {
        let mut stack = Vec::with_capacity(self.trace.steps.len());
        let mut child_id = 0;
        for step in self.trace.steps.iter() {
            let mut item = CallTraceStepStackItem {
                trace_node: self,
                step,
                call_child_id: None,
            };

            // If the opcode is a call, put the child trace on the stack
            if step.is_calllike_op() {
                // The opcode of this step is a call but it's possible that this
                // step resulted in a revert or out of gas error in which case there's no actual child call executed and recorded: <https://github.com/paradigmxyz/reth/issues/3915>
                if let Some(call_id) = self.children.get(child_id).copied() {
                    item.call_child_id = Some(call_id);
                    child_id += 1;
                }
            }
            stack.push(item);
        }
        stack
    }

    /// Returns true if this is a call to a precompile
    #[inline]
    pub fn is_precompile(&self) -> bool {
        self.trace.maybe_precompile.unwrap_or(false)
    }

    /// Returns the kind of call the trace belongs to
    #[inline]
    pub const fn kind(&self) -> CallKind { self.trace.kind }

    /// Returns the status of the call
    #[inline]
    pub const fn status(&self) -> InstructionResult { self.trace.status }

    /// Returns true if the call was a selfdestruct
    ///
    /// A selfdestruct is marked by the refund target being set.
    ///
    /// See also `TracingInspector::selfdestruct`
    ///
    /// Note: We can't rely in the [Self::status] being
    /// [InstructionResult::SelfDestruct] because there's an edge case where
    /// a new created contract (CREATE) is immediately selfdestructed.
    #[inline]
    pub const fn is_selfdestruct(&self) -> bool {
        self.trace.selfdestruct_refund_target.is_some()
    }

    /// If the trace is a selfdestruct, returns the `CallFrame` for a geth call
    /// trace
    pub fn geth_selfdestruct_call_trace(&self) -> Option<CallFrame> {
        if self.is_selfdestruct() {
            Some(CallFrame {
                typ: "SELFDESTRUCT".to_string(),
                from: self.trace.caller,
                to: self.trace.selfdestruct_refund_target,
                value: Some(self.trace.value),
                ..Default::default()
            })
        } else {
            None
        }
    }

    /// Converts this call trace into an _empty_ geth [CallFrame]
    pub fn geth_empty_call_frame(&self, include_logs: bool) -> CallFrame {
        let mut call_frame = CallFrame {
            typ: self.trace.kind.to_string(),
            from: self.trace.caller,
            to: Some(self.trace.address),
            value: Some(self.trace.value),
            gas: U256::from(self.trace.gas_limit),
            gas_used: U256::from(self.trace.gas_used),
            input: self.trace.data.clone(),
            output: (!self.trace.output.is_empty())
                .then(|| self.trace.output.clone()),
            error: None,
            revert_reason: None,
            calls: Default::default(),
            logs: Default::default(),
        };

        if self.trace.kind.is_static_call() {
            // STATICCALL frames don't have a value
            call_frame.value = None;
        }

        // we need to populate error and revert reason
        if !self.trace.success {
            call_frame.revert_reason =
                utils::maybe_revert_reason(self.trace.output.as_ref());

            // Note: the call tracer mimics parity's trace transaction and geth maps errors to parity style error messages, <https://github.com/ethereum/go-ethereum/blob/34d507215951fb3f4a5983b65e127577989a6db8/eth/tracers/native/call_flat.go#L39-L55>
            call_frame.error = self.trace.as_error_msg(TraceStyle::Parity);
        }

        if include_logs && !self.logs.is_empty() {
            call_frame.logs = self
                .logs
                .iter()
                .map(|log| CallLogFrame {
                    address: Some(self.execution_address()),
                    topics: Some(log.topics().to_vec()),
                    data: Some(log.data.clone()),
                })
                .collect();
        }

        call_frame
    }
}

/// A unified representation of a call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "UPPERCASE"))]
pub enum CallKind {
    /// Represents a regular call.
    #[default]
    Call,
    /// Represents a static call.
    StaticCall,
    /// Represents a call code operation.
    CallCode,
    /// Represents a delegate call.
    DelegateCall,
    /// Represents a contract creation operation.
    Create,
    /// Represents a contract creation operation using the CREATE2 opcode.
    Create2,
}

impl CallKind {
    /// Returns true if the call is a create
    #[inline]
    pub const fn is_any_create(&self) -> bool {
        matches!(self, Self::Create | Self::Create2)
    }

    /// Returns true if the call is a delegate of some sorts
    #[inline]
    pub const fn is_delegate(&self) -> bool {
        matches!(self, Self::DelegateCall | Self::CallCode)
    }

    /// Returns true if the call is [CallKind::StaticCall].
    #[inline]
    pub const fn is_static_call(&self) -> bool {
        matches!(self, Self::StaticCall)
    }
}

impl std::fmt::Display for CallKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call => {
                write!(f, "CALL")
            }
            Self::StaticCall => {
                write!(f, "STATICCALL")
            }
            Self::CallCode => {
                write!(f, "CALLCODE")
            }
            Self::DelegateCall => {
                write!(f, "DELEGATECALL")
            }
            Self::Create => {
                write!(f, "CREATE")
            }
            Self::Create2 => {
                write!(f, "CREATE2")
            }
        }
    }
}

impl From<CallScheme> for CallKind {
    fn from(scheme: CallScheme) -> Self {
        match scheme {
            CallScheme::Call => Self::Call,
            CallScheme::StaticCall => Self::StaticCall,
            CallScheme::CallCode => Self::CallCode,
            CallScheme::DelegateCall => Self::DelegateCall,
        }
    }
}

impl From<CreateScheme> for CallKind {
    fn from(create: CreateScheme) -> Self {
        match create {
            CreateScheme::Create => Self::Create,
            CreateScheme::Create2 { .. } => Self::Create2,
        }
    }
}

impl From<CfxCallType> for CallKind {
    fn from(ct: CfxCallType) -> Self {
        match ct {
            CfxCallType::None => Self::Create,
            CfxCallType::Call => Self::Call,
            CfxCallType::CallCode => Self::CallCode,
            CfxCallType::DelegateCall => Self::DelegateCall,
            CfxCallType::StaticCall => Self::StaticCall,
        }
    }
}

pub(crate) struct CallTraceStepStackItem<'a> {
    /// The trace node that contains this step
    pub(crate) trace_node: &'a CallTraceNode,
    /// The step that this stack item represents
    pub(crate) step: &'a CallTraceStep,
    /// The index of the child call in the CallArena if this step's opcode is a
    /// call
    pub(crate) call_child_id: Option<usize>,
}

/// Ordering enum for calls and logs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LogCallOrder {
    /// Contains the index of the corresponding log
    Log(usize),
    /// Contains the index of the corresponding trace node
    Call(usize),
}

/// Represents a tracked call step during execution
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CallTraceStep {
    // Fields filled in `step`
    /// Call depth
    pub depth: u64,
    /// Program counter before step execution
    pub pc: usize,
    /// Opcode to be executed
    #[cfg_attr(feature = "serde", serde(with = "opcode_serde"))]
    pub op: OpCode,
    /// Current contract address
    pub contract: Address,
    /// Stack before step execution
    pub stack: Option<Vec<U256>>,
    /// The new stack items placed by this step if any
    pub push_stack: Option<Vec<U256>>,
    /// All allocated memory in a step
    ///
    /// This will be empty if memory capture is disabled
    pub memory: RecordedMemory,
    /// Size of memory at the beginning of the step
    pub memory_size: usize,
    /// Remaining gas before step execution
    pub gas_remaining: u64,
    /// Gas refund counter before step execution
    pub gas_refund_counter: u64,
    // Fields filled in `step_end`
    /// Gas cost of step execution
    pub gas_cost: u64,
    /// Change of the contract state after step execution (effect of the
    /// SLOAD/SSTORE instructions)
    pub storage_change: Option<StorageChange>,
    /// Final status of the step
    ///
    /// This is set after the step was executed.
    pub status: InstructionResult,
}

// === impl CallTraceStep ===

impl CallTraceStep {
    /// Converts this step into a geth [StructLog]
    ///
    /// This sets memory and stack capture based on the `opts` parameter.
    pub(crate) fn convert_to_geth_struct_log(
        &self, opts: &GethDefaultTracingOptions,
    ) -> StructLog {
        let mut log = StructLog {
            depth: self.depth,
            error: self.as_error(),
            gas: self.gas_remaining,
            gas_cost: self.gas_cost,
            op: self.op.to_string(),
            pc: self.pc as u64,
            refund_counter: (self.gas_refund_counter > 0)
                .then_some(self.gas_refund_counter),
            // Filled, if not disabled manually
            stack: None,
            // Filled in `CallTraceArena::geth_trace` as a result of compounding
            // all slot changes
            return_data: None,
            // Filled via trace object
            storage: None,
            // Only enabled if `opts.enable_memory` is true
            memory: None,
            // This is None in the rpc response
            memory_size: None,
        };

        if opts.is_stack_enabled() {
            log.stack.clone_from(&self.stack);
        }

        if opts.is_memory_enabled() {
            log.memory = Some(self.memory.memory_chunks());
        }

        log
    }

    /// Returns true if the step is a STOP opcode
    #[inline]
    pub(crate) const fn is_stop(&self) -> bool {
        matches!(self.op.get(), opcode::STOP)
    }

    /// Returns true if the step is a call operation, any of
    /// CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2
    #[inline]
    pub(crate) const fn is_calllike_op(&self) -> bool {
        matches!(
            self.op.get(),
            opcode::CALL
                | opcode::DELEGATECALL
                | opcode::STATICCALL
                | opcode::CREATE
                | opcode::CALLCODE
                | opcode::CREATE2
        )
    }

    // Returns true if the status code is an error or revert, See
    // [InstructionResult::Revert]
    #[inline]
    pub(crate) const fn is_error(&self) -> bool {
        self.status as u8 >= InstructionResult::Revert as u8
    }

    /// Returns the error message if it is an erroneous result.
    #[inline]
    pub(crate) fn as_error(&self) -> Option<String> {
        self.is_error().then(|| format!("{:?}", self.status))
    }
}

/// Represents the source of a storage change - e.g., whether it came
/// from an SSTORE or SLOAD instruction.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StorageChangeReason {
    /// SLOAD opcode
    SLOAD,
    /// SSTORE opcode
    SSTORE,
}

/// Represents a storage change during execution.
///
/// This maps to evm internals:
/// [JournalEntry::StorageChange](revm::JournalEntry::StorageChange)
///
/// It is used to track both storage change and warm load of a storage slot. For
/// warm load in regard to EIP-2929 AccessList had_value will be None.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StorageChange {
    /// key of the storage slot
    pub key: U256,
    /// Current value of the storage slot
    pub value: U256,
    /// The previous value of the storage slot, if any
    pub had_value: Option<U256>,
    /// How this storage was accessed
    pub reason: StorageChangeReason,
}

/// Represents the memory captured during execution
///
/// This is a wrapper around the [SharedMemory](revm::interpreter::SharedMemory)
/// context memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecordedMemory(pub(crate) Vec<u8>);

impl RecordedMemory {
    #[inline]
    pub(crate) fn new(mem: Vec<u8>) -> Self { Self(mem) }

    /// Returns the memory as a byte slice
    #[inline]
    pub fn as_bytes(&self) -> &[u8] { &self.0 }

    #[inline]
    pub(crate) fn resize(&mut self, size: usize) { self.0.resize(size, 0); }

    /// Returns the size of the memory
    #[inline]
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns whether the memory is empty
    #[inline]
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Converts the memory into 32byte hex chunks
    #[inline]
    pub fn memory_chunks(&self) -> Vec<String> {
        convert_memory(self.as_bytes())
    }
}

impl AsRef<[u8]> for RecordedMemory {
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

pub struct GethTraceWithHash {
    pub trace: GethTrace,
    pub tx_hash: H256,
    pub space: Space,
}

#[derive(Clone)]
pub struct TxExecContext {
    pub tx_gas_limit: u64,
    pub block_number: BlockNumber,
    pub block_height: BlockHeight,
}

#[cfg(feature = "serde")]
mod opcode_serde {
    use super::OpCode;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(
        op: &OpCode, serializer: S,
    ) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_u8(op.get())
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<OpCode, D::Error>
    where D: Deserializer<'de> {
        let op = u8::deserialize(deserializer)?;
        Ok(OpCode::new(op).unwrap_or_else(|| {
            OpCode::new(revm::interpreter::opcode::INVALID).unwrap()
        }))
    }
}
