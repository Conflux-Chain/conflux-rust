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

use crate::TxExecContext;

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
use super::{
    arena::PushTraceKind,
    gas::GasInspector,
    types::{
        CallKind, CallTrace, CallTraceNode, CallTraceStep, RecordedMemory,
        StorageChange, StorageChangeReason,
    },
    utils::{gas_used, stack_push_count, to_alloy_address, to_alloy_u256},
    CallTraceArena, GethTraceBuilder, TracingInspectorConfig,
};
use cfx_types::{Space, H160};

use alloy_primitives::{Address, Bytes, U256};
use revm::interpreter::{opcode, InstructionResult, InterpreterResult, OpCode};

use cfx_executor::machine::Machine;

use cfx_vm_types::InterpreterInfo;

use std::sync::Arc;

#[derive(Clone)]
pub struct TracingInspector {
    /// Configures what and how the inspector records traces.
    pub config: TracingInspectorConfig,
    /// Records all call traces
    pub traces: CallTraceArena,
    /// Tracks active calls
    trace_stack: Vec<usize>,
    /// Tracks active steps
    step_stack: Vec<StackStep>,
    /// Tracks the return value of the last call
    pub last_call_return_data: Option<Bytes>,
    /// The gas inspector used to track remaining gas.
    pub gas_inspector: GasInspector,
    //
    machine: Arc<Machine>,

    tx_exec_context: TxExecContext,
}

impl TracingInspector {
    /// Returns a new instance for the given config
    pub fn new(
        config: TracingInspectorConfig, machine: Arc<Machine>,
        tx_exec_context: TxExecContext,
    ) -> Self {
        Self {
            config,
            traces: Default::default(),
            trace_stack: vec![],
            step_stack: vec![],
            last_call_return_data: None,
            gas_inspector: Default::default(),
            machine,
            tx_exec_context,
        }
    }

    /// Resets the inspector to its initial state of [Self::new].
    /// This makes the inspector ready to be used again.
    ///
    /// Note that this method has no effect on the allocated capacity of the
    /// vector.
    #[inline]
    pub fn fuse(&mut self) {
        let Self {
            traces,
            trace_stack,
            step_stack,
            last_call_return_data,
            gas_inspector,
            // kept
            config: _,
            machine: _,
            ..
        } = self;
        traces.clear();
        trace_stack.clear();
        step_stack.clear();
        last_call_return_data.take();
        *gas_inspector = Default::default();
    }

    /// Resets the inspector to it's initial state of [Self::new].
    #[inline]
    pub fn fused(mut self) -> Self {
        self.fuse();
        self
    }

    /// Returns the config of the inspector.
    pub const fn config(&self) -> &TracingInspectorConfig { &self.config }

    /// Gets a reference to the recorded call traces.
    pub const fn get_traces(&self) -> &CallTraceArena { &self.traces }

    /// Gets a mutable reference to the recorded call traces.
    pub fn get_traces_mut(&mut self) -> &mut CallTraceArena { &mut self.traces }

    /// Manually the gas used of the root trace.
    ///
    /// This is useful if the root trace's gasUsed should mirror the actual gas
    /// used by the transaction.
    ///
    /// This allows setting it manually by consuming the execution result's gas
    /// for example.
    #[inline]
    pub fn set_transaction_gas_used(&mut self, gas_used: u64) {
        if let Some(node) = self.traces.arena.first_mut() {
            node.trace.gas_used = gas_used;
        }
    }

    /// Convenience function for [ParityTraceBuilder::set_transaction_gas_used]
    /// that consumes the type.
    #[inline]
    pub fn with_transaction_gas_used(mut self, gas_used: u64) -> Self {
        self.set_transaction_gas_used(gas_used);
        self
    }

    /// Consumes the Inspector and returns a [ParityTraceBuilder].
    // #[inline]
    // pub fn into_parity_builder(self) -> ParityTraceBuilder {
    //     ParityTraceBuilder::new(self.traces.arena, self.spec_id, self.config)
    // }

    /// Consumes the Inspector and returns a [GethTraceBuilder].
    #[inline]
    pub fn into_geth_builder(self) -> GethTraceBuilder {
        GethTraceBuilder::new(self.traces.arena, self.config)
    }

    /// Returns true if we're no longer in the context of the root call.
    fn is_deep(&self) -> bool {
        // the root call will always be the first entry in the trace stack
        !self.trace_stack.is_empty()
    }

    /// Returns true if this a call to a precompile contract.
    ///
    /// Returns true if the `to` address is a precompile contract and the value
    /// is zero.
    #[inline]
    pub fn is_precompile_call(
        &self, to: &H160, value: U256, space: Space,
    ) -> bool {
        // TODO: check according block height
        let is_precompile = match space {
            Space::Native => self.machine.builtins().contains_key(&to),
            Space::Ethereum => self.machine.builtins_evm().contains_key(&to),
        };

        if is_precompile {
            // only if this is _not_ the root call
            return self.is_deep() && value.is_zero();
        }
        false
    }

    /// Returns the currently active call trace.
    ///
    /// This will be the last call trace pushed to the stack: the call we
    /// entered most recently.
    #[track_caller]
    #[inline]
    pub fn active_trace(&self) -> Option<&CallTraceNode> {
        self.trace_stack.last().map(|idx| &self.traces.arena[*idx])
    }

    /// Returns the last trace [CallTrace] index from the stack.
    ///
    /// This will be the currently active call trace.
    ///
    /// # Panics
    ///
    /// If no [CallTrace] was pushed
    #[track_caller]
    #[inline]
    pub fn last_trace_idx(&self) -> usize {
        self.trace_stack
            .last()
            .copied()
            .expect("can't start step without starting a trace first")
    }

    /// _Removes_ the last trace [CallTrace] index from the stack.
    ///
    /// # Panics
    ///
    /// If no [CallTrace] was pushed
    #[track_caller]
    #[inline]
    fn pop_trace_idx(&mut self) -> usize {
        self.trace_stack
            .pop()
            .expect("more traces were filled than started")
    }

    /// Starts tracking a new trace.
    ///
    /// Invoked on [Inspector::call].
    #[allow(clippy::too_many_arguments)]
    pub fn start_trace_on_call(
        &mut self, address: Address, input_data: Bytes, value: U256,
        kind: CallKind, caller: Address, mut gas_limit: u64,
        maybe_precompile: Option<bool>, tx_gas_limit: u64, depth: usize,
    ) {
        // This will only be true if the inspector is configured to exclude
        // precompiles and the call is to a precompile
        let push_kind = if maybe_precompile.unwrap_or(false) {
            // We don't want to track precompiles
            PushTraceKind::PushOnly
        } else {
            PushTraceKind::PushAndAttachToParent
        };

        if self.trace_stack.is_empty() {
            // this is the root call which should get the original gas limit of
            // the transaction, because initialization costs are
            // already subtracted from gas_limit For the root call
            // this value should use the transaction's gas limit See <https://github.com/paradigmxyz/reth/issues/3678> and <https://github.com/ethereum/go-ethereum/pull/27029>
            gas_limit = tx_gas_limit;
        }
        self.trace_stack.push(self.traces.push_trace(
            0,
            push_kind,
            CallTrace {
                depth,
                address,
                kind,
                data: input_data,
                value,
                status: InstructionResult::Continue,
                caller,
                maybe_precompile,
                gas_limit,
                ..Default::default()
            },
        ));
    }

    /// Fills the current trace with the outcome of a call.
    ///
    /// Invoked on [Inspector::call_end].
    ///
    /// # Panics
    ///
    /// This expects an existing trace [Self::start_trace_on_call]
    pub fn fill_trace_on_call_end(
        &mut self, result: InterpreterResult, created_address: Option<Address>,
        gas_spent: u64,
    ) {
        let InterpreterResult {
            result,
            output,
            gas: _,
        } = result;

        let trace_idx = self.pop_trace_idx();
        let trace = &mut self.traces.arena[trace_idx].trace;

        if trace_idx == 0 {
            // this is the root call which should get the gas used of the
            // transaction refunds are applied after execution,
            // which is when the root call ends
            // Conflux have no refund
            trace.gas_used = gas_used(gas_spent, 0);
        } else {
            trace.gas_used = gas_spent;
        }

        trace.status = result;
        trace.success = trace.status.is_ok();
        trace.output = output.clone();

        self.last_call_return_data = Some(output);

        if let Some(address) = created_address {
            // A new contract was created via CREATE
            trace.address = address;
        }
    }

    /// Starts tracking a step
    ///
    /// Invoked on [Inspector::step]
    ///
    /// # Panics
    ///
    /// This expects an existing [CallTrace], in other words, this panics if not
    /// within the context of a call.
    pub fn start_step(&mut self, interp: &dyn InterpreterInfo, depth: u64) {
        let trace_idx = self.last_trace_idx();
        let trace = &mut self.traces.arena[trace_idx];

        self.step_stack.push(StackStep {
            trace_idx,
            step_idx: trace.trace.steps.len(),
        });

        let memory = self
            .config
            .record_memory_snapshots
            .then(|| RecordedMemory::new(interp.mem().to_vec()))
            .unwrap_or_default();

        let stack: Option<Vec<U256>> =
            if self.config.record_stack_snapshots.is_full() {
                Some(
                    interp
                        .stack()
                        .into_iter()
                        .map(|v| to_alloy_u256(*v))
                        .collect(),
                )
            } else {
                None
            };

        let op = OpCode::new(interp.current_opcode())
            .or_else(|| {
                // if the opcode is invalid, we'll use the invalid opcode to
                // represent it because this is invoked before
                // the opcode is executed, the evm will eventually return a
                // `Halt` with invalid/unknown opcode as result
                let invalid_opcode = 0xfe;
                OpCode::new(invalid_opcode)
            })
            .expect("is valid opcode;");

        // if op is SLOAD or SSTORE, we need to record the storage change
        let storage_change = match (op.get(), stack.clone()) {
            (opcode::SLOAD, Some(s)) if s.len() >= 1 => {
                let key = s[s.len() - 1];
                let change = StorageChange {
                    key,
                    value: U256::ZERO,
                    had_value: None, // not used for now
                    reason: StorageChangeReason::SLOAD,
                };
                Some(change)
            }
            (opcode::SSTORE, Some(s)) if s.len() >= 2 => {
                let key = s[s.len() - 1];
                let value = s[s.len() - 2];
                let change = StorageChange {
                    key,
                    value,
                    had_value: None, // not used for now
                    reason: StorageChangeReason::SSTORE,
                };
                Some(change)
            }
            _ => None,
        };

        trace.trace.steps.push(CallTraceStep {
            depth,
            pc: interp.program_counter() as usize,
            op,
            contract: to_alloy_address(interp.contract_address()),
            stack,
            push_stack: None,
            memory_size: memory.len(),
            memory,
            gas_remaining: self.gas_inspector.gas_remaining(),
            gas_refund_counter: 0, // conflux has no gas refund

            // fields will be populated end of call
            gas_cost: 0,
            storage_change,
            status: InstructionResult::Continue,
        });
    }

    /// Fills the current trace with the output of a step.
    ///
    /// Invoked on [Inspector::step_end].
    pub fn fill_step_on_step_end(&mut self, interp: &dyn InterpreterInfo) {
        let StackStep {
            trace_idx,
            step_idx,
        } = self
            .step_stack
            .pop()
            .expect("can't fill step without starting a step first");
        let step = &mut self.traces.arena[trace_idx].trace.steps[step_idx];

        if self.config.record_stack_snapshots.is_pushes() {
            let spec = self.machine.spec(
                self.tx_exec_context.block_number,
                self.tx_exec_context.block_height,
            );
            let num_pushed =
                stack_push_count(step.op.get(), spec.cancun_opcodes);
            let start = interp.stack().len() - num_pushed;
            let push_stack = interp.stack()[start..].to_vec();
            step.push_stack = Some(
                push_stack.into_iter().map(|v| to_alloy_u256(v)).collect(),
            );
        }

        if self.config.record_memory_snapshots {
            // resize memory so opcodes that allocated memory is correctly
            // displayed
            if interp.mem().len() > step.memory.len() {
                step.memory.resize(interp.mem().len());
            }
        }

        if self.config.record_state_diff {
            let op = step.op.get();

            // update value if it's a SLOAD
            match (op, step.push_stack.clone(), step.storage_change) {
                (opcode::SLOAD, Some(s), Some(change)) if s.len() >= 1 => {
                    let val = s.last().unwrap();
                    step.storage_change = Some(StorageChange {
                        key: change.key,
                        value: *val,
                        had_value: None, // not used for now
                        reason: StorageChangeReason::SLOAD,
                    });
                }
                _ => {}
            }
        }

        // The gas cost is the difference between the recorded gas remaining at
        // the start of the step the remaining gas here, at the end of
        // the step.
        // todo(evm-inspector): Figure out why this can overflow. https://github.com/paradigmxyz/evm-inspectors/pull/38
        step.gas_cost = step
            .gas_remaining
            .saturating_sub(self.gas_inspector.gas_remaining());

        // TODO set the status
        // step.status = interp.instruction_result;
    }
}

#[derive(Clone, Copy, Debug)]
struct StackStep {
    trace_idx: usize,
    step_idx: usize,
}
