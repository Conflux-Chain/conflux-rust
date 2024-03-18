#![allow(unused)]
mod arena;
mod builder;
mod config;
mod db_adapter;
mod gas;
mod types;
mod utils;

pub use arena::CallTraceArena;
pub use builder::geth::{self, GethTraceBuilder};
use cfx_types::H160;
pub use config::{StackSnapshotType, TracingInspectorConfig};

use arena::PushTraceKind;
use gas::GasInspector;
use types::{
    CallKind, CallTrace, CallTraceNode, CallTraceStep, LogCallOrder,
    RecordedMemory,
};
use utils::{
    convert_h160, convert_h256, convert_u256, gas_used, stack_push_count,
};

use alloy_primitives::{Address, Bytes, LogData, U256};
use revm::interpreter::{Gas, InstructionResult, InterpreterResult, OpCode};

use cfx_executor::{
    observer::{
        CallTracer, CheckpointTracer, DrainTrace, InternalTransferTracer,
        OpcodeTracer, StorageTracer,
    },
    stack::{FrameResult, FrameReturn},
};

use cfx_vm_types::{ActionParams, CallType, Error, InterpreterInfo};

use alloy_rpc_trace_types::geth::{
    CallFrame, DefaultFrame, GethTrace, NoopFrame,
};

#[derive(Clone, Debug)]
pub struct TracingInspector {
    /// Configures what and how the inspector records traces.
    config: TracingInspectorConfig,
    /// Records all call traces
    traces: CallTraceArena,
    /// Tracks active calls
    trace_stack: Vec<usize>,
    /// Tracks active steps
    step_stack: Vec<StackStep>,
    /// Tracks the return value of the last call
    last_call_return_data: Option<Bytes>,
    /// The gas inspector used to track remaining gas.
    gas_inspector: GasInspector,
    // call depth
    depth: usize,
    // gas stack, used to trace gas_spent in call_result/create_result
    gas_stack: Vec<cfx_types::U256>,
}

impl TracingInspector {
    /// Returns a new instance for the given config
    pub fn new(config: TracingInspectorConfig) -> Self {
        Self {
            config,
            traces: Default::default(),
            trace_stack: vec![],
            step_stack: vec![],
            last_call_return_data: None,
            gas_inspector: Default::default(),
            depth: 0,
            gas_stack: vec![],
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
            depth,
            gas_stack,
        } = self;
        traces.clear();
        trace_stack.clear();
        step_stack.clear();
        gas_stack.clear();
        last_call_return_data.take();
        *gas_inspector = Default::default();
        *depth = 0;
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
    fn is_precompile_call(&self, _to: &Address, value: U256) -> bool {
        // TODO(pana) check to is in precompile list
        // precompile list is in Machine object
        if false {
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
    fn active_trace(&self) -> Option<&CallTraceNode> {
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
    fn last_trace_idx(&self) -> usize {
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
    fn start_trace_on_call(
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
    fn fill_trace_on_call_end(
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
    fn start_step(&mut self, interp: &dyn InterpreterInfo, depth: u64) {
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

        let stack = if self.config.record_stack_snapshots.is_full() {
            Some(
                interp
                    .stack()
                    .into_iter()
                    .map(|v| convert_u256(v))
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

        trace.trace.steps.push(CallTraceStep {
            depth,
            pc: interp.program_counter() as usize,
            op,
            contract: convert_h160(interp.contract_address()),
            stack,
            push_stack: None,
            memory_size: memory.len(),
            memory,
            gas_remaining: self.gas_inspector.gas_remaining(),
            gas_refund_counter: 0, // conflux has no gas refund

            // fields will be populated end of call
            gas_cost: 0,
            storage_change: None,
            status: InstructionResult::Continue,
        });
    }

    /// Fills the current trace with the output of a step.
    ///
    /// Invoked on [Inspector::step_end].
    fn fill_step_on_step_end(&mut self, interp: &dyn InterpreterInfo) {
        let StackStep {
            trace_idx,
            step_idx,
        } = self
            .step_stack
            .pop()
            .expect("can't fill step without starting a step first");
        let step = &mut self.traces.arena[trace_idx].trace.steps[step_idx];

        if self.config.record_stack_snapshots.is_pushes() {
            let num_pushed = stack_push_count(step.op.get());
            let start = interp.stack().len() - num_pushed;
            let push_stack = interp.stack()[start..].to_vec();
            step.push_stack =
                Some(push_stack.into_iter().map(|v| convert_u256(v)).collect());
        }

        if self.config.record_memory_snapshots {
            // resize memory so opcodes that allocated memory is correctly
            // displayed
            if interp.mem().len() > step.memory.len() {
                step.memory.resize(interp.mem().len());
            }
        }
        if self.config.record_state_diff {
            let _op = step.op.get();

            // TODO setup the storage_change
        }

        // The gas cost is the difference between the recorded gas remaining at
        // the start of the step the remaining gas here, at the end of
        // the step.
        // todo: Figure out why this can overflow. https://github.com/paradigmxyz/evm-inspectors/pull/38
        step.gas_cost = step
            .gas_remaining
            .saturating_sub(self.gas_inspector.gas_remaining());

        // TODO set the status
        // step.status = interp.instruction_result;
    }
}

pub struct GethTracer {
    inner: TracingInspector,
}

impl GethTracer {
    pub fn new(config: TracingInspectorConfig) -> Self {
        Self {
            inner: TracingInspector::new(config),
        }
    }

    pub fn drain(self) -> GethTrace {
        // TODO return the right kind of frame according to the config
        GethTrace::NoopTracer(NoopFrame::default())
    }
}

impl DrainTrace for GethTracer {
    fn drain_trace(self, map: &mut typemap::ShareDebugMap) {
        map.insert::<GethTraceKey>(self.drain());
    }
}

pub struct GethTraceKey;

impl typemap::Key for GethTraceKey {
    type Value = GethTrace;
}

impl CheckpointTracer for GethTracer {}

impl InternalTransferTracer for GethTracer {}

impl StorageTracer for GethTracer {}

impl CallTracer for GethTracer {
    fn record_call(&mut self, params: &ActionParams) {
        self.inner.depth += 1;
        self.inner.gas_stack.push(params.gas.clone());

        // determine correct `from` and `to` based on the call scheme
        let (from, to) = match params.call_type {
            CallType::DelegateCall | CallType::CallCode => (
                convert_h160(params.address),
                convert_h160(params.code_address),
            ),
            _ => (convert_h160(params.sender), convert_h160(params.address)),
        };

        let value = if matches!(params.call_type, CallType::DelegateCall) {
            // for delegate calls we need to use the value of the top trace
            if let Some(parent) = self.inner.active_trace() {
                parent.trace.value
            } else {
                convert_u256(params.value.value())
            }
        } else {
            convert_u256(params.value.value())
        };

        // if calls to precompiles should be excluded, check whether this is a
        // call to a precompile
        let maybe_precompile = self
            .inner
            .config
            .exclude_precompile_calls
            .then(|| self.inner.is_precompile_call(&to, value));

        self.inner.start_trace_on_call(
            to,
            params.data.clone().unwrap_or_default().into(),
            value,
            params.call_type.into(),
            from,
            params.gas.as_u64(),
            maybe_precompile,
            params.gas.as_u64(), /* TODO should use tx gas_limit not frame
                                  * gas_limit */
            self.inner.depth,
        );
    }

    fn record_call_result(&mut self, result: &FrameResult) {
        self.inner.depth -= 1;
        let mut gas_spent =
            self.inner.gas_stack.pop().expect("should have value");

        if let Ok(r) = result {
            gas_spent = gas_spent - r.gas_left;
        }

        let instruction_result = to_instruction_result(result);

        if instruction_result.is_error() {
            self.inner.gas_inspector.set_gas_remainning(0);
        }

        let output = result
            .as_ref()
            .map(|f| Bytes::from(f.return_data.to_vec()))
            .unwrap_or_default();

        let outcome = InterpreterResult {
            result: instruction_result,
            output,
            gas: Gas::default(),
        };

        self.inner
            .fill_trace_on_call_end(outcome, None, gas_spent.as_u64());
    }

    fn record_create(&mut self, params: &ActionParams) {
        self.inner.depth += 1;
        self.inner.gas_stack.push(params.gas.clone());

        let value = if matches!(params.call_type, CallType::DelegateCall) {
            // for delegate calls we need to use the value of the top trace
            if let Some(parent) = self.inner.active_trace() {
                parent.trace.value
            } else {
                convert_u256(params.value.value())
            }
        } else {
            convert_u256(params.value.value())
        };

        self.inner.start_trace_on_call(
            Address::default(), // call_result will set this address
            params.data.clone().unwrap_or_default().into(),
            value,
            params.call_type.into(),
            convert_h160(params.sender),
            params.gas.as_u64(),
            Some(false),
            params.gas.as_u64(),
            self.inner.depth,
        );
    }

    fn record_create_result(&mut self, result: &FrameResult) {
        self.inner.depth -= 1;
        let mut gas_spent =
            self.inner.gas_stack.pop().expect("should have value");

        if let Ok(r) = result {
            gas_spent = gas_spent - r.gas_left;
        }

        let instruction_result = to_instruction_result(result);

        if instruction_result.is_error() {
            self.inner.gas_inspector.set_gas_remainning(0);
        }

        let output = result
            .as_ref()
            .map(|f| Bytes::from(f.return_data.to_vec()))
            .unwrap_or_default();

        let outcome = InterpreterResult {
            result: instruction_result,
            output,
            gas: Gas::default(),
        };

        let create_address =
            if let Ok(FrameReturn { create_address, .. }) = result {
                create_address.as_ref().map(|h| convert_h160(*h))
            } else {
                None
            };

        self.inner.fill_trace_on_call_end(
            outcome,
            create_address,
            gas_spent.as_u64(),
        );
    }
}

impl OpcodeTracer for GethTracer {
    fn do_trace_opcode(&self, enabled: &mut bool) {
        if self.inner.config.record_steps {
            *enabled |= true;
        }
    }

    fn initialize_interp(&mut self, gas_limit: cfx_types::U256) {
        self.inner
            .gas_inspector
            .set_gas_remainning(gas_limit.as_u64());
    }

    fn step(&mut self, interp: &dyn InterpreterInfo, depth: usize) {
        self.inner
            .gas_inspector
            .set_gas_remainning(interp.gas_remainning().as_u64());

        if self.inner.config.record_steps {
            self.inner.start_step(interp, depth as u64);
        }
    }

    fn step_end(&mut self, interp: &dyn InterpreterInfo) {
        let remainning = interp.gas_remainning().as_u64();
        let last_gas_cost = self
            .inner
            .gas_inspector
            .gas_remaining()
            .saturating_sub(remainning);
        self.inner.gas_inspector.set_gas_remainning(remainning);
        self.inner.gas_inspector.set_last_gas_cost(last_gas_cost);

        // trace
        if self.inner.config.record_steps {
            self.inner.fill_step_on_step_end(interp);
        }
    }

    fn log(
        &mut self, _address: &cfx_types::Address, topics: Vec<cfx_types::H256>,
        data: &[u8],
    ) {
        if self.inner.config.record_logs {
            let trace_idx = self.inner.last_trace_idx();
            let trace = &mut self.inner.traces.arena[trace_idx];
            trace.ordering.push(LogCallOrder::Log(trace.logs.len()));
            trace.logs.push(LogData::new_unchecked(
                topics.iter().map(|f| convert_h256(*f)).collect(),
                Bytes::from(data.to_vec()),
            ));
        }
    }

    fn selfdestruct(
        &mut self, _contract: &cfx_types::Address, target: &cfx_types::Address,
        _value: cfx_types::U256,
    ) {
        let trace_idx = self.inner.last_trace_idx();
        let trace = &mut self.inner.traces.arena[trace_idx].trace;
        trace.selfdestruct_refund_target = Some(convert_h160(*target as H160))
    }
}

#[derive(Clone, Copy, Debug)]
struct StackStep {
    trace_idx: usize,
    step_idx: usize,
}

pub fn to_instruction_result(frame_result: &FrameResult) -> InstructionResult {
    let result = match frame_result {
        Ok(_r) => InstructionResult::Return, // todo check this
        Err(err) => match err {
            Error::OutOfGas => InstructionResult::OutOfGas,
            Error::BadJumpDestination { destination: _ } => {
                InstructionResult::InvalidJump
            }
            Error::BadInstruction { instruction: _ } => {
                InstructionResult::OpcodeNotFound
            }
            Error::StackUnderflow {
                instruction: _,
                wanted: _,
                on_stack: _,
            } => InstructionResult::StackUnderflow,
            Error::OutOfStack { .. } => InstructionResult::StackOverflow,
            Error::SubStackUnderflow { .. } => {
                InstructionResult::StackUnderflow
            }
            Error::OutOfSubStack {
                wanted: _,
                limit: _,
            } => InstructionResult::StackOverflow,
            Error::InvalidSubEntry => InstructionResult::NotActivated, //
            Error::NotEnoughBalanceForStorage {
                required: _,
                got: _,
            } => InstructionResult::OutOfFunds,
            Error::ExceedStorageLimit => InstructionResult::OutOfGas, /* treat storage as gas */
            Error::BuiltIn(_) => InstructionResult::PrecompileError,
            Error::InternalContract(_) => InstructionResult::PrecompileError, /* treat internalContract as builtIn */
            Error::MutableCallInStaticContext => {
                InstructionResult::StateChangeDuringStaticCall
            }
            Error::StateDbError(_) => InstructionResult::FatalExternalError,
            Error::Wasm(_) => InstructionResult::NotActivated,
            Error::OutOfBounds => InstructionResult::OutOfOffset,
            Error::Reverted => InstructionResult::Revert,
            Error::InvalidAddress(_) => todo!(), /* when selfdestruct refund */
            // address is invalid will
            // emit this error
            Error::ConflictAddress(_) => InstructionResult::CreateCollision,
        },
    };
    result
}
