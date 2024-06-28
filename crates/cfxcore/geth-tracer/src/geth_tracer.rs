use crate::{
    config::TracingInspectorConfig,
    fourbyte::FourByteInspector,
    tracing_inspector::TracingInspector,
    types::{LogCallOrder, TxExecContext},
    utils::{to_alloy_address, to_alloy_h256, to_alloy_u256},
};
use alloy_primitives::{Address, Bytes, LogData};
use alloy_rpc_types_trace::geth::{
    CallConfig, GethDebugBuiltInTracerType, GethDebugBuiltInTracerType::*,
    GethDebugTracerType, GethDebugTracingOptions, GethTrace, NoopFrame,
    PreStateConfig,
};
use cfx_executor::{
    machine::Machine,
    observer::{
        CallTracer, CheckpointTracer, DrainTrace, InternalTransferTracer,
        OpcodeTracer, StorageTracer,
    },
    stack::{FrameResult, FrameReturn},
};
use cfx_types::H160;
use cfx_vm_types::{ActionParams, CallType, Error, InterpreterInfo};
use revm::{
    db::InMemoryDB,
    interpreter::{Gas, InstructionResult, InterpreterResult},
    primitives::State,
};
use std::sync::Arc;

pub struct GethTracer {
    inner: TracingInspector,
    //
    fourbyte_inspector: FourByteInspector,
    //
    tx_gas_limit: u64, // tx level gas limit
    //
    gas_left: u64, // update in call_result/create_result
    // call depth
    depth: usize,
    //
    opts: GethDebugTracingOptions,
    // gas stack, used to trace gas_spent in call_result/create_result
    pub gas_stack: Vec<u64>,
}

impl GethTracer {
    pub fn new(
        tx_exec_context: TxExecContext, machine: Arc<Machine>,
        opts: GethDebugTracingOptions,
    ) -> Self {
        let TxExecContext { tx_gas_limit, .. } = tx_exec_context;
        let config = match opts.tracer {
            Some(GethDebugTracerType::BuiltInTracer(builtin_tracer)) => {
                match builtin_tracer {
                    FourByteTracer | NoopTracer | MuxTracer => {
                        TracingInspectorConfig::none()
                    }
                    CallTracer => {
                        let c = opts
                            .tracer_config
                            .clone()
                            .into_call_config()
                            .expect("should success");
                        TracingInspectorConfig::from_geth_call_config(&c)
                    }
                    PreStateTracer => {
                        let c = opts
                            .tracer_config
                            .clone()
                            .into_pre_state_config()
                            .expect("should success");
                        TracingInspectorConfig::from_geth_prestate_config(&c)
                    }
                }
            }
            Some(GethDebugTracerType::JsTracer(_)) => {
                TracingInspectorConfig::none()
            }
            None => TracingInspectorConfig::from_geth_config(&opts.config),
        };

        Self {
            inner: TracingInspector::new(config, machine, tx_exec_context),
            fourbyte_inspector: FourByteInspector::new(),
            tx_gas_limit,
            depth: 0,
            gas_left: tx_gas_limit,
            opts,
            gas_stack: Vec::new(),
        }
    }

    fn tracer_type(&self) -> Option<GethDebugBuiltInTracerType> {
        match self.opts.tracer.clone() {
            Some(t) => match t {
                GethDebugTracerType::BuiltInTracer(builtin_tracer) => {
                    Some(builtin_tracer)
                }
                GethDebugTracerType::JsTracer(_) => {
                    // not supported
                    Some(NoopTracer)
                }
            },
            None => None,
        }
    }

    fn call_config(&self) -> Option<CallConfig> {
        self.opts.tracer_config.clone().into_call_config().ok()
    }

    fn prestate_config(&self) -> Option<PreStateConfig> {
        self.opts.tracer_config.clone().into_pre_state_config().ok()
    }

    pub fn is_fourbyte_tracer(&self) -> bool {
        self.tracer_type() == Some(FourByteTracer)
    }

    pub fn gas_used(&self) -> u64 { self.tx_gas_limit - self.gas_left }

    pub fn drain(self) -> GethTrace {
        let trace = match self.tracer_type() {
            Some(t) => match t {
                FourByteTracer => self.fourbyte_inspector.drain(),
                CallTracer => {
                    let gas_used = self.gas_used();
                    let opts = self.call_config().expect("should have config");
                    let frame = self
                        .inner
                        .into_geth_builder()
                        .geth_call_traces(opts, gas_used);
                    GethTrace::CallTracer(frame)
                }
                PreStateTracer => {
                    // TODO replace the empty state and db with a real state
                    let opts =
                        self.prestate_config().expect("should have config");
                    let state = State::default();
                    let db = InMemoryDB::default();
                    let frame = self
                        .inner
                        .into_geth_builder()
                        .geth_prestate_traces(state, opts, db)
                        .unwrap();
                    GethTrace::PreStateTracer(frame)
                }
                NoopTracer | MuxTracer => {
                    GethTrace::NoopTracer(NoopFrame::default())
                }
            },
            None => {
                let gas_used = self.gas_used();
                let return_value = self
                    .inner
                    .last_call_return_data
                    .clone()
                    .unwrap_or_default();
                let opts = self.opts.config;
                let frame = self.inner.into_geth_builder().geth_traces(
                    gas_used,
                    return_value,
                    opts,
                );
                GethTrace::Default(frame)
            }
        };

        trace
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
        if self.is_fourbyte_tracer() {
            self.fourbyte_inspector.record_call(params);
            return;
        }

        let gas_limit = params.gas.as_u64();
        self.gas_stack.push(gas_limit);

        // determine correct `from` and `to` based on the call scheme
        let (from, to) = match params.call_type {
            CallType::DelegateCall | CallType::CallCode => {
                (params.address, params.code_address)
            }
            _ => (params.sender, params.address),
        };

        let value = if matches!(params.call_type, CallType::DelegateCall)
            && self.inner.active_trace().is_some()
        {
            // for delegate calls we need to use the value of the top trace
            let parent = self.inner.active_trace().unwrap();
            parent.trace.value
        } else {
            to_alloy_u256(params.value.value())
        };

        // if calls to precompiles should be excluded, check whether this is a
        // call to a precompile
        let maybe_precompile =
            self.inner.config.exclude_precompile_calls.then(|| {
                self.inner.is_precompile_call(&to, value, params.space)
            });

        let to = to_alloy_address(to);
        let from = to_alloy_address(from);
        self.inner.start_trace_on_call(
            to,
            params.data.clone().unwrap_or_default().into(),
            value,
            params.call_type.into(),
            from,
            params.gas.as_u64(),
            maybe_precompile,
            self.tx_gas_limit,
            self.depth,
        );

        self.depth += 1;
    }

    fn record_call_result(&mut self, result: &FrameResult) {
        if self.is_fourbyte_tracer() {
            return;
        }

        self.depth -= 1;
        let mut gas_spent = self.gas_stack.pop().expect("should have value");

        if let Ok(r) = result {
            gas_spent = gas_spent - r.gas_left.as_u64();
            self.gas_left = r.gas_left.as_u64();
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

        self.inner.fill_trace_on_call_end(outcome, None, gas_spent);
    }

    fn record_create(&mut self, params: &ActionParams) {
        if self.is_fourbyte_tracer() {
            return;
        }

        let gas_limit = params.gas.as_u64();
        self.gas_stack.push(gas_limit);

        let value = if matches!(params.call_type, CallType::DelegateCall) {
            // for delegate calls we need to use the value of the top trace
            if let Some(parent) = self.inner.active_trace() {
                parent.trace.value
            } else {
                to_alloy_u256(params.value.value())
            }
        } else {
            to_alloy_u256(params.value.value())
        };

        self.inner.start_trace_on_call(
            Address::default(), // call_result will set this address
            params.data.clone().unwrap_or_default().into(),
            value,
            params.call_type.into(),
            to_alloy_address(params.sender),
            params.gas.as_u64(),
            Some(false),
            params.gas.as_u64(),
            self.depth,
        );

        self.depth += 1;
    }

    fn record_create_result(&mut self, result: &FrameResult) {
        if self.is_fourbyte_tracer() {
            return;
        }

        self.depth -= 1;
        let mut gas_spent = self.gas_stack.pop().expect("should have value");

        if let Ok(r) = result {
            gas_spent = gas_spent - r.gas_left.as_u64();
            self.gas_left = r.gas_left.as_u64();
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
                create_address.as_ref().map(|h| to_alloy_address(*h))
            } else {
                None
            };

        self.inner
            .fill_trace_on_call_end(outcome, create_address, gas_spent);
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

    fn step(&mut self, interp: &dyn InterpreterInfo) {
        self.inner
            .gas_inspector
            .set_gas_remainning(interp.gas_remainning().as_u64());

        if self.inner.config.record_steps {
            self.inner.start_step(interp, self.depth as u64);
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
        &mut self, _address: &cfx_types::Address,
        topics: &Vec<cfx_types::H256>, data: &[u8],
    ) {
        if self.inner.config.record_logs {
            let trace_idx = self.inner.last_trace_idx();
            let trace = &mut self.inner.traces.arena[trace_idx];
            trace.ordering.push(LogCallOrder::Log(trace.logs.len()));
            trace.logs.push(LogData::new_unchecked(
                topics.iter().map(|f| to_alloy_h256(*f)).collect(),
                Bytes::from(data.to_vec()),
            ));
        }
    }

    fn selfdestruct(
        &mut self, _contract: &cfx_types::Address, target: &cfx_types::Address,
        _value: cfx_types::U256,
    ) {
        if self.is_fourbyte_tracer() {
            return;
        }

        let trace_idx = self.inner.last_trace_idx();
        let trace = &mut self.inner.traces.arena[trace_idx].trace;
        trace.selfdestruct_refund_target =
            Some(to_alloy_address(*target as H160))
    }
}

pub fn to_instruction_result(frame_result: &FrameResult) -> InstructionResult {
    let result = match frame_result {
        Ok(r) => match r.apply_state {
            true => InstructionResult::Return,
            false => InstructionResult::Revert,
        },
        Err(err) => match err {
            Error::OutOfGas => InstructionResult::OutOfGas,
            Error::BadJumpDestination { .. } => InstructionResult::InvalidJump,
            Error::BadInstruction { .. } => InstructionResult::OpcodeNotFound,
            Error::StackUnderflow { .. } => InstructionResult::StackUnderflow,
            Error::OutOfStack { .. } => InstructionResult::StackOverflow,
            Error::SubStackUnderflow { .. } => {
                InstructionResult::StackUnderflow
            }
            Error::OutOfSubStack { .. } => InstructionResult::StackOverflow,
            Error::InvalidSubEntry => InstructionResult::NotActivated, //
            Error::NotEnoughBalanceForStorage { .. } => {
                InstructionResult::OutOfFunds
            }
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
            // address is invalid will emit this error
            Error::ConflictAddress(_) => InstructionResult::CreateCollision,
        },
    };
    result
}
