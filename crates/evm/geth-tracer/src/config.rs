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
use alloy_rpc_types_trace::{
    geth::{CallConfig, GethDefaultTracingOptions, PreStateConfig},
    parity::TraceType,
};
use std::collections::HashSet;

/// Gives guidance to the [TracingInspector](crate::tracing::TracingInspector).
///
/// Use [TracingInspectorConfig::default_parity] or
/// [TracingInspectorConfig::default_geth] to get the default configs for
/// specific styles of traces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracingInspectorConfig {
    /// Whether to record every individual opcode level step.
    pub record_steps: bool,
    /// Whether to record individual memory snapshots.
    pub record_memory_snapshots: bool,
    /// Whether to record individual stack snapshots.
    pub record_stack_snapshots: StackSnapshotType,
    /// Whether to record state diffs.
    pub record_state_diff: bool,
    /// Whether to ignore precompile calls.
    pub exclude_precompile_calls: bool,
    /// Whether to record logs
    pub record_logs: bool,
}

impl TracingInspectorConfig {
    /// Returns a config with everything enabled.
    pub const fn all() -> Self {
        Self {
            record_steps: true,
            record_memory_snapshots: true,
            record_stack_snapshots: StackSnapshotType::Full,
            record_state_diff: false,
            exclude_precompile_calls: false,
            record_logs: true,
        }
    }

    /// Returns a config with everything is disabled.
    pub const fn none() -> Self {
        Self {
            record_steps: false,
            record_memory_snapshots: false,
            record_stack_snapshots: StackSnapshotType::None,
            record_state_diff: false,
            exclude_precompile_calls: false,
            record_logs: false,
        }
    }

    /// Returns a config for parity style traces.
    ///
    /// This config does _not_ record opcode level traces and is suited for
    /// `trace_transaction`
    pub const fn default_parity() -> Self {
        Self {
            record_steps: false,
            record_memory_snapshots: false,
            record_stack_snapshots: StackSnapshotType::None,
            record_state_diff: false,
            exclude_precompile_calls: true,
            record_logs: false,
        }
    }

    /// Returns a config for geth style traces.
    ///
    /// This config does _not_ record opcode level traces and is suited for
    /// `debug_traceTransaction`
    ///
    /// This will configure the default output of geth's default
    /// [StructLogTracer](alloy_rpc_trace_types::geth::DefaultFrame).
    pub const fn default_geth() -> Self {
        Self {
            record_steps: true,
            record_memory_snapshots: false,
            record_stack_snapshots: StackSnapshotType::Full,
            record_state_diff: true,
            exclude_precompile_calls: false,
            record_logs: false,
        }
    }

    /// Returns the [TracingInspectorConfig] depending on the enabled
    /// [TraceType]s
    ///
    /// Note: the parity statediffs can be populated entirely via the execution
    /// result, so we don't need statediff recording
    #[inline]
    pub fn from_parity_config(trace_types: &HashSet<TraceType>) -> Self {
        let needs_vm_trace = trace_types.contains(&TraceType::VmTrace);
        let snap_type = if needs_vm_trace {
            StackSnapshotType::Pushes
        } else {
            StackSnapshotType::None
        };
        Self::default_parity()
            .set_steps(needs_vm_trace)
            .set_stack_snapshots(snap_type)
            .set_memory_snapshots(needs_vm_trace)
    }

    /// Returns a config for geth style traces based on the given
    /// [GethDefaultTracingOptions].
    ///
    /// This will configure the output of geth's default
    /// [StructLogTracer](alloy_rpc_trace_types::geth::DefaultFrame) according
    /// to the given config.
    #[inline]
    pub fn from_geth_config(config: &GethDefaultTracingOptions) -> Self {
        Self {
            record_memory_snapshots: config.enable_memory.unwrap_or_default(),
            record_stack_snapshots: if config.disable_stack.unwrap_or_default()
            {
                StackSnapshotType::None
            } else {
                StackSnapshotType::Full
            },
            record_state_diff: !config.disable_storage.unwrap_or_default(),
            ..Self::default_geth()
        }
    }

    /// Returns a config for geth's
    /// [CallTracer](alloy_rpc_trace_types::geth::CallFrame).
    ///
    /// This returns [Self::none] and enables
    /// [TracingInspectorConfig::record_logs] if configured in
    /// the given [CallConfig]
    #[inline]
    pub fn from_geth_call_config(config: &CallConfig) -> Self {
        Self::none()
            // call tracer is similar parity tracer with optional support for
            // logs
            .set_record_logs(config.with_log.unwrap_or_default())
    }

    /// Returns a config for geth's
    /// [PrestateTracer](alloy_rpc_trace_types::geth::PreStateFrame).
    ///
    /// Note: This currently returns [Self::none] because the prestate tracer
    /// result currently relies on the execution result entirely, see
    /// [GethTraceBuilder::geth_prestate_traces](crate::tracing::geth::GethTraceBuilder::geth_prestate_traces)
    #[inline]
    pub const fn from_geth_prestate_config(_config: &PreStateConfig) -> Self {
        Self::none()
    }

    /// Configure whether calls to precompiles should be ignored.
    ///
    /// If set to `true`, calls to precompiles without value transfers will be
    /// ignored.
    pub const fn set_exclude_precompile_calls(
        mut self, exclude_precompile_calls: bool,
    ) -> Self {
        self.exclude_precompile_calls = exclude_precompile_calls;
        self
    }

    /// Disable recording of individual opcode level steps
    pub const fn disable_steps(self) -> Self { self.set_steps(false) }

    /// Enable recording of individual opcode level steps
    pub const fn steps(self) -> Self { self.set_steps(true) }

    /// Configure whether individual opcode level steps should be recorded
    pub const fn set_steps(mut self, record_steps: bool) -> Self {
        self.record_steps = record_steps;
        self
    }

    /// Disable recording of individual memory snapshots
    pub const fn disable_memory_snapshots(self) -> Self {
        self.set_memory_snapshots(false)
    }

    /// Enable recording of individual memory snapshots
    pub const fn memory_snapshots(self) -> Self {
        self.set_memory_snapshots(true)
    }

    /// Configure whether the tracer should record memory snapshots
    pub const fn set_memory_snapshots(
        mut self, record_memory_snapshots: bool,
    ) -> Self {
        self.record_memory_snapshots = record_memory_snapshots;
        self
    }

    /// Disable recording of individual stack snapshots
    pub const fn disable_stack_snapshots(self) -> Self {
        self.set_stack_snapshots(StackSnapshotType::None)
    }

    /// Enable recording of individual stack snapshots
    pub const fn stack_snapshots(self) -> Self {
        self.set_stack_snapshots(StackSnapshotType::Full)
    }

    /// Configure how the tracer should record stack snapshots
    pub const fn set_stack_snapshots(
        mut self, record_stack_snapshots: StackSnapshotType,
    ) -> Self {
        self.record_stack_snapshots = record_stack_snapshots;
        self
    }

    /// Disable recording of state diffs
    pub const fn disable_state_diffs(self) -> Self {
        self.set_state_diffs(false)
    }

    /// Configure whether the tracer should record state diffs
    pub const fn set_state_diffs(mut self, record_state_diff: bool) -> Self {
        self.record_state_diff = record_state_diff;
        self
    }

    /// Sets state diff recording to true.
    ///
    /// Also enables steps recording since state diff recording requires steps
    /// recording.
    pub const fn with_state_diffs(self) -> Self {
        self.set_steps_and_state_diffs(true)
    }

    /// Configure whether the tracer should record steps and state diffs.
    ///
    /// This is a convenience method for setting both
    /// [TracingInspectorConfig::set_steps] and
    /// [TracingInspectorConfig::set_state_diffs] since tracking state diffs
    /// requires steps tracing.
    pub const fn set_steps_and_state_diffs(
        mut self, steps_and_diffs: bool,
    ) -> Self {
        self.record_steps = steps_and_diffs;
        self.record_state_diff = steps_and_diffs;
        self
    }

    /// Disable recording of individual logs
    pub const fn disable_record_logs(self) -> Self {
        self.set_record_logs(false)
    }

    /// Enable recording of individual logs
    pub const fn record_logs(self) -> Self { self.set_record_logs(true) }

    /// Configure whether the tracer should record logs
    pub const fn set_record_logs(mut self, record_logs: bool) -> Self {
        self.record_logs = record_logs;
        self
    }
}

/// How much of the stack to record. Nothing, just the items pushed, or the full
/// stack
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackSnapshotType {
    /// Don't record stack snapshots
    None,
    /// Record only the items pushed to the stack
    Pushes,
    /// Record the full stack
    Full,
}

impl StackSnapshotType {
    /// Returns true if this is the [StackSnapshotType::Full] variant
    #[inline]
    pub const fn is_full(self) -> bool { matches!(self, Self::Full) }

    /// Returns true if this is the [StackSnapshotType::Pushes] variant
    #[inline]
    pub const fn is_pushes(self) -> bool { matches!(self, Self::Pushes) }
}

/// What kind of tracing style this is.
///
/// This affects things like error messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceStyle {
    /// Parity style tracer
    Parity,
    /// Geth style tracer
    Geth,
}

impl TraceStyle {
    /// Returns true if this is a parity style tracer.
    pub(crate) const fn is_parity(self) -> bool { matches!(self, Self::Parity) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parity_config() {
        let mut s = HashSet::new();
        s.insert(TraceType::StateDiff);
        let config = TracingInspectorConfig::from_parity_config(&s);
        // not required
        assert!(!config.record_steps);
        assert!(!config.record_state_diff);

        let mut s = HashSet::new();
        s.insert(TraceType::VmTrace);
        let config = TracingInspectorConfig::from_parity_config(&s);
        assert!(config.record_steps);
        assert!(!config.record_state_diff);

        let mut s = HashSet::new();
        s.insert(TraceType::VmTrace);
        s.insert(TraceType::StateDiff);
        let config = TracingInspectorConfig::from_parity_config(&s);
        assert!(config.record_steps);
        // not required for StateDiff
        assert!(!config.record_state_diff);
    }
}
