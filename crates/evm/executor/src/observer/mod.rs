// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod as_tracer;
mod call_tracer;
mod checkpoint_tracer;
mod drain_trace;
mod internal_transfer_tracer;
mod opcode_tracer;
mod storage_tracer;
mod tracer_trait;

pub use as_tracer::AsTracer;
pub use call_tracer::CallTracer;
pub use cfx_parity_trace_types::AddressPocket;
pub use checkpoint_tracer::CheckpointTracer;
pub use drain_trace::DrainTrace;
pub use internal_transfer_tracer::InternalTransferTracer;
pub use opcode_tracer::OpcodeTracer;
pub use storage_tracer::StorageTracer;
pub use tracer_trait::TracerTrait;

pub trait ExecutiveObserver: DrainTrace + AsTracer {}

impl<T: DrainTrace + AsTracer> ExecutiveObserver for T {}
