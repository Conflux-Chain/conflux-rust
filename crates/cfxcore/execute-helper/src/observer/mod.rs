pub mod exec_tracer;
pub mod fourbyte;
pub mod gasman;
pub mod geth_tracer;
mod utils;

use exec_tracer::ExecTracer;
use gasman::GasMan;

use cfx_executor::{
    executive_observer::{AsTracer, DrainTrace, TracerTrait},
    machine::Machine,
};
use cfx_vm_tracer_derive::{AsTracer, DrainTrace};
use std::sync::Arc;

use self::geth_tracer::{GethTracer, TracingInspectorConfig};
use alloy_rpc_types_trace::geth::{
    CallConfig, GethDebugBuiltInTracerType, GethDefaultTracingOptions,
    PreStateConfig,
};

#[derive(AsTracer, DrainTrace)]
pub struct Observer {
    pub tracer: Option<ExecTracer>,
    pub gas_man: Option<GasMan>,
    pub geth_tracer: Option<GethTracer>,
}

impl Observer {
    pub fn with_tracing() -> Self {
        Observer {
            tracer: Some(ExecTracer::default()),
            gas_man: None,
            geth_tracer: None,
        }
    }

    pub fn with_no_tracing() -> Self {
        Observer {
            tracer: None,
            gas_man: None,
            geth_tracer: None,
        }
    }

    pub fn virtual_call() -> Self {
        Observer {
            tracer: Some(ExecTracer::default()),
            gas_man: Some(GasMan::default()),
            geth_tracer: None,
        }
    }

    pub fn geth_tracer(
        config: TracingInspectorConfig, tx_gas_limit: u64,
        machine: Arc<Machine>, tracer_type: Option<GethDebugBuiltInTracerType>,
        call_config: Option<CallConfig>,
        prestate_config: Option<PreStateConfig>,
        opcode_config: Option<GethDefaultTracingOptions>,
    ) -> Self {
        Observer {
            tracer: None,
            gas_man: None,
            geth_tracer: Some(GethTracer::new(
                config,
                tx_gas_limit,
                machine,
                tracer_type,
                call_config,
                prestate_config,
                opcode_config,
            )),
        }
    }
}
