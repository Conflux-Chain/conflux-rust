pub mod exec_tracer;
pub mod gasman;
mod utils;

use exec_tracer::ExecTracer;
use gasman::GasMan;

use cfx_executor::{
    executive_observer::{AsTracer, DrainTrace, TracerTrait},
    machine::Machine,
};
use cfx_vm_tracer_derive::{AsTracer, DrainTrace};
use std::sync::Arc;

use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use geth_tracer::{GethTracer, TxExecContext};

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
        tx_exec_context: TxExecContext, machine: Arc<Machine>,
        opts: GethDebugTracingOptions,
    ) -> Self {
        Observer {
            tracer: None,
            gas_man: None,
            geth_tracer: Some(GethTracer::new(tx_exec_context, machine, opts)),
        }
    }
}
