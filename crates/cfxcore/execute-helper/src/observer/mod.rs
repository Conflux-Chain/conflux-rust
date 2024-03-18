pub mod exec_tracer;
pub mod fourbyte;
pub mod gasman;
pub mod geth_tracer;
mod utils;

use exec_tracer::ExecTracer;
use gasman::GasMan;

use cfx_executor::executive_observer::{AsTracer, DrainTrace, TracerTrait};
use cfx_vm_tracer_derive::{AsTracer, DrainTrace};

use self::geth_tracer::GethTracer;

#[derive(AsTracer, DrainTrace)]
pub struct Observer {
    pub tracer: Option<ExecTracer>,
    pub gas_man: Option<GasMan>,
    pub geth_tracer: Option<GethTracer>,
}

// TODO[geth-tracer]: instantiation your tracer here.

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
}
