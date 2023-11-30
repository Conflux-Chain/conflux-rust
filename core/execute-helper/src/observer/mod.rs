pub mod exec_tracer;
pub mod gasman;
mod utils;

use exec_tracer::ExecTracer;
use gasman::GasMan;

use cfx_executor::executive_observer::{AsTracer, DrainTrace, TracerTrait};
use cfx_vm_tracer_derive::{AsTracer, DrainTrace};

#[derive(AsTracer, DrainTrace)]
pub struct Observer {
    pub tracer: Option<ExecTracer>,
    pub gas_man: Option<GasMan>,
}

impl Observer {
    pub fn with_tracing() -> Self {
        Observer {
            tracer: Some(ExecTracer::default()),
            gas_man: None,
        }
    }

    pub fn with_no_tracing() -> Self {
        Observer {
            tracer: None,
            gas_man: None,
        }
    }

    pub fn virtual_call() -> Self {
        Observer {
            tracer: Some(ExecTracer::default()),
            gas_man: Some(GasMan::default()),
        }
    }
}
