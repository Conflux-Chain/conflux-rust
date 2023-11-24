// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod error_unwind;
pub mod gasman;
pub mod internal_transfer;
pub mod trace;
pub mod trace_filter;
pub mod tracer;
mod traits;

use cfx_vm_tracer_derive::AsTracer;
pub use error_unwind::ErrorUnwind;
pub use gasman::GasMan;
pub use internal_transfer::AddressPocket;
use internal_transfer::InternalTransferTracer;
pub use tracer::ExecutiveTracer;
use traits::{CallTracer, CheckpointTracer};

pub trait TracerTrait:
    CheckpointTracer + CallTracer + InternalTransferTracer
{
}

impl<T: CheckpointTracer + CallTracer + InternalTransferTracer> TracerTrait
    for T
{
}

pub trait AsTracer {
    fn as_tracer<'a>(&'a mut self) -> Box<dyn 'a + TracerTrait>;
}

#[derive(AsTracer)]
pub struct Observer {
    pub tracer: Option<ExecutiveTracer>,
    pub gas_man: Option<GasMan>,
}

impl Observer {
    pub fn with_tracing() -> Self {
        Observer {
            tracer: Some(ExecutiveTracer::default()),
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
            tracer: Some(ExecutiveTracer::default()),
            gas_man: Some(GasMan::default()),
        }
    }
}
