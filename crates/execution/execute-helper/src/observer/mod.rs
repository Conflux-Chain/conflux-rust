pub mod access_list;
pub mod exec_tracer;
pub mod gasman;
mod utils;

use access_list::AccessListInspector;
use exec_tracer::ExecTracer;
use gasman::GasMan;

use cfx_executor::{
    executive_observer::{AsTracer, DrainTrace, TracerTrait},
    machine::Machine,
};
use cfx_vm_tracer_derive::{AsTracer, DrainTrace};
use std::sync::Arc;

use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use cfx_types::Address;
use geth_tracer::{GethTracer, TxExecContext};
use primitives::AccessList;
use std::collections::HashSet;

#[derive(AsTracer, DrainTrace)]
pub struct Observer {
    pub tracer: Option<ExecTracer>, // parity tracer
    pub gas_man: Option<GasMan>,
    pub geth_tracer: Option<GethTracer>,
    pub access_list_inspector: Option<AccessListInspector>,
}

impl Observer {
    pub fn with_tracing() -> Self {
        Observer {
            tracer: Some(ExecTracer::default()),
            gas_man: None,
            geth_tracer: None,
            access_list_inspector: None,
        }
    }

    pub fn with_no_tracing() -> Self {
        Observer {
            tracer: None,
            gas_man: None,
            geth_tracer: None,
            access_list_inspector: None,
        }
    }

    pub fn virtual_call() -> Self {
        Observer {
            tracer: Some(ExecTracer::default()),
            gas_man: Some(GasMan::default()),
            geth_tracer: None,
            access_list_inspector: None,
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
            access_list_inspector: None,
        }
    }

    pub fn access_list_inspector(
        access_list: AccessList, excluded: HashSet<Address>,
    ) -> Self {
        Observer {
            tracer: None,
            gas_man: None,
            geth_tracer: None,
            access_list_inspector: Some(AccessListInspector::new(
                access_list,
                excluded,
            )),
        }
    }
}
