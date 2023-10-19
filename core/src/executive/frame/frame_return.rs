use super::{FrameContext, RuntimeRes};
use crate::{
    evm::{FinalizationResult, Finalize},
    state::Substate,
    vm::{self, GasLeft, ReturnData},
};

use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, Space, U256};

/// When the executive (the inner EVM) returns, this function will process
/// the rest tasks: If the execution successes, this function collects
/// storage collateral change from the cache to substate, merge substate to
/// its parent and settles down bytecode for newly created contract. If the
/// execution fails, this function reverts state and drops substate.
pub(super) fn process_return<'a>(
    mut context: FrameContext<'a>, result: vm::Result<GasLeft>,
    resources: &mut RuntimeRes<'a>,
) -> DbResult<FrameResult>
{
    let vm_context = context.make_vm_context(resources);
    // The post execution task in spec is completed here.
    let finalized_result = result.finalize(vm_context);
    let finalized_result = vm::separate_out_db_error(finalized_result)?;

    let apply_state =
        finalized_result.as_ref().map_or(false, |r| r.apply_state);
    let maybe_substate;
    if apply_state {
        let mut substate = context.substate;
        if let Some(create_address) = context.create_address {
            substate
                .contracts_created
                .push(create_address.with_space(context.space));
        }
        maybe_substate = Some(substate);
        resources.state.discard_checkpoint();
    } else {
        maybe_substate = None;
        resources.state.revert_to_checkpoint();
    }

    let create_address = context.create_address;
    let executive_result = finalized_result
        .map(|result| FrameReturn::new(result, create_address, maybe_substate));
    if context.create_address.is_some() {
        resources.tracer.record_create_result(&executive_result);
    } else {
        resources.tracer.record_call_result(&executive_result);
    }

    resources.callstack.pop();

    Ok(executive_result)
}

pub type FrameResult = vm::Result<FrameReturn>;

/// The result contains more data than finalization result.
#[derive(Debug)]
pub struct FrameReturn {
    /// Space
    pub space: Space,
    /// Final amount of gas left.
    pub gas_left: U256,
    /// Apply execution state changes or revert them.
    pub apply_state: bool,
    /// Return data buffer.
    pub return_data: ReturnData,
    /// Create address.
    pub create_address: Option<Address>,
    /// Substate.
    pub substate: Option<Substate>,
}

impl Into<FinalizationResult> for FrameReturn {
    fn into(self) -> FinalizationResult {
        FinalizationResult {
            space: self.space,
            gas_left: self.gas_left,
            apply_state: self.apply_state,
            return_data: self.return_data,
        }
    }
}

impl FrameReturn {
    fn new(
        result: FinalizationResult, create_address: Option<Address>,
        substate: Option<Substate>,
    ) -> Self
    {
        FrameReturn {
            space: result.space,
            gas_left: result.gas_left,
            apply_state: result.apply_state,
            return_data: result.return_data,
            create_address,
            substate,
        }
    }
}
