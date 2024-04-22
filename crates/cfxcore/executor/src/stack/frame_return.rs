use super::{FrameLocal, RuntimeRes};
use crate::substate::Substate;

use cfx_types::{Address, Space, U256};
use cfx_vm_interpreter::FinalizationResult;
use cfx_vm_types::{self as vm, ReturnData};

/// Processes the result of a frame's execution and updates the state and
/// resources accordingly.
pub(super) fn process_return<'a>(
    frame_local: FrameLocal<'a>, result: vm::Result<FinalizationResult>,
    resources: &mut RuntimeRes<'a>,
) -> FrameResult {
    let is_create = frame_local.create_address.is_some();
    let frame_result =
        result.map(|result| FrameReturn::new(frame_local, result));

    let apply_state = frame_result.as_ref().map_or(false, |r| r.apply_state);

    if apply_state {
        resources.state.discard_checkpoint();
    } else {
        resources.state.revert_to_checkpoint();
    }

    if is_create {
        resources.tracer.record_create_result(&frame_result);
    } else {
        resources.tracer.record_call_result(&frame_result);
    }

    resources.callstack.pop();

    frame_result
}

/// The result of executing a frame
pub type FrameResult = vm::Result<FrameReturn>;

/// The result of executing a frame on a successful complete or an expected
/// revert.
#[derive(Debug)]
pub struct FrameReturn {
    /// The space the current frame belongs.
    pub space: Space,

    /// Final amount of gas left.
    pub gas_left: U256,

    /// Apply execution state changes or revert them.
    pub apply_state: bool,

    /// Return data buffer.
    pub return_data: ReturnData,

    /// The address of a newly created contract, if applicable.
    pub create_address: Option<Address>,

    /// Changes produced during execution for post-execution logic, if
    /// `apply_state` is true.
    pub substate: Option<Substate>,
}

impl Into<FinalizationResult> for FrameReturn {
    fn into(self) -> FinalizationResult {
        FinalizationResult {
            gas_left: self.gas_left,
            apply_state: self.apply_state,
            return_data: self.return_data,
        }
    }
}

impl FrameReturn {
    fn new(frame_local: FrameLocal, result: FinalizationResult) -> Self {
        let substate;
        let create_address;
        if result.apply_state {
            substate = Some(frame_local.substate);
            create_address = frame_local.create_address;
        } else {
            substate = None;
            create_address = None;
        };
        FrameReturn {
            space: frame_local.space,
            gas_left: result.gas_left,
            apply_state: result.apply_state,
            return_data: result.return_data,
            create_address,
            substate,
        }
    }
}
