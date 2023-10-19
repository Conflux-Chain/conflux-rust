mod frame_context;
mod frame_invoke;
mod frame_return;
mod frame_start;
mod resources;

pub use frame_context::FrameContext;
use frame_invoke::{InvokeInfo, SuspendedFrame};
pub use frame_return::{FrameResult, FrameReturn};
pub use frame_start::FreshFrame;
pub use resources::RuntimeRes;

#[cfg(test)]
pub use resources::runtime_res_test::OwnedRuntimeRes;

use crate::{state::Substate, unwrap_or_return};

use cfx_statedb::Result as DbResult;

enum ExecResult<'a> {
    Return(FrameResult),
    Invoke(InvokeInfo<'a>),
}

/// Execute the top call-create executive. This function handles resume
/// traps and sub-level tracing. The caller is expected to handle
/// current-level tracing.
pub fn exec_main_frame<'a>(
    main_frame: FreshFrame<'a>, mut resources: RuntimeRes<'a>,
) -> DbResult<FrameResult> {
    let mut frame_stack: Vec<SuspendedFrame> = Vec::new();
    let mut last_result = main_frame.init_and_exec(&mut resources)?;

    loop {
        last_result = match last_result {
            ExecResult::Return(result) => {
                let frame = unwrap_or_return!(frame_stack.pop(), Ok(result));
                frame.resume(result, &mut resources)?
            }
            ExecResult::Invoke(InvokeInfo { callee, caller }) => {
                frame_stack.push(caller);
                callee.init_and_exec(&mut resources)?
            }
        }
    }
}

pub fn accrue_substate(substate: &mut Substate, result: &mut FrameResult) {
    if let Ok(frame_return) = result {
        if let Some(child_substate) = std::mem::take(&mut frame_return.substate)
        {
            substate.accrue(child_substate);
        }
    }
}
