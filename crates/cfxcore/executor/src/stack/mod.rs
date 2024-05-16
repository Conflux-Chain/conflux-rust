mod executable;
mod frame_invoke;
mod frame_local;
mod frame_return;
mod frame_start;
mod resources;
mod resumable;
mod stack_info;

pub use crate::context::Context;
pub use executable::{Executable, ExecutableOutcome};
pub use frame_local::FrameLocal;
pub use frame_return::{FrameResult, FrameReturn};
pub use frame_start::FreshFrame;
pub use resources::RuntimeRes;
pub use resumable::Resumable;
pub use stack_info::CallStackInfo;

#[cfg(test)]
pub use resources::runtime_res_test::OwnedRuntimeRes;

use crate::{substate::Substate, unwrap_or_return};
use cfx_statedb::Result as DbResult;

use frame_invoke::{InvokeInfo, SuspendedFrame};

/// The output of a frame's execution, which guides the behavior of the frame
/// stack.
///
/// It either completes the execution of the frame and returns its result or
/// prepares the parameters for the invocation of the next frame in the call
/// stack.
enum FrameStackAction<'a> {
    /// The result of the frame execution.
    Return(FrameResult),

    /// The info for invoking the next frame.
    Invoke(InvokeInfo<'a>),
}

/// The function operates in a loop, starting with the execution of the main
/// frame. Upon each frame's invocation, the caller is pushed onto the call
/// stack, and the callee is executed. After a frame completes execution, the
/// function retrieves the result, pops a frame from the stack, and continues
/// execution with the results from the callee. The loop continues until the
/// call stack is empty, indicating that the main frame has finished executing.
pub fn exec_main_frame<'a>(
    main_frame: FreshFrame<'a>, mut resources: RuntimeRes<'a>,
) -> DbResult<FrameResult> {
    let mut frame_stack: Vec<SuspendedFrame> = Vec::new();
    let mut last_result = main_frame.init_and_exec(&mut resources)?;

    loop {
        last_result = match last_result {
            FrameStackAction::Return(result) => {
                let frame = unwrap_or_return!(frame_stack.pop(), Ok(result));
                frame.resume(result, &mut resources)?
            }
            FrameStackAction::Invoke(InvokeInfo { callee, caller }) => {
                frame_stack.push(caller);
                callee.init_and_exec(&mut resources)?
            }
        }
    }
}

/// Executes an `Executable` within a frame context. Processes and transforms
/// the output into a `FrameStackAction` that is compatible with the frame stack
/// logic. This function also maintains the resources (e.g., maintain the state
/// checkpoints and the callstack metadata) on the frame return.
#[inline]
fn run_executable<'a>(
    executable: Box<dyn 'a + Executable>, mut frame_local: FrameLocal<'a>,
    resources: &mut RuntimeRes<'a>,
) -> DbResult<FrameStackAction<'a>> {
    let vm_context = frame_local.make_vm_context(resources);
    let output = executable.execute(vm_context)?;

    let exec_result = match output {
        ExecutableOutcome::Return(result) => FrameStackAction::Return(
            frame_return::process_return(frame_local, result, resources),
        ),

        ExecutableOutcome::Invoke(params, resumer) => FrameStackAction::Invoke(
            frame_invoke::process_invoke(frame_local, params, resumer),
        ),
    };
    Ok(exec_result)
}

/// A helper function which extract substate from `FrameResult` if applicable
/// and merges it to the parent function.
pub fn accrue_substate(substate: &mut Substate, result: &mut FrameResult) {
    if let Ok(frame_return) = result {
        if let Some(child_substate) = std::mem::take(&mut frame_return.substate)
        {
            substate.accrue(child_substate);
        }
    }
}
