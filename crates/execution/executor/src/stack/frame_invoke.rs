use cfx_vm_types::ActionParams;

use cfx_statedb::Result as DbResult;

use super::{
    accrue_substate, run_executable, FrameLocal, FrameResult, FrameStackAction,
    FreshFrame, Resumable, RuntimeRes,
};

/// Information for invoking the next frame.
pub(super) struct InvokeInfo<'a> {
    /// The next frame to be executed.
    pub callee: FreshFrame<'a>,

    /// The current frame which has been suspended in anticipation of the
    /// `callee`'s execution.
    pub caller: SuspendedFrame<'a>,
}

/// A frame that has been suspended in anticipation of the subcall result.
pub(super) struct SuspendedFrame<'a> {
    /// For handling the return from the callee frame and creating the
    /// executable for the rest execution.
    resumer: Box<dyn Resumable>,

    /// The local data associated with this frame.
    frame_local: FrameLocal<'a>,
}

/// With the local data of a frame, converts the VM sub-call return value
/// `ExecTrapError` into `InvokeInfo` for frames.
pub(super) fn process_invoke<'a>(
    frame_local: FrameLocal<'a>, params: ActionParams,
    resumer: Box<dyn Resumable>,
) -> InvokeInfo<'a> {
    let callee = FreshFrame::new(
        params,
        frame_local.env,
        frame_local.machine,
        frame_local.spec,
        frame_local.depth + 1,
        frame_local.static_flag,
    );
    let caller = SuspendedFrame {
        frame_local,
        resumer,
    };
    InvokeInfo { callee, caller }
}

impl<'a> SuspendedFrame<'a> {
    /// Continues the execution of the current frame using the result from a
    /// subcall result, along with runtime resources shared across all frames.
    pub fn resume(
        self, mut result: FrameResult, resources: &mut RuntimeRes<'a>,
    ) -> DbResult<FrameStackAction<'a>> {
        let SuspendedFrame {
            mut frame_local,
            resumer,
        } = self;
        accrue_substate(&mut frame_local.substate, &mut result);

        let executable = resumer.resume(result);
        run_executable(executable, frame_local, resources)
    }
}
