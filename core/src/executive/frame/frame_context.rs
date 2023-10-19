use super::{
    super::context::{Context, OriginInfo},
    frame_invoke, frame_return, ExecResult, RuntimeRes,
};
use crate::{
    machine::Machine,
    state::Substate,
    vm::{Env, Exec, Spec, TrapResult},
};

use cfx_statedb::Result as DbResult;
use cfx_types::{Address, Space};

/// The `FrameContext` only contains the parameters can be owned by an
/// frame. It will be never changed by other frames.
pub struct FrameContext<'a> {
    pub space: Space,
    pub env: &'a Env,
    pub depth: usize,
    pub create_address: Option<Address>,
    pub origin: OriginInfo,
    pub substate: Substate,
    pub machine: &'a Machine,
    pub spec: &'a Spec,
    pub static_flag: bool,
}

impl<'a> FrameContext<'a> {
    pub fn new(
        space: Space, env: &'a Env, machine: &'a Machine, spec: &'a Spec,
        depth: usize, origin: OriginInfo, substate: Substate,
        create_address: Option<Address>, static_flag: bool,
    ) -> Self
    {
        FrameContext {
            space,
            env,
            depth,
            origin,
            substate,
            machine,
            spec,
            create_address,
            static_flag,
        }
    }

    /// The `LocalContext` only contains the parameters can be owned by an
    /// executive. For the parameters shared between executives (like `&mut
    /// State`), the executive should activate `LocalContext` by passing in
    /// these parameters.
    pub fn make_vm_context<'b, 'c>(
        &'b mut self, resources: &'b mut RuntimeRes<'c>,
    ) -> Context<'b> {
        Context::new(self, resources)
    }

    #[inline]
    pub(super) fn run(
        mut self, exec: Box<dyn 'a + Exec>, resources: &mut RuntimeRes<'a>,
    ) -> DbResult<ExecResult<'a>> {
        let mut vm_context = self.make_vm_context(resources);
        let output = exec.exec(&mut vm_context);

        // Convert the `ExecTrapResult` (result of evm) to `ExecutiveTrapResult`
        // (result of frame).
        let exec_result = match output {
            TrapResult::Return(result) => ExecResult::Return(
                frame_return::process_return(self, result, resources)?,
            ),

            TrapResult::SubCallCreate(trap_err) => {
                ExecResult::Invoke(frame_invoke::process_invoke(self, trap_err))
            }
        };
        Ok(exec_result)
    }
}
