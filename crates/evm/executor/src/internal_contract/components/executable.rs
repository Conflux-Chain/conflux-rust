use super::{InternalContractTrait, InternalTrapResult};
use cfx_statedb::Result as DbResult;
use cfx_vm_interpreter::Finalize;
use cfx_vm_types::{
    separate_out_db_error, ActionParams, CallType, Error as VmError,
};
use InternalTrapResult::*;

use crate::stack::{Context, Executable, ExecutableOutcome};

pub struct InternalContractExec<'a> {
    pub internal: &'a Box<dyn InternalContractTrait>,
    pub params: ActionParams,
}

impl<'a> Executable for InternalContractExec<'a> {
    fn execute(
        self: Box<Self>, mut context: Context,
    ) -> DbResult<ExecutableOutcome> {
        let result = if self.params.call_type != CallType::Call
            && self.params.call_type != CallType::StaticCall
        {
            ExecutableOutcome::Return(Err(VmError::InternalContract(
                "Incorrect call type.".into(),
            )))
        } else {
            match self
                .internal
                .execute(&self.params, &mut context.internal_ref())
            {
                Return(result) => {
                    let result = separate_out_db_error(result)?;
                    let finalized_result = result.finalize(context);
                    debug!("Internal Call Result: {:?}", finalized_result);
                    ExecutableOutcome::Return(finalized_result)
                }
                Invoke(p, r) => {
                    debug!("Internal Call Has a sub-call/create");
                    ExecutableOutcome::Invoke(p, r)
                }
            }
        };

        Ok(result)
    }
}
