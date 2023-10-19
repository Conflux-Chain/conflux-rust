use crate::vm::{
    ContractCreateResult, ExecTrapError, MessageCallResult, ResumeCall,
    ResumeCreate, TrapError,
};

use cfx_statedb::Result as DbResult;
use cfx_types::AddressWithSpace;

use super::{
    accrue_substate, ExecResult, FrameContext, FrameResult, FrameReturn,
    FreshFrame, RuntimeRes,
};

pub(super) struct InvokeInfo<'a> {
    pub callee: FreshFrame<'a>,
    pub caller: SuspendedFrame<'a>,
}

pub(super) struct SuspendedFrame<'a> {
    resumer: FrameResumer,
    context: FrameContext<'a>,
}

enum FrameResumer {
    ResumeFromCall(Box<dyn ResumeCall>),
    ResumeFromCreate(Box<dyn ResumeCreate>),
}

/// If the executive triggers a sub-call during execution, this function
/// outputs a trap error with sub-call parameters and return point.
pub(super) fn process_invoke<'a>(
    context: FrameContext<'a>, trap_err: ExecTrapError,
) -> InvokeInfo<'a> {
    let (params, resumer) = match trap_err {
        TrapError::Call(subparams, resume) => {
            (subparams, FrameResumer::ResumeFromCall(resume))
        }
        TrapError::Create(subparams, resume) => {
            (subparams, FrameResumer::ResumeFromCreate(resume))
        }
    };
    let callee = FreshFrame::new(
        params,
        context.env,
        context.machine,
        context.spec,
        context.depth + 1,
        context.static_flag,
    );
    let caller = SuspendedFrame { context, resumer };
    InvokeInfo { callee, caller }
}

impl<'a> SuspendedFrame<'a> {
    pub fn resume(
        self, mut result: FrameResult, resources: &mut RuntimeRes<'a>,
    ) -> DbResult<ExecResult<'a>> {
        let SuspendedFrame {
            mut context,
            resumer,
        } = self;
        accrue_substate(&mut context.substate, &mut result);

        // Process resume tasks, which is defined in Instruction Set
        // Specification of tech-specification.
        let exec = match resumer {
            FrameResumer::ResumeFromCreate(resume) => {
                let result = into_contract_create_result(result);
                resume.resume_create(result)
            }
            FrameResumer::ResumeFromCall(resume) => {
                let result = into_message_call_result(result);
                resume.resume_call(result)
            }
        };

        // Post execution.
        context.run(exec, resources)
    }
}

/// Convert a finalization result into a VM message call result.
fn into_message_call_result(result: FrameResult) -> MessageCallResult {
    match result {
        Ok(FrameReturn {
            gas_left,
            return_data,
            apply_state: true,
            ..
        }) => MessageCallResult::Success(gas_left, return_data),
        Ok(FrameReturn {
            gas_left,
            return_data,
            apply_state: false,
            ..
        }) => MessageCallResult::Reverted(gas_left, return_data),
        Err(err) => MessageCallResult::Failed(err),
    }
}

/// Convert a finalization result into a VM contract create result.
fn into_contract_create_result(result: FrameResult) -> ContractCreateResult {
    match result {
        Ok(FrameReturn {
            space,
            gas_left,
            apply_state: true,
            create_address,
            ..
        }) => {
            // Move the change of contracts_created in substate to
            // process_return.
            let address = create_address
                .expect("ExecutiveResult for Create executive should be some.");
            let address = AddressWithSpace { address, space };
            ContractCreateResult::Created(address, gas_left)
        }
        Ok(FrameReturn {
            gas_left,
            apply_state: false,
            return_data,
            ..
        }) => ContractCreateResult::Reverted(gas_left, return_data),
        Err(err) => ContractCreateResult::Failed(err),
    }
}
