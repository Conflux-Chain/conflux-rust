use super::{Executable, FrameResult, FrameReturn};
use cfx_vm_types::{
    ContractCreateResult, MessageCallResult, ResumeCall, ResumeCreate,
};

/// `Resumable` is a trait representing objects for resuming the execution of a
/// frame, which is suspended due to the invocation of another frame. The caller
/// frame is resumed when the callee frame returns.
pub trait Resumable: Send {
    fn resume(self: Box<Self>, result: FrameResult) -> Box<dyn Executable>;
}

impl Resumable for Box<dyn ResumeCall> {
    fn resume(self: Box<Self>, result: FrameResult) -> Box<dyn Executable> {
        let result = into_message_call_result(result);
        Box::new(self.resume_call(result))
    }
}

impl Resumable for Box<dyn ResumeCreate> {
    fn resume(self: Box<Self>, result: FrameResult) -> Box<dyn Executable> {
        let result = into_contract_create_result(result);
        Box::new(self.resume_create(result))
    }
}

/// Converts the execution result of a frame into the format expected by the VM.
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

/// Converts the execution result of a frame into the format expected by the VM.
fn into_contract_create_result(result: FrameResult) -> ContractCreateResult {
    match result {
        Ok(FrameReturn {
            gas_left,
            apply_state: true,
            create_address,
            ..
        }) => {
            // Move the change of contracts_created in substate to
            // process_return.
            let address = create_address
                .expect("ExecutiveResult for Create executive should be some.");
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
