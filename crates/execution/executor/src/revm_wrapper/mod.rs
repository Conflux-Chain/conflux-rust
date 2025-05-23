#![allow(unused)]

use crate::{
    context::{Context, EvmHost},
    stack::{Executable, ExecutableOutcome},
};

use cfx_statedb::Result as DbResult;
use cfx_types::U256;
use cfx_vm_interpreter::FinalizationResult;
use cfx_vm_types::{self as vm, ActionParams};
use revm_context_interface::result::{HaltReason, SuccessReason};
use revm_interpreter::{
    instruction_table, CallInputs, Host, Interpreter, InterpreterAction,
    InterpreterResult, SharedMemory, SuccessOrHalt,
};

use vm::ReturnData;

impl Executable for Interpreter {
    fn execute<'c>(
        mut self: Box<Self>, context: Context<'c>,
    ) -> DbResult<ExecutableOutcome> {
        let mut revm_context = EvmHost::new(context);
        let shared_memory = SharedMemory::new();

        let table = &instruction_table();

        // TODO: inspect shared_memory
        let action = self.run_plain(table, &mut revm_context);

        revm_context.take_db_error()?;

        todo!()
    }
}

fn adapt_action(action: InterpreterAction) -> ExecutableOutcome {
    match action {
        InterpreterAction::NewFrame(frame_input) => todo!(),
        InterpreterAction::Return { result } => todo!(),
        InterpreterAction::None => todo!("What should I do here"),
    }
}

fn adapt_frame_call(inputs: Box<CallInputs>) -> ActionParams { todo!() }

fn adapt_frame_create(inputs: Box<CallInputs>) -> ActionParams { todo!() }

fn adapt_frame_return(
    inputs: InterpreterResult,
) -> vm::Result<FinalizationResult> {
    let gas_left: U256 = inputs.gas.remaining().into();
    let return_data =
        <ReturnData as From<Vec<u8>>>::from(inputs.output.0.into());

    match SuccessOrHalt::from(inputs.result) {
        SuccessOrHalt::Success(SuccessReason::Stop | SuccessReason::Return) => {
            Ok(FinalizationResult {
                gas_left,
                apply_state: true,
                return_data,
            })
        }
        SuccessOrHalt::Success(SuccessReason::SelfDestruct) => todo!(),
        SuccessOrHalt::Success(SuccessReason::EofReturnContract) => todo!(),
        SuccessOrHalt::Revert => Ok(FinalizationResult {
            gas_left,
            apply_state: false,
            return_data,
        }),
        SuccessOrHalt::Halt(halt_reason) => Err(adapt_vm_error(halt_reason)),
        // If FatalExternalError happen, db error should have halted the
        // execution
        SuccessOrHalt::FatalExternalError => unreachable!(),
        // Interpreter internal result should not throw out
        SuccessOrHalt::Internal(_) => unreachable!(),
    }
}

fn adapt_vm_error(halt_reason: HaltReason) -> vm::Error { todo!() }
