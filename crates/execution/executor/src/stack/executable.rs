use super::{FrameLocal, Resumable};
use crate::{
    builtin::BuiltinExec, context::Context, executive_observer::TracerTrait,
    internal_contract::InternalContractExec,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{AddressSpaceUtil, U256};
use cfx_vm_interpreter::{FinalizationResult, Finalize};
use cfx_vm_types::{
    self as vm, separate_out_db_error, ActionParams, Exec, GasLeft, ReturnData,
    TrapError, TrapResult,
};

/// `Executable` is a trait representing an object that can be executed within a
/// frame.
///
/// There are generally two ways to create an `Executable`:
/// 1. In a new frame, an `Executable` is created by the `make_executable`
/// function, which uses the frame's input parameters    (`ActionParams`) and
/// local information (`FrameLocal`) to determine the appropriate executable
/// action.
/// 2. After the completion of a frame's execution, an `Executable` may
/// be created by the its caller frame's `Resumer` (implementing the `Resumable`
/// trait) based on the execution results.
pub trait Executable: Send {
    fn execute(
        self: Box<Self>, context: Context,
    ) -> DbResult<ExecutableOutcome>;
}

/// The possible outcomes of an `Executable`'s execution within a frame. It
/// encapsulates either the final result of the frame's execution or the
/// parameters needed for invoking the next level frame.

pub enum ExecutableOutcome {
    /// The result of the frame's execution.
    Return(vm::Result<FinalizationResult>),
    /// The parameters for invoking the next frame and a resumable object for
    /// the current frame.
    Invoke(ActionParams, Box<dyn Resumable>),
}
use ExecutableOutcome::*;

/// Constructs an executable object from a frame's local information and input
/// parameters. Possible executables include built-in functions, internal
/// contracts, simple transfers, or the execution of EVM bytecode.
pub fn make_executable<'a>(
    frame_local: &FrameLocal<'a>, params: ActionParams,
    tracer: &mut dyn TracerTrait,
) -> Box<dyn 'a + Executable> {
    let is_create = frame_local.create_address.is_some();
    let code_address = params.code_address.with_space(params.space);
    let internal_contract_map = frame_local.machine.internal_contracts();

    // Builtin is located for both Conflux Space and EVM Space.
    if let Some(builtin) = frame_local
        .machine
        .builtin(&code_address, frame_local.env.number)
    {
        trace!("CallBuiltin");
        return Box::new(BuiltinExec { builtin, params });
    }

    if let Some(internal) =
        internal_contract_map.contract(&code_address, &frame_local.spec)
    {
        trace!(
            "CallInternalContract: address={:?} data={:?}",
            code_address,
            params.data
        );
        return Box::new(InternalContractExec { internal, params });
    }

    if is_create || params.code.is_some() {
        trace!("CallCreate");

        // call the initialize_interp hook to log gas_limit
        tracer.initialize_interp(params.gas.clone());

        let factory = frame_local.machine.vm_factory_ref();
        Box::new(factory.create(params, frame_local.spec, frame_local.depth))
    } else {
        trace!("Transfer");
        Box::new(NoopExec { gas: params.gas })
    }
}

impl Executable for Box<dyn Exec> {
    fn execute(
        self: Box<Self>, mut context: Context,
    ) -> DbResult<ExecutableOutcome> {
        Ok(match self.exec(&mut context) {
            TrapResult::Return(result) => {
                let result = separate_out_db_error(result)?;
                // Backward compatible for a strange behaviour. If the contract
                // creation process do not generate any code and the contract is
                // not inited, it should also be put in the contract creation
                // receipt.
                if matches!(result, Ok(GasLeft::Known(_))) {
                    context.insert_create_address_to_substate();
                }
                Return(result.finalize(context))
            }
            TrapResult::SubCallCreate(TrapError::Call(params, resume)) => {
                Invoke(params, Box::new(resume))
            }
            TrapResult::SubCallCreate(TrapError::Create(params, resume)) => {
                Invoke(params, Box::new(resume))
            }
        })
    }
}

pub struct NoopExec {
    pub gas: U256,
}

impl Executable for NoopExec {
    fn execute(self: Box<Self>, _: Context) -> DbResult<ExecutableOutcome> {
        let result = FinalizationResult {
            gas_left: self.gas,
            apply_state: true,
            return_data: ReturnData::empty(),
        };
        Ok(Return(Ok(result)))
    }
}
