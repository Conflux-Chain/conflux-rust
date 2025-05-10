use super::TrapKind;
use cfx_types::U256;

#[derive(Clone)]
pub enum InstructionResult<Gas> {
    Ok,
    UnusedGas(Gas),
    JumpToPosition(U256),
    JumpToSubroutine(U256),
    ReturnFromSubroutine(usize),
    StopExecutionNeedsReturn {
        /// Gas left.
        gas: Gas,
        /// Return data offset.
        init_off: U256,
        /// Return data size.
        init_size: U256,
        /// Apply or revert state changes.
        apply: bool,
    },
    StopExecution,
    Trap(TrapKind),
}
