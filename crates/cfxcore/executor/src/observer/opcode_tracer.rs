use cfx_types::{Address, H256, U256};
use cfx_vm_types::InterpreterInfo;

use impl_tools::autoimpl;
use impl_trait_for_tuples::impl_for_tuples;

#[impl_for_tuples(3)]
#[autoimpl(for<T: trait + ?Sized> &mut T)]
pub trait OpcodeTracer {
    fn do_trace_opcode(&self, _enabled: &mut bool) {}

    /// Called before the interpreter is initialized.
    #[inline]
    fn initialize_interp(&mut self, gas_limit: U256) { let _ = gas_limit; }

    /// Called on each step of the interpreter.
    ///
    /// Information about the current execution, including the memory, stack and
    /// more is available on `interp` (see [Interpreter]).
    fn step(&mut self, interp: &dyn InterpreterInfo) { let _ = interp; }

    /// Called after `step` when the instruction has been executed.
    fn step_end(&mut self, interp: &dyn InterpreterInfo) { let _ = interp; }

    /// Called when a log is emitted.
    #[inline]
    fn log(&mut self, address: &Address, topics: &Vec<H256>, data: &[u8]) {
        let _ = address;
        let _ = topics;
        let _ = data;
    }

    /// Called when a contract has been self-destructed with funds transferred
    /// to target.
    #[inline]
    fn selfdestruct(
        &mut self, contract: &Address, target: &Address, value: U256,
    ) {
        let _ = contract;
        let _ = target;
        let _ = value;
    }
}
