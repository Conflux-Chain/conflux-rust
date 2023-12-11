use crate::{
    executive_observer::TracerTrait, stack::CallStackInfo, state::State,
};

/// The global resources and utilities shared across all frames.
pub struct RuntimeRes<'a> {
    /// The ledger state including information such as the balance of each
    /// account.
    pub state: &'a mut State,

    /// Metadata about the frame call stack.
    pub callstack: &'a mut CallStackInfo,

    /// A tool for recording information about the execution as it proceeds.
    /// The data captured by the tracer is not used for consensus-critical
    /// operations.
    pub tracer: &'a mut dyn TracerTrait,
}

#[cfg(test)]
pub mod runtime_res_test {
    use super::RuntimeRes;
    use crate::stack::CallStackInfo;

    use super::State;

    pub struct OwnedRuntimeRes<'a> {
        state: &'a mut State,
        callstack: CallStackInfo,
        tracer: (),
    }

    impl<'a> From<&'a mut State> for OwnedRuntimeRes<'a> {
        fn from(state: &'a mut State) -> Self {
            OwnedRuntimeRes {
                state,
                callstack: CallStackInfo::new(),
                tracer: (),
            }
        }
    }

    impl<'a> OwnedRuntimeRes<'a> {
        pub fn as_res<'b>(&'b mut self) -> RuntimeRes<'b> {
            RuntimeRes {
                state: &mut self.state,
                callstack: &mut self.callstack,
                tracer: &mut self.tracer,
            }
        }
    }
}
