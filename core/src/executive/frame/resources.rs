use crate::{
    observer::VmObserve,
    state::{CallStackInfo, State},
};

pub struct RuntimeRes<'a> {
    pub state: &'a mut State,
    pub callstack: &'a mut CallStackInfo,
    pub tracer: &'a mut dyn VmObserve,
}

#[cfg(test)]
pub mod runtime_res_test {
    use super::RuntimeRes;
    use crate::state::CallStackInfo;

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
