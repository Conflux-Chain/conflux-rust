use crate::{
    state::CallStackInfo,
    vm::{self, ActionParams, Env, Spec},
};
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_types::{H256, U256};

/// The internal contracts need to access the context parameter directly, e.g.,
/// `foo(env, spec)`. But `foo(context.env(), context.spec())` will incur
/// lifetime issue. The `InternalRefContext` contains the parameters required by
/// the internal contracts.
pub struct InternalRefContext<'a> {
    pub env: &'a Env,
    pub spec: &'a Spec,
    pub callstack: &'a mut CallStackInfo,
    pub state: &'a mut dyn StateOpsTrait,
    pub substate: &'a mut dyn SubstateTrait,
    pub static_flag: bool,
}

// The following implementation is copied from `executive/context.rs`. I know
// it is not a good idea to implement the context interface again. We put it
// here temporarily.
impl<'a> InternalRefContext<'a> {
    pub fn log(
        &mut self, param: &ActionParams, topics: Vec<H256>, data: Vec<u8>,
    ) -> vm::Result<()> {
        use primitives::log_entry::LogEntry;

        if self.static_flag || self.callstack.in_reentrancy() {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let address = param.address;
        self.substate.logs_mut().push(LogEntry {
            address,
            topics,
            data,
        });

        Ok(())
    }

    pub fn set_storage(
        &mut self, param: &ActionParams, key: Vec<u8>, value: U256,
    ) -> vm::Result<()> {
        self.substate
            .set_storage(
                self.state,
                &param.address,
                key,
                value,
                param.storage_owner,
            )
            .map_err(|e| e.into())
    }

    pub fn storage_at(
        &mut self, param: &ActionParams, key: &[u8],
    ) -> vm::Result<U256> {
        self.substate
            .storage_at(self.state, &param.address, key)
            .map_err(|e| e.into())
    }
}
