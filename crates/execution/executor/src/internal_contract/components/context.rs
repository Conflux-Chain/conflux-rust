use crate::{
    executive_observer::TracerTrait, stack::CallStackInfo, state::State,
    substate::Substate,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, H256, U256,
};
use cfx_vm_types::{self as vm, ActionParams, Env, Spec};

/// The internal contracts need to access the context parameter directly, e.g.,
/// `foo(env, spec)`. But `foo(context.env(), context.spec())` will incur
/// lifetime issue. The `InternalRefContext` contains the parameters required by
/// the internal contracts.
pub struct InternalRefContext<'a> {
    pub env: &'a Env,
    pub spec: &'a Spec,
    pub callstack: &'a mut CallStackInfo,
    pub state: &'a mut State,
    pub substate: &'a mut Substate,
    pub tracer: &'a mut dyn TracerTrait,
    pub static_flag: bool,
    pub depth: usize,
}

// The following implementation is copied from `executive/context.rs`. I know
// it is not a good idea to implement the context interface again. We put it
// here temporarily.
impl<'a> InternalRefContext<'a> {
    pub fn log(
        &mut self, params: &ActionParams, spec: &Spec, topics: Vec<H256>,
        data: Vec<u8>,
    ) -> vm::Result<()> {
        use primitives::log_entry::LogEntry;

        if self.static_flag || self.callstack.in_reentrancy(spec) {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let address = params.address;
        self.substate.logs.push(LogEntry {
            address,
            topics,
            data,
            space: params.space,
        });

        Ok(())
    }

    pub fn set_storage(
        &mut self, params: &ActionParams, key: Vec<u8>, value: U256,
    ) -> vm::Result<()> {
        let receiver = params.address.with_space(params.space);
        self.state
            .set_storage(
                &receiver,
                key,
                value,
                params.storage_owner,
                self.substate,
            )
            .map_err(|e| e.into())
    }

    pub fn storage_at(
        &mut self, params: &ActionParams, key: &[u8],
    ) -> DbResult<U256> {
        let receiver = params.address.with_space(params.space);
        self.state.storage_at(&receiver, key).map_err(|e| e.into())
    }

    pub fn is_contract_address(&self, address: &Address) -> vm::Result<bool> {
        Ok(address.is_contract_address())
    }
}
