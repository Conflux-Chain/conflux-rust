use super::{
    super::context::{Context, OriginInfo},
    RuntimeRes,
};
use crate::{machine::Machine, substate::Substate};

use cfx_types::{Address, Space};
use cfx_vm_types::{Env, Spec};

/// `FrameLocal` represents the local data associated with a specific call frame
/// during the execution of the Ethereum Virtual Machine (EVM). This data is
/// local to the frame and is not visible to other frames in the execution
/// stack.
pub struct FrameLocal<'a> {
    /// The space the current frame belongs.
    pub space: Space,

    /// A reference to environmental information relevant to the
    /// current execution, such as the block number and block author.
    pub env: &'a Env,

    /// The depth of the current frame in the call stack.
    pub depth: usize,

    /// The address of the newly deployed contract, if the current frame is for
    /// contract creation.
    pub create_address: Option<Address>,

    /// The caller information for the current frame, including the caller, the
    /// original sender, etc.
    pub origin: OriginInfo,

    /// Collects changes produced during execution for post-execution logic
    /// such as collecting storage fees, and generating receipts.
    pub substate: Substate,

    /// All the necessities for executing EVM bytecode.
    pub machine: &'a Machine,

    /// Activated hardfork features and the parameters that may be modified in
    /// hardfork
    pub spec: &'a Spec,

    /// Enforce the static context of a call, as defined by EIP-214
    /// (STATICCALL), ensuring that certain operations do not alter the
    /// state.
    pub static_flag: bool,
}

impl<'a> FrameLocal<'a> {
    pub fn new(
        space: Space, env: &'a Env, machine: &'a Machine, spec: &'a Spec,
        depth: usize, origin: OriginInfo, substate: Substate,
        create_address: Option<Address>, static_flag: bool,
    ) -> Self {
        FrameLocal {
            space,
            env,
            depth,
            origin,
            substate,
            machine,
            spec,
            create_address,
            static_flag,
        }
    }

    /// Creates a `Context` for the current frame, which includes two distinct
    /// parts:
    /// 1. Local frame information - Specific to the current frame and not
    /// visible to others.
    /// 2. Runtime resources - Contains global information like the ledger
    /// state, accessible across frames.
    pub fn make_vm_context<'b, 'c>(
        &'b mut self, resources: &'b mut RuntimeRes<'c>,
    ) -> Context<'b> {
        Context::new(self, resources)
    }
}
