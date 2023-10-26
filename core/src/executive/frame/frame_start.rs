use super::super::{
    context::OriginInfo,
    vm_exec::{BuiltinExec, InternalContractExec, NoopExec},
};
use crate::{
    machine::Machine,
    state::{cleanup_mode, State, Substate},
    vm::{
        self, ActionParams, ActionValue, CallType, CreateType, Env, Exec, Spec,
    },
};

use super::{ExecResult, FrameContext, RuntimeRes};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, Space, U256};
use primitives::{storage::STORAGE_LAYOUT_REGULAR_V0, StorageLayout};

pub struct FreshFrame<'a> {
    params: ActionParams,
    context: FrameContext<'a>,
}

impl<'a> FreshFrame<'a> {
    /// Create a new call executive using raw data.
    pub fn new(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, depth: usize, parent_static_flag: bool,
    ) -> Self
    {
        let is_create = params.create_type != CreateType::None;
        let create_address = is_create.then_some(params.code_address);
        trace!(
            "Executive::{:?}(params={:?}) self.env={:?}, parent_static={}",
            if is_create { "create" } else { "call" },
            params,
            env,
            parent_static_flag,
        );

        let static_flag =
            parent_static_flag || params.call_type == CallType::StaticCall;

        let substate = Substate::new();
        // This logic is moved from function exec.
        let origin = OriginInfo::from(&params);

        let context = FrameContext::new(
            params.space,
            env,
            machine,
            spec,
            depth,
            origin,
            substate,
            create_address,
            static_flag,
        );
        FreshFrame { context, params }
    }

    /// Execute the executive. If a sub-call/create action is required, a
    /// resume trap error is returned. The caller is then expected to call
    /// `resume` to continue the execution.
    pub(super) fn init_and_exec(
        self, resources: &mut RuntimeRes<'a>,
    ) -> DbResult<ExecResult<'a>> {
        let FreshFrame {
            mut context,
            params,
        } = self;
        let is_create = context.create_address.is_some();

        // By technical specification and current implementation, the EVM should
        // guarantee the current executive satisfies static_flag.
        check_static_flag(&params, context.static_flag, is_create)
            .expect("check_static_flag should always success because EVM has checked it.");

        // Trace task
        if is_create {
            debug!(
                "CallCreateExecutiveKind::ExecCreate: contract_addr = {:?}",
                params.address
            );
            resources.tracer.record_create(&params);
        } else {
            resources.tracer.record_call(&params);
        }

        // Make checkpoint for this executive, callstack is always maintained
        // with checkpoint.
        resources.state.checkpoint();

        let contract_address = context.origin.recipient().clone();
        resources
            .callstack
            .push(contract_address.with_space(context.space), is_create);

        // Pre execution: transfer value and init contract.
        let spec = &context.spec;
        if is_create {
            transfer_exec_balance_and_init_contract(
                &params,
                spec,
                resources.state,
                // It is a bug in the Parity version.
                &mut context.substate,
                Some(STORAGE_LAYOUT_REGULAR_V0),
            )?
        } else {
            transfer_exec_balance(
                &params,
                spec,
                resources.state,
                &mut context.substate,
            )?
        };

        let exec = make_executable(&context, params);
        context.run(exec, resources)
    }
}

fn make_executable<'a>(
    context: &FrameContext<'a>, params: ActionParams,
) -> Box<dyn 'a + Exec> {
    let is_create = context.create_address.is_some();
    let code_address = params.code_address.with_space(params.space);
    let internal_contract_map = context.machine.internal_contracts();

    // Builtin is located for both Conflux Space and EVM Space.
    if let Some(builtin) =
        context.machine.builtin(&code_address, context.env.number)
    {
        trace!("CallBuiltin");
        return Box::new(BuiltinExec { builtin, params });
    }

    if let Some(internal) =
        internal_contract_map.contract(&code_address, &context.spec)
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
        let factory = context.machine.vm_factory_ref();
        factory.create(params, context.spec, context.depth)
    } else {
        trace!("Transfer");
        Box::new(NoopExec { gas: params.gas })
    }
}

fn check_static_flag(
    params: &ActionParams, static_flag: bool, is_create: bool,
) -> vm::Result<()> {
    // This is the function check whether contract creation or value
    // transferring happens in static context at callee executive. However,
    // it is meaningless because the caller has checked this constraint
    // before message call. Currently, if we panic when this
    // function returns error, all the tests can still pass.
    // So we no longer check the logic for reentrancy here,
    // TODO: and later we will check if we can safely remove this function.
    if is_create {
        if static_flag {
            return Err(vm::Error::MutableCallInStaticContext);
        }
    } else {
        if static_flag
            && (params.call_type == CallType::StaticCall
                || params.call_type == CallType::Call)
            && params.value.value() > U256::zero()
        {
            return Err(vm::Error::MutableCallInStaticContext);
        }
    }

    Ok(())
}

fn transfer_exec_balance(
    params: &ActionParams, spec: &Spec, state: &mut State,
    substate: &mut Substate,
) -> DbResult<()>
{
    let sender = AddressWithSpace {
        address: params.sender,
        space: params.space,
    };
    let receiver = AddressWithSpace {
        address: params.address,
        space: params.space,
    };
    if let ActionValue::Transfer(val) = params.value {
        state.transfer_balance(
            &sender,
            &receiver,
            &val,
            cleanup_mode(substate, &spec),
        )?;
    }

    Ok(())
}

fn transfer_exec_balance_and_init_contract(
    params: &ActionParams, spec: &Spec, state: &mut State,
    substate: &mut Substate, storage_layout: Option<StorageLayout>,
) -> DbResult<()>
{
    let sender = AddressWithSpace {
        address: params.sender,
        space: params.space,
    };
    let receiver = AddressWithSpace {
        address: params.address,
        space: params.space,
    };
    if let ActionValue::Transfer(val) = params.value {
        // It is possible to first send money to a pre-calculated
        // contract address.
        let prev_balance = state.balance(&receiver)?;
        state.sub_balance(&sender, &val, &mut cleanup_mode(substate, &spec))?;
        let admin = if params.space == Space::Native {
            params.original_sender
        } else {
            Address::zero()
        };
        state.new_contract_with_admin(
            &receiver,
            &admin,
            val.saturating_add(prev_balance),
            storage_layout,
            spec.cip107,
        )?;
    } else {
        // In contract creation, the `params.value` should never be
        // `Apparent`.
        unreachable!();
    }

    Ok(())
}
