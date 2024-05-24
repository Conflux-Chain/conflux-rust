use super::{
    super::context::OriginInfo, executable::make_executable, run_executable,
    FrameLocal, FrameStackAction, RuntimeRes,
};
use crate::{
    machine::Machine,
    state::State,
    substate::{cleanup_mode, Substate},
};

use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, Space};
use cfx_vm_types::{
    ActionParams, ActionValue, CallType, CreateType, Env, Spec,
};
use primitives::{storage::STORAGE_LAYOUT_REGULAR_V0, StorageLayout};

/// A frame has not yet been executed, with all the necessary information to
/// initiate and carry out the execution of the frame.
pub struct FreshFrame<'a> {
    /// The input parameters for the frame.
    params: ActionParams,

    /// The local data associated with this frame.
    frame_local: FrameLocal<'a>,
}

impl<'a> FreshFrame<'a> {
    pub fn new(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, depth: usize, parent_static_flag: bool,
    ) -> Self {
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
        let origin = OriginInfo::from(&params);

        let frame_local = FrameLocal::new(
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
        FreshFrame {
            frame_local,
            params,
        }
    }

    /// Initializes and executes a frame, along with runtime resources shared
    /// across all frames.
    pub(super) fn init_and_exec(
        self, resources: &mut RuntimeRes<'a>,
    ) -> DbResult<FrameStackAction<'a>> {
        let FreshFrame {
            mut frame_local,
            params,
        } = self;
        let is_create = frame_local.create_address.is_some();

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

        let contract_address = frame_local.origin.recipient().clone();
        resources
            .callstack
            .push(contract_address.with_space(frame_local.space), is_create);

        // Pre execution: transfer value and init contract.
        let spec = &frame_local.spec;
        if is_create {
            transfer_exec_balance_and_init_contract(
                &params,
                spec,
                resources.state,
                // It is a bug in the Parity version.
                &mut frame_local.substate,
                Some(STORAGE_LAYOUT_REGULAR_V0),
            )?
        } else {
            transfer_balance(
                &params,
                spec,
                resources.state,
                &mut frame_local.substate,
            )?
        };

        let executable =
            make_executable(&frame_local, params, resources.tracer);
        run_executable(executable, frame_local, resources)
    }
}

fn transfer_balance(
    params: &ActionParams, spec: &Spec, state: &mut State,
    substate: &mut Substate,
) -> DbResult<()> {
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
) -> DbResult<()> {
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
