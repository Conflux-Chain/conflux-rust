use super::{
    contract_address,
    executed::make_ext_result,
    fresh_executive::CostInfo,
    transact_options::{ChargeCollateral, TransactSettings},
    Executed, ExecutionError, ExecutiveContext,
};

use crate::{
    executive::ExecutionOutcome,
    executive_observer::{AddressPocket, ExecutiveObserver, TracerTrait},
    stack::{
        accrue_substate, exec_main_frame, CallStackInfo, FrameResult,
        FrameReturn, FreshFrame, RuntimeRes,
    },
    state::settle_collateral_for_all,
    substate::{cleanup_mode, Substate},
};
use cfx_parameters::staking::code_collateral_units;
use cfx_vm_types::{
    self as vm, ActionParams, ActionValue, CallType, CreateContractAddress,
    CreateType,
};

use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, Space, U256, U512};
use primitives::{transaction::Action, SignedTransaction};
use std::{convert::TryInto, sync::Arc};

pub(super) struct PreCheckedExecutive<'a, O: ExecutiveObserver> {
    pub context: ExecutiveContext<'a>,
    pub tx: &'a SignedTransaction,
    pub observer: O,
    pub settings: TransactSettings,
    pub cost: CostInfo,
    pub substate: Substate,
}

impl<'a, O: ExecutiveObserver> PreCheckedExecutive<'a, O> {
    pub(super) fn execute_transaction(mut self) -> DbResult<ExecutionOutcome> {
        self.inc_sender_nonce()?;

        let (actual_gas_cost, insufficient_sender_balance) =
            self.charge_gas()?;

        if insufficient_sender_balance {
            if self.tx.space() == Space::Ethereum {
                self.context.state.sub_total_evm_tokens(actual_gas_cost);
            }
            return self.finalize_on_insufficient_balance(actual_gas_cost);
        }

        let params = self.make_action_params()?;
        if self.tx.space() == Space::Native
            && !self.check_create_address(&params)?
        {
            return self.finalize_on_conflict_address(params.address);
        }

        let result = self.exec_vm(params.clone())?;

        let refund_info = self.compute_refunded_gas(&result);
        self.refund_gas(&params, refund_info.refund_value)?;

        if self.tx.space() == Space::Ethereum {
            self.context
                .state
                .sub_total_evm_tokens(refund_info.fees_value);
        }

        // perform suicides
        self.kill_process()?;

        self.finalize_on_executed(result, refund_info)
    }
}

impl<'a, O: ExecutiveObserver> PreCheckedExecutive<'a, O> {
    fn inc_sender_nonce(&mut self) -> DbResult<()> {
        self.context.state.inc_nonce(&self.tx.sender())
    }

    fn charge_gas<'t>(&mut self) -> DbResult<(U256, bool)> {
        let sender = self.tx.sender();
        let spec = self.context.spec;
        let substate = &mut self.substate;
        let cleanup_mode = &mut cleanup_mode(substate, spec);
        let mut tracer = self.observer.as_tracer();

        let CostInfo {
            sender_balance,
            gas_cost,
            sender_intended_cost,
            gas_sponsored,
            ..
        } = self.cost;

        // Here, we only discuss the case `sender_balance <
        // sender_intended_cost` The case `sender_intended_cost <=
        // sender_balance < sender_cost` has been handled before nonce bumping.
        let insufficient_sender_balance = sender_balance < sender_intended_cost;

        let actual_gas_cost: U256 = if insufficient_sender_balance {
            // Sender is responsible for the insufficient balance.
            // Sub tx fee if not enough cash, and substitute all remaining
            // balance if balance is not enough to pay the tx fee
            U512::min(gas_cost, sender_balance)
        } else {
            gas_cost
        }
        .try_into()
        .unwrap();

        if !gas_sponsored || insufficient_sender_balance {
            tracer.trace_internal_transfer(
                AddressPocket::Balance(self.tx.sender()),
                AddressPocket::GasPayment,
                actual_gas_cost,
            );
            self.context.state.sub_balance(
                &sender,
                &actual_gas_cost,
                cleanup_mode,
            )?;
        } else {
            let code_address = match self.tx.action() {
                Action::Create => Address::zero(),
                Action::Call(ref address) => *address,
            };
            tracer.trace_internal_transfer(
                AddressPocket::SponsorBalanceForGas(code_address),
                AddressPocket::GasPayment,
                actual_gas_cost,
            );

            self.context
                .state
                .sub_sponsor_balance_for_gas(&code_address, &actual_gas_cost)?;
        }

        // Don't subtract total_evm_balance here. It is maintained properly in
        // `finalize`.

        Ok((actual_gas_cost, insufficient_sender_balance))
    }

    fn make_action_params(&self) -> DbResult<ActionParams> {
        let tx = self.tx;
        let cost = &self.cost;
        let env = self.context.env;
        let state = &*self.context.state;
        let sender = tx.sender();
        let nonce = tx.nonce();

        let init_gas = tx.gas() - cost.base_gas;

        match tx.action() {
            Action::Create => {
                let address_scheme = match tx.space() {
                    Space::Native => {
                        CreateContractAddress::FromSenderNonceAndCodeHash
                    }
                    Space::Ethereum => CreateContractAddress::FromSenderNonce,
                };
                let (new_address, code_hash) = contract_address(
                    address_scheme,
                    env.number.into(),
                    &sender,
                    &nonce,
                    &tx.data(),
                );

                Ok(ActionParams {
                    space: sender.space,
                    code_address: new_address.address,
                    code_hash,
                    address: new_address.address,
                    sender: sender.address,
                    original_sender: sender.address,
                    storage_owner: sender.address,
                    gas: init_gas,
                    gas_price: cost.gas_price,
                    value: ActionValue::Transfer(*tx.value()),
                    code: Some(Arc::new(tx.data().clone())),
                    data: None,
                    call_type: CallType::None,
                    create_type: CreateType::CREATE,
                    params_type: vm::ParamsType::Embedded,
                })
            }
            Action::Call(ref receipient) => {
                let receipient = receipient.with_space(sender.space);
                let storage_owner = if cost.storage_sponsored {
                    receipient.address
                } else {
                    sender.address
                };
                Ok(ActionParams {
                    space: sender.space,
                    code_address: receipient.address,
                    address: receipient.address,
                    sender: sender.address,
                    original_sender: sender.address,
                    storage_owner,
                    gas: init_gas,
                    gas_price: cost.gas_price,
                    value: ActionValue::Transfer(*tx.value()),
                    code: state.code(&receipient)?,
                    code_hash: state.code_hash(&receipient)?,
                    data: Some(tx.data().clone()),
                    call_type: CallType::Call,
                    create_type: CreateType::None,
                    params_type: vm::ParamsType::Separate,
                })
            }
        }
    }

    /// For a contract address already with code, we do not allow overlap the
    /// address. This should generally not happen. Unless we enable account dust
    /// in future. We add this check just in case it helps in future.
    fn check_create_address(&self, params: &ActionParams) -> DbResult<bool> {
        if params.create_type != CreateType::CREATE {
            return Ok(true);
        }

        if params.space != Space::Native {
            return Ok(true);
        }

        let new_address = params.address.with_native_space();
        self.context
            .state
            .is_contract_with_code(&new_address)
            .map(|x| !x)
    }
}

pub(super) fn exec_vm<'a>(
    context: &mut ExecutiveContext<'a>, params: ActionParams,
    tracer: &mut dyn TracerTrait,
) -> DbResult<FrameResult> {
    let main_frame = FreshFrame::new(
        params,
        context.env,
        context.machine,
        context.spec,
        /* depth */ 0,
        /* static_flag */ false,
    );
    let mut callstack = CallStackInfo::new();
    let resources = RuntimeRes {
        state: &mut context.state,
        callstack: &mut callstack,
        tracer: &mut *tracer,
    };
    exec_main_frame(main_frame, resources)
}

impl<'a, O: ExecutiveObserver> PreCheckedExecutive<'a, O> {
    fn exec_vm(&mut self, params: ActionParams) -> DbResult<ExecutiveResult> {
        // No matter who pays the collateral, we only focuses on the storage
        // limit of sender.
        let total_storage_limit =
            self.context.state.collateral_for_storage(&params.sender)?
                + self.cost.storage_cost;

        // Initialize the checkpoint for transaction execution. This checkpoint
        // can be reverted by "not enough balance for storage".
        self.context.state.checkpoint();
        self.observer.as_tracer().trace_checkpoint();

        let res = exec_vm(
            &mut self.context,
            params.clone(),
            &mut *self.observer.as_tracer(),
        )?;
        let mut res = self.settle_collateral(res, total_storage_limit)?;

        // Charge collateral and process the checkpoint.
        match &res {
            Ok(_) => {
                self.observer.as_tracer().trace_checkpoint_discard();
                self.context.state.discard_checkpoint();
            }
            Err(_) => {
                self.observer.as_tracer().trace_checkpoint_revert();
                self.context.state.revert_to_checkpoint();
            }
        };

        accrue_substate(&mut self.substate, &mut res);
        let res = res.map(|r| ExecutiveReturn {
            gas_left: r.gas_left,
            apply_state: r.apply_state,
            return_data: r.return_data.to_vec(),
        });

        Ok(res)
    }

    fn settle_collateral(
        &mut self, mut res: FrameResult, total_storage_limit: U256,
    ) -> DbResult<FrameResult> {
        let context = &mut self.context;
        let state = &mut *context.state;
        if let Ok(FrameReturn {
            apply_state: true,
            substate: Some(ref substate),
            ..
        }) = res
        {
            let dry_run = !matches!(
                self.settings.charge_collateral,
                ChargeCollateral::Normal
            );

            // For a ethereum space tx, this function has no op.
            let mut collateral_check_result = settle_collateral_for_all(
                state,
                substate,
                &mut *self.observer.as_tracer(),
                &context.spec,
                dry_run,
            )?;

            if collateral_check_result.is_ok() {
                let sender = self.tx.sender();
                collateral_check_result = state.check_storage_limit(
                    &sender.address,
                    &total_storage_limit,
                    dry_run,
                )?;
            }

            if let Err(err) = collateral_check_result {
                res = Err(err.into_vm_error());
            }
        }
        return Ok(res);
    }

    // TODO: maybe we can find a better interface for doing the suicide
    // post-processing.
    fn kill_process(&mut self) -> DbResult<()> {
        let parent_substate = &mut self.substate;
        let state = &mut *self.context.state;
        let spec = self.context.spec;
        let mut tracer = self.observer.as_tracer();

        assert!(state.no_checkpoint());

        let mut substate = Substate::new();
        for address in parent_substate
            .suicides
            .iter()
            .filter(|x| x.space == Space::Native)
        {
            let code_size = state.code_size(address)?;
            if code_size > 0 {
                // Only refund the code collateral when code exists.
                // If a contract suicides during creation, the code will be
                // empty.
                let code_owner = state.code_owner(address)?;
                substate.record_storage_release(
                    &code_owner,
                    code_collateral_units(code_size),
                );
            }
            state.record_storage_and_whitelist_entries_release(
                &address.address,
                &mut substate,
                spec.cip131,
            )?;

            assert!(state.is_fresh_storage(address)?);
        }

        // Kill process does not occupy new storage entries.
        // The storage recycling process should never occupy new collateral.
        settle_collateral_for_all(
            state,
            &substate,
            &mut *tracer,
            &spec,
            false,
        )?
        .expect("Should success");

        for contract_address in parent_substate
            .suicides
            .iter()
            .filter(|x| x.space == Space::Native)
            .map(|x| &x.address)
        {
            let sponsor_for_gas = state.sponsor_for_gas(contract_address)?;
            let sponsor_for_collateral =
                state.sponsor_for_collateral(contract_address)?;
            let sponsor_balance_for_gas =
                state.sponsor_balance_for_gas(contract_address)?;
            let sponsor_balance_for_collateral =
                state.sponsor_balance_for_collateral(contract_address)?;

            if let Some(ref sponsor_address) = sponsor_for_gas {
                tracer.trace_internal_transfer(
                    AddressPocket::SponsorBalanceForGas(*contract_address),
                    AddressPocket::Balance(sponsor_address.with_native_space()),
                    sponsor_balance_for_gas.clone(),
                );
                state.add_balance(
                    &sponsor_address.with_native_space(),
                    &sponsor_balance_for_gas,
                    cleanup_mode(&mut substate, spec),
                )?;
                state.sub_sponsor_balance_for_gas(
                    contract_address,
                    &sponsor_balance_for_gas,
                )?;
            }
            if let Some(ref sponsor_address) = sponsor_for_collateral {
                tracer.trace_internal_transfer(
                    AddressPocket::SponsorBalanceForStorage(*contract_address),
                    AddressPocket::Balance(sponsor_address.with_native_space()),
                    sponsor_balance_for_collateral.clone(),
                );

                state.add_balance(
                    &sponsor_address.with_native_space(),
                    &sponsor_balance_for_collateral,
                    cleanup_mode(&mut substate, spec),
                )?;
                state.sub_sponsor_balance_for_collateral(
                    contract_address,
                    &sponsor_balance_for_collateral,
                )?;
            }
        }

        for contract_address in &parent_substate.suicides {
            if contract_address.space == Space::Native {
                let contract_address = contract_address.address;
                let staking_balance =
                    state.staking_balance(&contract_address)?;
                tracer.trace_internal_transfer(
                    AddressPocket::StakingBalance(contract_address),
                    AddressPocket::MintBurn,
                    staking_balance.clone(),
                );
                state.sub_total_issued(staking_balance);
            }

            let contract_balance = state.balance(contract_address)?;
            tracer.trace_internal_transfer(
                AddressPocket::Balance(*contract_address),
                AddressPocket::MintBurn,
                contract_balance.clone(),
            );

            state.remove_contract(contract_address)?;
            state.sub_total_issued(contract_balance);
            if contract_address.space == Space::Ethereum {
                state.sub_total_evm_tokens(contract_balance);
            }
        }

        parent_substate.accrue(substate);

        Ok(())
    }

    fn compute_refunded_gas(&self, result: &ExecutiveResult) -> RefundInfo {
        let tx = self.tx;
        let cost = &self.cost;
        let spec = self.context.spec;
        let gas_left = match result {
            Ok(ExecutiveReturn { gas_left, .. }) => *gas_left,
            _ => 0.into(),
        };
        // gas_used is only used to estimate gas needed
        let gas_used = tx.gas() - gas_left;
        // gas_left should be smaller than 1/4 of gas_limit, otherwise
        // 3/4 of gas_limit is charged.
        let charge_all = (gas_left + gas_left + gas_left) >= gas_used;
        let (gas_charged, gas_refunded) = if charge_all {
            let gas_refunded = tx.gas() >> 2;
            let gas_charged = tx.gas() - gas_refunded;
            (gas_charged, gas_refunded)
        } else {
            (gas_used, gas_left)
        };

        let fees_value = gas_charged.saturating_mul(cost.gas_price);
        let burnt_fees_value = spec
            .cip1559
            .then(|| gas_charged.saturating_mul(cost.burnt_gas_price));

        let refund_value = gas_refunded.saturating_mul(cost.gas_price);

        RefundInfo {
            gas_used,
            gas_charged,
            fees_value,
            burnt_fees_value,
            refund_value,
        }
    }

    fn refund_gas(
        &mut self, params: &ActionParams, refund_value: U256,
    ) -> DbResult<()> {
        let context = &mut self.context;
        let cost = &self.cost;
        let state = &mut context.state;
        let mut tracer = self.observer.as_tracer();

        if cost.gas_sponsored {
            tracer.trace_internal_transfer(
                AddressPocket::GasPayment,
                AddressPocket::SponsorBalanceForGas(params.code_address),
                refund_value.clone(),
            );
            state.add_sponsor_balance_for_gas(
                &params.code_address,
                &refund_value,
            )?;
        } else {
            tracer.trace_internal_transfer(
                AddressPocket::GasPayment,
                AddressPocket::Balance(self.tx.sender()),
                refund_value.clone(),
            );
            state.add_balance(
                &self.tx.sender(),
                &refund_value,
                cleanup_mode(&mut self.substate, context.spec),
            )?;
        };

        Ok(())
    }
}

impl<'a, O: ExecutiveObserver> PreCheckedExecutive<'a, O> {
    fn finalize_on_insufficient_balance(
        self, actual_gas_cost: U256,
    ) -> DbResult<ExecutionOutcome> {
        return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
            ExecutionError::NotEnoughCash {
                required: self.cost.total_cost,
                got: self.cost.sender_balance,
                actual_gas_cost,
                max_storage_limit_cost: self.cost.storage_cost,
            },
            Executed::not_enough_balance_fee_charged(
                self.tx,
                &actual_gas_cost,
                self.cost,
                make_ext_result(self.observer),
                &self.context.spec,
            ),
        ));
    }

    fn finalize_on_conflict_address(
        self, address: Address,
    ) -> DbResult<ExecutionOutcome> {
        return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
            ExecutionError::VmError(vm::Error::ConflictAddress(address)),
            Executed::execution_error_fully_charged(
                self.tx,
                self.cost,
                make_ext_result(self.observer),
                &self.context.spec,
            ),
        ));
    }

    fn finalize_on_executed(
        self, result: ExecutiveResult, refund_info: RefundInfo,
    ) -> DbResult<ExecutionOutcome> {
        let tx = self.tx;
        let cost = self.cost;
        let ext_result = make_ext_result(self.observer);
        let spec = self.context.spec;
        let tx_substate = self.substate;

        let outcome = match result {
            Err(vm::Error::StateDbError(e)) => bail!(e.0),
            Err(exception) => ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(exception),
                Executed::execution_error_fully_charged(
                    tx, cost, ext_result, spec,
                ),
            ),
            Ok(r) => {
                let executed = Executed::from_executive_return(
                    &r,
                    refund_info,
                    cost,
                    tx_substate,
                    ext_result,
                    spec,
                );

                if r.apply_state {
                    ExecutionOutcome::Finished(executed)
                } else {
                    // Transaction reverted by vm instruction.
                    ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::VmError(vm::Error::Reverted),
                        executed,
                    )
                }
            }
        };

        Ok(outcome)
    }
}

pub(super) struct RefundInfo {
    pub gas_used: U256,
    pub gas_charged: U256,

    pub fees_value: U256,
    pub burnt_fees_value: Option<U256>,
    pub refund_value: U256,
}

pub(super) type ExecutiveResult = vm::Result<ExecutiveReturn>;

pub(super) struct ExecutiveReturn {
    pub gas_left: U256,
    /// Apply execution state changes or revert them.
    pub apply_state: bool,
    /// Return data buffer.
    pub return_data: Vec<u8>,
}
