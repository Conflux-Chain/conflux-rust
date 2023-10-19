// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    estimation::{ChargeCollateral, TransactCheckSettings, TransactOptions},
    frame::{exec_main_frame, FrameResult, FreshFrame, RuntimeRes},
    Executed, ExecutionError, FrameReturn,
};
use crate::{
    bytes::Bytes,
    executive::{
        executed::{ExecutionOutcome, ToRepackError, TxDropError},
        frame::accrue_substate,
    },
    hash::keccak,
    machine::Machine,
    observer::{
        tracer::ExecutiveTracer, AddressPocket, GasMan, StateTracer, VmObserve,
    },
    state::{
        cleanup_mode, settle_collateral_for_all, CallStackInfo, State, Substate,
    },
    verification::VerificationConfig,
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress,
        CreateType, Env, Spec,
    },
};
use cfx_parameters::staking::*;

use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, H256, U256, U512, U64,
};
use primitives::{
    receipt::StorageChange, transaction::Action, SignedTransaction, Transaction,
};
use rlp::RlpStream;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    sync::Arc,
};

/// Calculate new contract address.
pub fn contract_address(
    address_scheme: CreateContractAddress, _block_number: U64,
    sender: &AddressWithSpace, nonce: &U256, code: &[u8],
) -> (AddressWithSpace, Option<H256>)
{
    let code_hash = keccak(code);
    let (address, code_hash) = match address_scheme {
        CreateContractAddress::FromSenderNonce => {
            assert_eq!(sender.space, Space::Ethereum);
            let mut rlp = RlpStream::new_list(2);
            rlp.append(&sender.address);
            rlp.append(nonce);
            let h = Address::from(keccak(rlp.as_raw()));
            (h, Some(code_hash))
        }
        CreateContractAddress::FromBlockNumberSenderNonceAndCodeHash => {
            unreachable!("Inactive setting");
            // let mut buffer = [0u8; 1 + 8 + 20 + 32 + 32];
            // let (lead_bytes, rest) = buffer.split_at_mut(1);
            // let (block_number_bytes, rest) = rest.split_at_mut(8);
            // let (sender_bytes, rest) =
            // rest.split_at_mut(Address::len_bytes());
            // let (nonce_bytes, code_hash_bytes) =
            //     rest.split_at_mut(H256::len_bytes());
            // // In Conflux, we take block_number and CodeHash into address
            // // calculation. This is required to enable us to clean
            // // up unused user account in future.
            // lead_bytes[0] = 0x0;
            // block_number.to_little_endian(block_number_bytes);
            // sender_bytes.copy_from_slice(&sender.address[..]);
            // nonce.to_little_endian(nonce_bytes);
            // code_hash_bytes.copy_from_slice(&code_hash[..]);
            // // In Conflux, we use the first four bits to indicate the type of
            // // the address. For contract address, the bits will be
            // // set to 0x8.
            // let mut h = Address::from(keccak(&buffer[..]));
            // h.set_contract_type_bits();
            // (h, Some(code_hash))
        }
        CreateContractAddress::FromSenderNonceAndCodeHash => {
            assert_eq!(sender.space, Space::Native);
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            // In Conflux, we append CodeHash to determine the address as well.
            // This is required to enable us to clean up unused user account in
            // future.
            buffer[0] = 0x0;
            buffer[1..(1 + 20)].copy_from_slice(&sender.address[..]);
            nonce.to_little_endian(&mut buffer[(1 + 20)..(1 + 20 + 32)]);
            buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first four bits to indicate the type of
            // the address. For contract address, the bits will be
            // set to 0x8.
            let mut h = Address::from(keccak(&buffer[..]));
            h.set_contract_type_bits();
            (h, Some(code_hash))
        }
        CreateContractAddress::FromSenderSaltAndCodeHash(salt) => {
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            buffer[0] = 0xff;
            buffer[1..(1 + 20)].copy_from_slice(&sender.address[..]);
            buffer[(1 + 20)..(1 + 20 + 32)].copy_from_slice(&salt[..]);
            buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first bit to indicate the type of the
            // address. For contract address, the bits will be set to 0x8.
            let mut h = Address::from(keccak(&buffer[..]));
            if sender.space == Space::Native {
                h.set_contract_type_bits();
            }
            (h, Some(code_hash))
        }
    };
    return (address.with_space(sender.space), code_hash);
}

pub struct Observer {
    pub tracer: Option<ExecutiveTracer>,
    pub gas_man: Option<GasMan>,
    _noop: (),
}

impl Observer {
    pub fn as_vm_observe<'a>(&'a mut self) -> Box<dyn VmObserve + 'a> {
        match (self.tracer.as_mut(), self.gas_man.as_mut()) {
            (Some(tracer), Some(gas_man)) => Box::new((tracer, gas_man)),
            (Some(tracer), None) => Box::new(tracer),
            (None, Some(gas_man)) => Box::new(gas_man),
            (None, None) => Box::new(&mut self._noop),
        }
    }

    pub fn as_state_tracer(&mut self) -> &mut dyn StateTracer {
        match self.tracer.as_mut() {
            None => &mut self._noop,
            Some(tracer) => tracer,
        }
    }

    pub fn with_tracing() -> Self {
        Observer {
            tracer: Some(ExecutiveTracer::default()),
            gas_man: None,
            _noop: (),
        }
    }

    pub fn with_no_tracing() -> Self {
        Observer {
            tracer: None,
            gas_man: None,
            _noop: (),
        }
    }

    pub fn virtual_call() -> Self {
        Observer {
            tracer: Some(ExecutiveTracer::default()),
            gas_man: Some(GasMan::default()),
            _noop: (),
        }
    }
}

// /// Trap result returned by executive.
// pub type ExecutiveTrapResult<'a, T> =
//     vm::TrapResult<T, CallCreateFrame<'a>, CallCreateFrame<'a>>;

// pub type ExecutiveTrapError<'a> =
//     vm::TrapError<CallCreateFrame<'a>, CallCreateFrame<'a>>;

pub type Executive<'a> = ExecutiveGeneric<'a>;

/// Transaction executor.
pub struct ExecutiveGeneric<'a> {
    pub state: &'a mut State,
    env: &'a Env,
    machine: &'a Machine,
    spec: &'a Spec,
    depth: usize,
    static_flag: bool,
}

struct SponsorCheckOutput {
    sender_intended_cost: U512,
    total_cost: U512,
    gas_sponsored: bool,
    storage_sponsored: bool,
    storage_sponsor_eligible: bool,
}

pub fn gas_required_for(is_create: bool, data: &[u8], spec: &Spec) -> u64 {
    data.iter().fold(
        (if is_create {
            spec.tx_create_gas
        } else {
            spec.tx_gas
        }) as u64,
        |g, b| {
            g + (match *b {
                0 => spec.tx_data_zero_gas,
                _ => spec.tx_data_non_zero_gas,
            }) as u64
        },
    )
}

impl<'a> ExecutiveGeneric<'a> {
    /// Basic constructor.
    pub fn new(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec,
    ) -> Self
    {
        ExecutiveGeneric {
            state,
            env,
            machine,
            spec,
            depth: 0,
            static_flag: false,
        }
    }

    pub fn exec_tx(
        &mut self, params: ActionParams, tracer: &mut dyn VmObserve,
        total_storage_limit: U256, check_settings: &TransactCheckSettings,
    ) -> DbResult<(FrameResult, Bytes)>
    {
        // Initialize the checkpoint for transaction execution. This checkpoint
        // can be reverted by "not enough balance for storage".
        self.state.checkpoint();
        tracer.checkpoint();

        let sender = params.sender.with_space(params.space);

        let mut res = self.exec_vm(params, tracer)?;
        if let Ok(FrameReturn {
            apply_state: true,
            substate: Some(ref substate),
            ..
        }) = res
        {
            let dry_run = !matches!(
                check_settings.charge_collateral,
                ChargeCollateral::Normal
            );

            // For a ethereum space tx, this function has no op.
            let mut collateral_check_result = settle_collateral_for_all(
                &mut self.state,
                substate,
                tracer,
                &self.spec,
                dry_run,
            )?;

            if collateral_check_result.is_ok() {
                collateral_check_result = self.state.check_storage_limit(
                    &sender.address,
                    &total_storage_limit,
                    dry_run,
                )?;
            }

            if let Err(err) = collateral_check_result {
                res = Err(err.into_vm_error());
            }
        }
        // Charge collateral and process the checkpoint.
        let out = match &res {
            Ok(res) => {
                tracer.discard_checkpoint();
                self.state.discard_checkpoint();
                res.return_data.to_vec()
            }
            Err(vm::Error::StateDbError(_)) => {
                // The whole epoch execution fails. No need to revert state.
                Vec::new()
            }
            Err(_) => {
                tracer.revert_to_checkpoint();
                self.state.revert_to_checkpoint();
                Vec::new()
            }
        };
        Ok((res, out))
    }

    fn exec_vm(
        &mut self, params: ActionParams, tracer: &mut dyn VmObserve,
    ) -> DbResult<FrameResult> {
        let main_frame = FreshFrame::new(
            params,
            self.env,
            self.machine,
            self.spec,
            self.depth,
            self.static_flag,
        );
        let mut callstack = CallStackInfo::new();
        let resources = RuntimeRes {
            state: &mut self.state,
            callstack: &mut callstack,
            tracer,
        };
        exec_main_frame(main_frame, resources)
    }

    #[cfg(test)]
    pub fn call_for_test(
        &mut self, params: ActionParams, substate: &mut Substate,
        tracer: &mut dyn VmObserve,
    ) -> DbResult<vm::Result<crate::evm::FinalizationResult>>
    {
        let mut frame_result = self.exec_vm(params, tracer)?;
        accrue_substate(substate, &mut frame_result);

        Ok(frame_result.map(Into::into))
    }

    fn sponsor_check(
        &self, tx: &SignedTransaction, spec: &Spec, sender_balance: U512,
        gas_cost: U512, storage_cost: U256, settings: &TransactCheckSettings,
    ) -> DbResult<Result<SponsorCheckOutput, ExecutionOutcome>>
    {
        let sender = tx.sender();
        // Check if contract will pay transaction fee for the sender.
        let mut code_address = Address::zero();
        let mut gas_sponsor_eligible = false;
        let mut storage_sponsor_eligible = false;

        if let Action::Call(ref address) = tx.action() {
            if !spec.is_valid_address(address) {
                return Ok(Err(ExecutionOutcome::NotExecutedDrop(
                    TxDropError::InvalidRecipientAddress(*address),
                )));
            }
            if self
                .state
                .is_contract_with_code(&address.with_native_space())?
            {
                code_address = *address;
                if self
                    .state
                    .check_contract_whitelist(&code_address, &sender.address)?
                {
                    // No need to check for gas sponsor account existence.
                    gas_sponsor_eligible = gas_cost
                        <= U512::from(
                            self.state.sponsor_gas_bound(&code_address)?,
                        );
                    storage_sponsor_eligible = self
                        .state
                        .sponsor_for_collateral(&code_address)?
                        .is_some();
                }
            }
        }

        let code_address = code_address;
        let gas_sponsor_eligible = gas_sponsor_eligible;
        let storage_sponsor_eligible = storage_sponsor_eligible;

        // Sender pays for gas when sponsor runs out of balance.
        let sponsor_balance_for_gas =
            U512::from(self.state.sponsor_balance_for_gas(&code_address)?);
        let gas_sponsored =
            gas_sponsor_eligible && sponsor_balance_for_gas >= gas_cost;

        let sponsor_balance_for_storage =
            self.state.sponsor_balance_for_collateral(&code_address)?
                + self
                    .state
                    .available_storage_points_for_collateral(&code_address)?;
        let storage_sponsored = match settings.charge_collateral {
            ChargeCollateral::Normal => {
                storage_sponsor_eligible
                    && storage_cost <= sponsor_balance_for_storage
            }
            ChargeCollateral::EstimateSender => false,
            ChargeCollateral::EstimateSponsor => true,
        };

        let sender_intended_cost = {
            let mut sender_intended_cost = U512::from(tx.value());

            if !gas_sponsor_eligible {
                sender_intended_cost += gas_cost;
            }
            if !storage_sponsor_eligible {
                sender_intended_cost += storage_cost.into();
            }
            sender_intended_cost
        };
        let total_cost = {
            let mut total_cost = U512::from(tx.value());
            if !gas_sponsored {
                total_cost += gas_cost
            }
            if !storage_sponsored {
                total_cost += storage_cost.into();
            }
            total_cost
        };
        // Sponsor is allowed however sender do not have enough balance to pay
        // for the extra gas because sponsor has run out of balance in
        // the mean time.
        //
        // Sender is not responsible for the incident, therefore we don't fail
        // the transaction.
        if sender_balance >= sender_intended_cost && sender_balance < total_cost
        {
            let gas_sponsor_balance = if gas_sponsor_eligible {
                sponsor_balance_for_gas
            } else {
                0.into()
            };

            let storage_sponsor_balance = if storage_sponsor_eligible {
                sponsor_balance_for_storage
            } else {
                0.into()
            };

            return Ok(Err(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::NotEnoughCashFromSponsor {
                    required_gas_cost: gas_cost,
                    gas_sponsor_balance,
                    required_storage_cost: storage_cost,
                    storage_sponsor_balance,
                },
            )));
        }

        return Ok(Ok(SponsorCheckOutput {
            sender_intended_cost,
            total_cost,
            gas_sponsored,
            storage_sponsored,
            // Only for backward compatible for a early bug.
            // The receipt reported `storage_sponsor_eligible` instead of
            // `storage_sponsored`.
            storage_sponsor_eligible,
        }));
    }

    pub fn transact(
        &mut self, tx: &SignedTransaction, options: TransactOptions,
    ) -> DbResult<ExecutionOutcome> {
        let TransactOptions {
            mut observer,
            check_settings,
        } = options;

        let spec = &self.spec;
        let sender = tx.sender();
        let nonce = self.state.nonce(&sender)?;

        // Validate transaction nonce
        if *tx.nonce() < nonce {
            return Ok(ExecutionOutcome::NotExecutedDrop(
                TxDropError::OldNonce(nonce, *tx.nonce()),
            ));
        } else if *tx.nonce() > nonce {
            return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::InvalidNonce {
                    expected: nonce,
                    got: *tx.nonce(),
                },
            ));
        }

        // Validate transaction epoch height.
        if let Transaction::Native(ref tx) = tx.transaction.transaction.unsigned
        {
            if check_settings.check_epoch_height
                && VerificationConfig::check_transaction_epoch_bound(
                    tx,
                    self.env.epoch_height,
                    self.env.transaction_epoch_bound,
                ) != 0
            {
                return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                    ToRepackError::EpochHeightOutOfBound {
                        block_height: self.env.epoch_height,
                        set: tx.epoch_height,
                        transaction_epoch_bound: self
                            .env
                            .transaction_epoch_bound,
                    },
                ));
            }
        }

        let base_gas_required =
            gas_required_for(tx.action() == &Action::Create, &tx.data(), spec);
        assert!(
            *tx.gas() >= base_gas_required.into(),
            "We have already checked the base gas requirement when we received the block."
        );

        let balance = self.state.balance(&sender)?;
        let gas_cost = if check_settings.charge_gas {
            tx.gas().full_mul(*tx.gas_price())
        } else {
            0.into()
        };
        let storage_cost =
            if let (Transaction::Native(tx), ChargeCollateral::Normal) = (
                &tx.transaction.transaction.unsigned,
                check_settings.charge_collateral,
            ) {
                U256::from(tx.storage_limit)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                U256::zero()
            };

        let sender_balance = U512::from(balance);

        let SponsorCheckOutput {
            sender_intended_cost,
            total_cost,
            gas_sponsored,
            storage_sponsored,
            storage_sponsor_eligible,
        } = if sender.space == Space::Native {
            match self.sponsor_check(
                tx,
                &spec,
                sender_balance,
                gas_cost,
                storage_cost,
                &check_settings,
            )? {
                Ok(res) => res,
                Err(err) => {
                    return Ok(err);
                }
            }
        } else {
            let sender_cost = U512::from(tx.value()) + gas_cost;
            SponsorCheckOutput {
                sender_intended_cost: sender_cost,
                total_cost: sender_cost,
                gas_sponsored: false,
                storage_sponsored: false,
                storage_sponsor_eligible: false,
            }
        };

        let mut tx_substate = Substate::new();
        if sender_balance < sender_intended_cost {
            // Sender is responsible for the insufficient balance.
            // Sub tx fee if not enough cash, and substitute all remaining
            // balance if balance is not enough to pay the tx fee
            let actual_gas_cost: U256 =
                U512::min(gas_cost, sender_balance).try_into().unwrap();

            // We don't want to bump nonce for non-existent account when we
            // can't charge gas fee. In this case, the sender account will
            // not be created if it does not exist.
            if !self.state.exists(&sender)? && check_settings.real_execution {
                return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                    ToRepackError::SenderDoesNotExist,
                ));
            }
            self.state.inc_nonce(&sender)?;
            self.state.sub_balance(
                &sender,
                &actual_gas_cost,
                &mut cleanup_mode(&mut tx_substate, &spec),
            )?;
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::Balance(sender.address.with_space(tx.space())),
                AddressPocket::GasPayment,
                actual_gas_cost,
            );
            if tx.space() == Space::Ethereum {
                self.state.sub_total_evm_tokens(actual_gas_cost);
            }

            return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::NotEnoughCash {
                    required: total_cost,
                    got: sender_balance,
                    actual_gas_cost: actual_gas_cost.clone(),
                    max_storage_limit_cost: storage_cost,
                },
                Executed::not_enough_balance_fee_charged(
                    tx,
                    &actual_gas_cost,
                    gas_sponsored,
                    storage_sponsored,
                    observer.tracer.map_or(Default::default(), |t| t.drain()),
                    &self.spec,
                ),
            ));
        } else {
            // From now on sender balance >= total_cost, even if the sender
            // account does not exist (since she may be sponsored). Transaction
            // execution is guaranteed. Note that inc_nonce() will create a
            // new account if the account does not exist.
            self.state.inc_nonce(&sender)?;
        }

        // Subtract the transaction fee from sender or contract.
        let gas_cost = U256::try_from(gas_cost).unwrap();
        // For tracer only when tx is sponsored.
        let code_address = match tx.action() {
            Action::Create => Address::zero(),
            Action::Call(ref address) => *address,
        };

        if !gas_sponsored {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::Balance(sender.address.with_space(tx.space())),
                AddressPocket::GasPayment,
                gas_cost,
            );
            self.state.sub_balance(
                &sender,
                &U256::try_from(gas_cost).unwrap(),
                &mut cleanup_mode(&mut tx_substate, &spec),
            )?;
        // Don't subtract total_evm_balance here. It is maintained properly in
        // `finalize`.
        } else {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::SponsorBalanceForGas(code_address),
                AddressPocket::GasPayment,
                gas_cost,
            );

            self.state.sub_sponsor_balance_for_gas(
                &code_address,
                &U256::try_from(gas_cost).unwrap(),
            )?;
        }

        let init_gas = tx.gas() - base_gas_required;

        // Find the `storage_owner` in this execution.
        let storage_owner = if storage_sponsored {
            code_address
        } else {
            sender.address
        };

        // No matter who pays the collateral, we only focuses on the storage
        // limit of sender.
        let total_storage_limit =
            self.state.collateral_for_storage(&sender.address)? + storage_cost;

        let params = self.make_action_params(tx, storage_owner, init_gas)?;

        if !self.check_create_address(&params)? {
            return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(vm::Error::ConflictAddress(
                    params.address.clone(),
                )),
                Executed::execution_error_fully_charged(
                    tx,
                    gas_sponsored,
                    storage_sponsored,
                    observer.tracer.map_or(Default::default(), |t| t.drain()),
                    &spec,
                ),
            ));
        }

        let (mut result, output) = self.exec_tx(
            params,
            &mut *observer.as_vm_observe(),
            total_storage_limit,
            &check_settings,
        )?;
        accrue_substate(&mut tx_substate, &mut result);

        let refund_receiver = if gas_sponsored {
            Some(code_address)
        } else {
            None
        };

        let estimated_gas_limit = observer
            .gas_man
            .as_ref()
            .map(|g| g.gas_required() * 7 / 6 + base_gas_required);

        Ok(self.finalize(
            tx,
            tx_substate,
            result,
            output,
            refund_receiver,
            /* Storage sponsor paid */
            if self.spec.cip78a {
                storage_sponsored
            } else {
                storage_sponsor_eligible
            },
            observer,
            estimated_gas_limit,
        )?)
    }

    fn make_action_params(
        &self, tx: &SignedTransaction, storage_owner: Address, init_gas: U256,
    ) -> DbResult<ActionParams> {
        let sender = tx.sender();
        let nonce = tx.nonce();
        match tx.action() {
            Action::Create => {
                let address_scheme = match tx.space() {
                    Space::Native => {
                        CreateContractAddress::FromSenderNonceAndCodeHash
                    }
                    Space::Ethereum => CreateContractAddress::FromSenderNonce,
                };
                let (new_address, _code_hash) = contract_address(
                    address_scheme,
                    self.env.number.into(),
                    &sender,
                    &nonce,
                    &tx.data(),
                );

                Ok(ActionParams {
                    space: sender.space,
                    code_address: new_address.address,
                    code_hash: None,
                    address: new_address.address,
                    sender: sender.address,
                    original_sender: sender.address,
                    storage_owner,
                    gas: init_gas,
                    gas_price: *tx.gas_price(),
                    value: ActionValue::Transfer(*tx.value()),
                    code: Some(Arc::new(tx.data().clone())),
                    data: None,
                    call_type: CallType::None,
                    create_type: CreateType::CREATE,
                    params_type: vm::ParamsType::Embedded,
                })
            }
            Action::Call(ref address) => {
                let address = address.with_space(sender.space);
                Ok(ActionParams {
                    space: sender.space,
                    code_address: address.address,
                    address: address.address,
                    sender: sender.address,
                    original_sender: sender.address,
                    storage_owner,
                    gas: init_gas,
                    gas_price: *tx.gas_price(),
                    value: ActionValue::Transfer(*tx.value()),
                    code: self.state.code(&address)?,
                    code_hash: self.state.code_hash(&address)?,
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
        self.state.is_contract_with_code(&new_address).map(|x| !x)
    }

    // TODO: maybe we can find a better interface for doing the suicide
    // post-processing.
    fn kill_process(
        &mut self, suicides: &HashSet<AddressWithSpace>,
        tracer: &mut dyn VmObserve, spec: &Spec,
    ) -> DbResult<Substate>
    {
        let mut substate = Substate::new();
        for address in suicides {
            if let Some(code_size) = self.state.code_size(address)? {
                // Only refund the code collateral when code exists.
                // If a contract suicides during creation, the code will be
                // empty.
                if address.space == Space::Native {
                    let code_owner = self
                        .state
                        .code_owner(address)?
                        .expect("code owner exists");
                    substate.record_storage_release(
                        &code_owner,
                        code_collateral_units(code_size),
                    );
                }
            }

            if address.space == Space::Native {
                self.state.record_storage_and_whitelist_entries_release(
                    &address.address,
                    &mut substate,
                )?;
            }

            assert!(self.state.is_fresh_storage(address)?);
        }

        // Kill process does not occupy new storage entries.
        // The storage recycling process should never occupy new collateral.
        settle_collateral_for_all(
            &mut self.state,
            &substate,
            tracer,
            spec,
            false,
        )?
        .expect("Should success");

        for contract_address in suicides
            .iter()
            .filter(|x| x.space == Space::Native)
            .map(|x| &x.address)
        {
            let sponsor_for_gas =
                self.state.sponsor_for_gas(contract_address)?;
            let sponsor_for_collateral =
                self.state.sponsor_for_collateral(contract_address)?;
            let sponsor_balance_for_gas =
                self.state.sponsor_balance_for_gas(contract_address)?;
            let sponsor_balance_for_collateral = self
                .state
                .sponsor_balance_for_collateral(contract_address)?;

            if let Some(ref sponsor_address) = sponsor_for_gas {
                tracer.trace_internal_transfer(
                    AddressPocket::SponsorBalanceForGas(*contract_address),
                    AddressPocket::Balance(sponsor_address.with_native_space()),
                    sponsor_balance_for_gas.clone(),
                );
                self.state.add_balance(
                    &sponsor_address.with_native_space(),
                    &sponsor_balance_for_gas,
                    cleanup_mode(&mut substate, self.spec),
                )?;
                self.state.sub_sponsor_balance_for_gas(
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

                self.state.add_balance(
                    &sponsor_address.with_native_space(),
                    &sponsor_balance_for_collateral,
                    cleanup_mode(&mut substate, self.spec),
                )?;
                self.state.sub_sponsor_balance_for_collateral(
                    contract_address,
                    &sponsor_balance_for_collateral,
                )?;
            }
        }

        for contract_address in suicides {
            if contract_address.space == Space::Native {
                let contract_address = contract_address.address;
                let staking_balance =
                    self.state.staking_balance(&contract_address)?;
                tracer.trace_internal_transfer(
                    AddressPocket::StakingBalance(contract_address),
                    AddressPocket::MintBurn,
                    staking_balance.clone(),
                );
                self.state.sub_total_issued(staking_balance);
            }

            let contract_balance = self.state.balance(contract_address)?;
            tracer.trace_internal_transfer(
                AddressPocket::Balance(*contract_address),
                AddressPocket::MintBurn,
                contract_balance.clone(),
            );

            self.state.remove_contract(contract_address)?;
            self.state.sub_total_issued(contract_balance);
            if contract_address.space == Space::Ethereum {
                self.state.sub_total_evm_tokens(contract_balance);
            }
        }

        Ok(substate)
    }

    /// Finalizes the transaction (does refunds and suicides).
    fn finalize(
        &mut self, tx: &SignedTransaction, mut substate: Substate,
        result: vm::Result<FrameReturn>, output: Bytes,
        refund_receiver: Option<Address>, storage_sponsor_paid: bool,
        mut observer: Observer, estimated_gas_limit: Option<U256>,
    ) -> DbResult<ExecutionOutcome>
    {
        let gas_left = match result {
            Ok(FrameReturn { gas_left, .. }) => gas_left,
            _ => 0.into(),
        };

        // gas_used is only used to estimate gas needed
        let gas_used = tx.gas() - gas_left;
        // gas_left should be smaller than 1/4 of gas_limit, otherwise
        // 3/4 of gas_limit is charged.
        let charge_all = (gas_left + gas_left + gas_left) >= gas_used;
        let (gas_charged, fees_value, refund_value) = if charge_all {
            let gas_refunded = tx.gas() >> 2;
            let gas_charged = tx.gas() - gas_refunded;
            (
                gas_charged,
                gas_charged.saturating_mul(*tx.gas_price()),
                gas_refunded.saturating_mul(*tx.gas_price()),
            )
        } else {
            (
                gas_used,
                gas_used.saturating_mul(*tx.gas_price()),
                gas_left.saturating_mul(*tx.gas_price()),
            )
        };

        if let Some(r) = refund_receiver {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::GasPayment,
                AddressPocket::SponsorBalanceForGas(r),
                refund_value.clone(),
            );
            self.state.add_sponsor_balance_for_gas(&r, &refund_value)?;
        } else {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::GasPayment,
                AddressPocket::Balance(tx.sender()),
                refund_value.clone(),
            );
            self.state.add_balance(
                &tx.sender(),
                &refund_value,
                cleanup_mode(&mut substate, self.spec),
            )?;
        };

        if tx.space() == Space::Ethereum {
            self.state.sub_total_evm_tokens(fees_value);
        }

        // perform suicides

        let subsubstate = self.kill_process(
            &substate.suicides,
            &mut *observer.as_vm_observe(),
            &self.spec,
        )?;
        substate.accrue(subsubstate);

        // TODO should be added back after enabling dust collection
        // Should be executed once per block, instead of per transaction?
        //
        // When enabling this feature, remember to check touched set in
        // functions like "add_collateral_for_storage()" in "State"
        // struct.

        //        // perform garbage-collection
        //        let min_balance = if spec.kill_dust != CleanDustMode::Off {
        //            Some(U256::from(spec.tx_gas) * tx.gas_price())
        //        } else {
        //            None
        //        };
        //
        //        self.state.kill_garbage(
        //            &substate.touched,
        //            spec.kill_empty,
        //            &min_balance,
        //            spec.kill_dust == CleanDustMode::WithCodeAndStorage,
        //        )?;

        match result {
            Err(vm::Error::StateDbError(e)) => bail!(e.0),
            Err(exception) => Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(exception),
                Executed::execution_error_fully_charged(
                    tx,
                    refund_receiver.is_some(),
                    storage_sponsor_paid,
                    observer.tracer.map_or(Default::default(), |t| t.drain()),
                    &self.spec,
                ),
            )),
            Ok(r) => {
                let mut storage_collateralized = Vec::new();
                let mut storage_released = Vec::new();

                if r.apply_state {
                    let mut affected_address: Vec<_> = substate
                        .keys_for_collateral_changed()
                        .iter()
                        .cloned()
                        .collect();
                    affected_address.sort();
                    for address in affected_address {
                        let (inc, sub) =
                            substate.get_collateral_change(&address);
                        if inc > 0 {
                            storage_collateralized.push(StorageChange {
                                address: *address,
                                collaterals: inc.into(),
                            });
                        } else if sub > 0 {
                            storage_released.push(StorageChange {
                                address: *address,
                                collaterals: sub.into(),
                            });
                        }
                    }
                }

                let trace =
                    observer.tracer.map_or(Default::default(), |t| t.drain());

                let estimated_storage_limit =
                    if let Some(x) = storage_collateralized.first() {
                        x.collaterals.as_u64()
                    } else {
                        0
                    };

                let executed = Executed {
                    gas_used,
                    gas_charged,
                    fee: fees_value,
                    gas_sponsor_paid: refund_receiver.is_some(),
                    logs: substate.logs.to_vec(),
                    contracts_created: substate.contracts_created.to_vec(),
                    storage_sponsor_paid,
                    storage_collateralized,
                    storage_released,
                    output,
                    trace,
                    estimated_gas_limit,
                    estimated_storage_limit,
                };

                if r.apply_state {
                    Ok(ExecutionOutcome::Finished(executed))
                } else {
                    // Transaction reverted by vm instruction.
                    Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::VmError(vm::Error::Reverted),
                        executed,
                    ))
                }
            }
        }
    }
}

pub type CollateralCheckResult = std::result::Result<(), CollateralCheckError>;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum CollateralCheckError {
    ExceedStorageLimit { limit: U256, required: U256 },
    NotEnoughBalance { required: U256, got: U256 },
}

impl CollateralCheckError {
    pub fn into_vm_error(self) -> vm::Error {
        match self {
            CollateralCheckError::ExceedStorageLimit { .. } => {
                vm::Error::ExceedStorageLimit
            }
            CollateralCheckError::NotEnoughBalance { required, got } => {
                vm::Error::NotEnoughBalanceForStorage { required, got }
            }
        }
    }
}
