use super::{Executed, ExecutionError, Observer};
use crate::{executive::executed::ExecutionOutcome, vm};
use cfx_parameters::{consensus::ONE_CFX_IN_DRIP, staking::*};
use cfx_state::CleanupMode;
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, Space, U256,
};
use primitives::{
    transaction::Action, NativeTransaction, SignedTransaction, Transaction,
};
use std::{
    cmp::{max, min},
    ops::Shl,
};

use super::ExecutiveGeneric;

impl<'a> ExecutiveGeneric<'a> {
    pub fn transact_virtual(
        &mut self, mut tx: SignedTransaction, request: EstimateRequest,
    ) -> DbResult<ExecutionOutcome> {
        let is_native_tx = tx.space() == Space::Native;
        let request_storage_limit = tx.storage_limit();

        if !request.has_sender {
            let mut random_hex = Address::random();
            if is_native_tx {
                random_hex.set_user_account_type_bits();
            }
            tx.sender = random_hex;
            tx.public = None;

            // If the sender is not specified, give it enough balance: 1 billion
            // CFX.
            let balance_inc = min(
                tx.value().saturating_add(
                    U256::from(1_000_000_000) * ONE_CFX_IN_DRIP,
                ),
                U256::one().shl(128),
            );

            self.state.add_balance(
                &random_hex.with_space(tx.space()),
                &balance_inc,
                CleanupMode::NoEmpty,
            )?;
            // Make sure statistics are also correct and will not violate any
            // underlying assumptions.
            self.state.add_total_issued(balance_inc);
            if tx.space() == Space::Ethereum {
                self.state.add_total_evm_tokens(balance_inc);
            }
        }

        if request.has_nonce {
            self.state.set_nonce(&tx.sender(), &tx.nonce())?;
        } else {
            *tx.nonce_mut() = self.state.nonce(&tx.sender())?;
        }

        let balance = self.state.balance(&tx.sender())?;

        // For the same transaction, the storage limit paid by user and the
        // storage limit paid by the sponsor are different values. So
        // this function will
        //
        // 1. First Pass: Assuming the sponsor pays for storage collateral,
        // check if the transaction will fail for
        // NotEnoughBalanceForStorage.
        //
        // 2. Second Pass: If it does, executes the transaction again assuming
        // the user pays for the storage collateral. The resultant
        // storage limit must be larger than the maximum storage limit
        // can be afford by the sponsor, to guarantee the user pays for
        // the storage limit.

        // First pass
        self.state.checkpoint();
        let sender_pay_executed = match self
            .transact(&tx, TransactOptions::estimate_first_pass(request))?
        {
            ExecutionOutcome::Finished(executed) => executed,
            res => {
                return Ok(res);
            }
        };
        debug!(
            "Transaction estimate first pass outcome {:?}",
            sender_pay_executed
        );
        self.state.revert_to_checkpoint();

        // Second pass
        let mut contract_pay_executed: Option<Executed> = None;
        let mut native_to_contract: Option<Address> = None;
        let mut sponsor_for_collateral_eligible = false;
        if let Transaction::Native(NativeTransaction {
            action: Action::Call(ref to),
            ..
        }) = tx.unsigned
        {
            if to.is_contract_address() {
                native_to_contract = Some(*to);
                let has_sponsor = self
                    .state
                    .sponsor_for_collateral(&to)?
                    .map_or(false, |x| !x.is_zero());

                if has_sponsor
                    && (self
                        .state
                        .check_contract_whitelist(&to, &tx.sender().address)?
                        || self
                            .state
                            .check_contract_whitelist(&to, &Address::zero())?)
                {
                    sponsor_for_collateral_eligible = true;

                    self.state.checkpoint();
                    let res = self.transact(
                        &tx,
                        TransactOptions::estimate_second_pass(request),
                    )?;
                    self.state.revert_to_checkpoint();

                    contract_pay_executed = match res {
                        ExecutionOutcome::Finished(executed) => Some(executed),
                        res => {
                            warn!("Should unreachable because two pass estimations should have the same output. \
                                Now we have: first pass success {:?}, second pass fail {:?}", sender_pay_executed, res);
                            None
                        }
                    };
                    debug!(
                        "Transaction estimate second pass outcome {:?}",
                        contract_pay_executed
                    );
                }
            }
        };

        let overwrite_storage_limit =
            |mut executed: Executed, max_sponsor_storage_limit: u64| {
                debug!("Transaction estimate overwrite the storage limit to overcome sponsor_balance_for_collateral.");
                executed.estimated_storage_limit = max(
                    executed.estimated_storage_limit,
                    max_sponsor_storage_limit + 64,
                );
                executed
            };

        let mut executed = if !sponsor_for_collateral_eligible {
            sender_pay_executed
        } else {
            let contract_address = native_to_contract.as_ref().unwrap();
            let sponsor_balance_for_collateral = self
                .state
                .sponsor_balance_for_collateral(contract_address)?
                + self.state.available_storage_points_for_collateral(
                    contract_address,
                )?;
            let max_sponsor_storage_limit = (sponsor_balance_for_collateral
                / *DRIPS_PER_STORAGE_COLLATERAL_UNIT)
                .as_u64();
            if let Some(contract_pay_executed) = contract_pay_executed {
                if max_sponsor_storage_limit
                    >= contract_pay_executed.estimated_storage_limit
                {
                    contract_pay_executed
                } else {
                    overwrite_storage_limit(
                        sender_pay_executed,
                        max_sponsor_storage_limit,
                    )
                }
            } else {
                overwrite_storage_limit(
                    sender_pay_executed,
                    max_sponsor_storage_limit,
                )
            }
        };

        // Revise the gas used in result, if we estimate the transaction with a
        // default large enough gas.
        if !request.has_gas_limit {
            let estimated_gas_limit = executed.estimated_gas_limit.unwrap();
            executed.gas_charged = max(
                estimated_gas_limit - estimated_gas_limit / 4,
                executed.gas_used,
            );
            executed.fee = executed.gas_charged.saturating_mul(*tx.gas_price());
        }

        // If we don't charge gas, recheck the current gas_fee is ok for
        // sponsorship.
        if !request.charge_gas()
            && request.has_gas_price
            && executed.gas_sponsor_paid
        {
            let enough_balance = executed.fee
                <= self
                    .state
                    .sponsor_balance_for_gas(&native_to_contract.unwrap())?;
            let enough_bound = executed.fee
                <= self
                    .state
                    .sponsor_gas_bound(&native_to_contract.unwrap())?;
            if !(enough_balance && enough_bound) {
                debug!("Transaction estimate unset \"sponsor_paid\" because of not enough sponsor balance / gas bound.");
                executed.gas_sponsor_paid = false;
            }
        }

        // If the request has a sender, recheck the balance requirement matched.
        if request.has_sender {
            // Unwrap safety: in given TransactOptions, this value must be
            // `Some(_)`.
            let gas_fee =
                if request.recheck_gas_fee() && !executed.gas_sponsor_paid {
                    executed
                        .estimated_gas_limit
                        .unwrap()
                        .saturating_mul(*tx.gas_price())
                } else {
                    0.into()
                };
            let storage_collateral = if !executed.storage_sponsor_paid {
                U256::from(executed.estimated_storage_limit)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                0.into()
            };
            let value_and_fee = tx
                .value()
                .saturating_add(gas_fee)
                .saturating_add(storage_collateral);
            if balance < value_and_fee {
                return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                    ExecutionError::NotEnoughCash {
                        required: value_and_fee.into(),
                        got: balance.into(),
                        actual_gas_cost: min(balance, gas_fee),
                        max_storage_limit_cost: storage_collateral,
                    },
                    executed,
                ));
            }
        }

        if request.has_storage_limit {
            let storage_limit = request_storage_limit.unwrap();
            if storage_limit < executed.estimated_storage_limit {
                return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                    ExecutionError::VmError(vm::Error::ExceedStorageLimit),
                    executed,
                ));
            }
        }

        return Ok(ExecutionOutcome::Finished(executed));
    }
}

/// Transaction execution options.
pub struct TransactOptions {
    pub observer: Observer,
    pub check_settings: TransactCheckSettings,
}

impl TransactOptions {
    pub fn exec_with_tracing() -> Self {
        Self {
            observer: Observer::with_tracing(),
            check_settings: TransactCheckSettings::all_checks(),
        }
    }

    pub fn exec_with_no_tracing() -> Self {
        Self {
            observer: Observer::with_no_tracing(),
            check_settings: TransactCheckSettings::all_checks(),
        }
    }

    pub fn estimate_first_pass(request: EstimateRequest) -> Self {
        Self {
            observer: Observer::virtual_call(),
            check_settings: TransactCheckSettings::from_estimate_request(
                request,
                ChargeCollateral::EstimateSender,
            ),
        }
    }

    pub fn estimate_second_pass(request: EstimateRequest) -> Self {
        Self {
            observer: Observer::virtual_call(),
            check_settings: TransactCheckSettings::from_estimate_request(
                request,
                ChargeCollateral::EstimateSponsor,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ChargeCollateral {
    Normal,
    EstimateSender,
    EstimateSponsor,
}

#[derive(Debug, Clone, Copy)]
pub struct EstimateRequest {
    pub has_sender: bool,
    pub has_gas_limit: bool,
    pub has_gas_price: bool,
    pub has_nonce: bool,
    pub has_storage_limit: bool,
}

impl EstimateRequest {
    fn recheck_gas_fee(&self) -> bool { self.has_sender && self.has_gas_price }

    fn charge_gas(&self) -> bool {
        self.has_sender && self.has_gas_limit && self.has_gas_price
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TransactCheckSettings {
    pub charge_collateral: ChargeCollateral,
    pub charge_gas: bool,
    pub real_execution: bool,
    pub check_epoch_height: bool,
}

impl TransactCheckSettings {
    fn all_checks() -> Self {
        Self {
            charge_collateral: ChargeCollateral::Normal,
            charge_gas: true,
            real_execution: true,
            check_epoch_height: true,
        }
    }

    fn from_estimate_request(
        request: EstimateRequest, charge_collateral: ChargeCollateral,
    ) -> Self {
        Self {
            charge_collateral,
            charge_gas: request.charge_gas(),
            real_execution: false,
            check_epoch_height: false,
        }
    }
}
