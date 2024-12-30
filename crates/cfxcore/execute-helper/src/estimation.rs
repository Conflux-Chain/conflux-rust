use cfx_executor::{
    executive::{
        ChargeCollateral, Executed, ExecutionError, ExecutionOutcome,
        ExecutiveContext, TransactOptions, TransactSettings,
    },
    machine::Machine,
    state::{CleanupMode, State},
};
use solidity_abi::string_revert_reason_decode;

use super::observer::{
    exec_tracer::ErrorUnwind, gasman::GasLimitEstimation, Observer,
};
use cfx_parameters::{consensus::ONE_CFX_IN_DRIP, staking::*};
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, Space, U256,
};
use cfx_vm_types::{self as vm, Env, Spec};
use primitives::{transaction::Action, SignedTransaction, Transaction};
use std::{
    cmp::{max, min},
    fmt::Display,
    ops::{Mul, Shl},
};

enum SponsoredType {
    Gas,
    Collateral,
}

#[derive(Default, Debug)]
pub struct EstimateExt {
    pub estimated_gas_limit: U256,
    pub estimated_storage_limit: u64,
}

pub struct EstimationContext<'a> {
    state: &'a mut State,
    env: &'a Env,
    machine: &'a Machine,
    spec: &'a Spec,
}

impl<'a> EstimationContext<'a> {
    pub fn new(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec,
    ) -> Self {
        EstimationContext {
            state,
            env,
            machine,
            spec,
        }
    }

    fn as_executive<'b>(&'b mut self) -> ExecutiveContext<'b> {
        ExecutiveContext::new(self.state, self.env, self.machine, self.spec)
    }

    fn process_estimate_request(
        &mut self, tx: &mut SignedTransaction, request: &EstimateRequest,
    ) -> DbResult<()> {
        if !request.has_sender {
            let mut random_hex = Address::random();
            if tx.space() == Space::Native {
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

        Ok(())
    }

    fn sponsored_contract_if_eligible_sender(
        &self, tx: &SignedTransaction, ty: SponsoredType,
    ) -> DbResult<Option<Address>> {
        if let Transaction::Native(ref native_tx) = tx.unsigned {
            if let Action::Call(to) = native_tx.action() {
                if to.is_contract_address() {
                    let sponsor = match ty {
                        SponsoredType::Gas => {
                            self.state.sponsor_for_gas(&to)?
                        }
                        SponsoredType::Collateral => {
                            self.state.sponsor_for_collateral(&to)?
                        }
                    };
                    let has_sponsor = sponsor.map_or(false, |x| !x.is_zero());

                    if has_sponsor
                        && self.state.check_contract_whitelist(
                            &to,
                            &tx.sender().address,
                        )?
                    {
                        return Ok(Some(*to));
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn transact_virtual(
        &mut self, mut tx: SignedTransaction, request: EstimateRequest,
    ) -> DbResult<(ExecutionOutcome, EstimateExt)> {
        if let Some(outcome) = self.check_cip130(&tx, &request) {
            return Ok(outcome);
        }

        self.process_estimate_request(&mut tx, &request)?;

        let (executed, overwrite_storage_limit) = match self
            .two_pass_estimation(&tx, request)?
        {
            Ok(x) => x,
            Err(execution) => {
                let estimate_ext = match &execution {
                    ExecutionOutcome::NotExecutedDrop(_)
                    | ExecutionOutcome::NotExecutedToReconsiderPacking(_) => {
                        EstimateExt::default()
                    }
                    ExecutionOutcome::ExecutionErrorBumpNonce(_, executed) => {
                        EstimateExt {
                            estimated_gas_limit: estimated_gas_limit(
                                executed, &tx,
                            ),
                            estimated_storage_limit: storage_limit(executed),
                        }
                    }
                    ExecutionOutcome::Finished(_) => unreachable!(),
                };
                return Ok((execution, estimate_ext));
            }
        };

        self.enact_executed_by_estimation_request(
            tx,
            executed,
            overwrite_storage_limit,
            &request,
        )
    }

    fn check_cip130(
        &self, tx: &SignedTransaction, request: &EstimateRequest,
    ) -> Option<(ExecutionOutcome, EstimateExt)> {
        let min_gas_limit = U256::from(tx.data().len() * 100);
        if !request.has_gas_limit || *tx.gas_limit() >= min_gas_limit {
            return None;
        }

        let outcome = ExecutionOutcome::NotExecutedDrop(
            cfx_executor::executive::TxDropError::NotEnoughGasLimit {
                expected: min_gas_limit,
                got: *tx.gas_limit(),
            },
        );
        let estimation = Default::default();

        Some((outcome, estimation))
    }

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
    fn two_pass_estimation(
        &mut self, tx: &SignedTransaction, request: EstimateRequest,
    ) -> DbResult<Result<(Executed, Option<u64>), ExecutionOutcome>> {
        // First pass
        let saved = self.state.save();
        let sender_pay_executed = match self
            .as_executive()
            .transact(&tx, request.first_pass_options())?
        {
            ExecutionOutcome::Finished(executed) => executed,
            res => {
                return Ok(Err(res));
            }
        };
        debug!(
            "Transaction estimate first pass outcome {:?}",
            sender_pay_executed
        );
        self.state.restore(saved);

        // Second pass
        let contract_pay_executed: Option<Executed>;
        let collateral_sponsored_contract_if_eligible_sender = self
            .sponsored_contract_if_eligible_sender(
                &tx,
                SponsoredType::Collateral,
            )?;

        let contract_pay_executed =
            if collateral_sponsored_contract_if_eligible_sender.is_some() {
                let saved = self.state.save();
                let res = self
                    .as_executive()
                    .transact(&tx, request.second_pass_options())?;
                self.state.restore(saved);

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
                contract_pay_executed
            } else {
                return Ok(Ok((sender_pay_executed, None)));
            };

        let contract_address =
            collateral_sponsored_contract_if_eligible_sender.unwrap();

        let sponsor_balance_for_collateral = self
            .state
            .sponsor_balance_for_collateral(&contract_address)?
            + self
                .state
                .available_storage_points_for_collateral(&contract_address)?;
        let max_sponsor_storage_limit = (sponsor_balance_for_collateral
            / *DRIPS_PER_STORAGE_COLLATERAL_UNIT)
            .as_u64();
        // In some cases we need to overwrite the storage limit to overcome
        // sponsor_balance_for_collateral.
        let overwrite_storage_limit = max(
            storage_limit(&sender_pay_executed),
            max_sponsor_storage_limit + 64,
        );
        Ok(Ok(
            if let Some(contract_pay_executed) = contract_pay_executed {
                if max_sponsor_storage_limit
                    >= storage_limit(&contract_pay_executed)
                {
                    (contract_pay_executed, None)
                } else {
                    (sender_pay_executed, Some(overwrite_storage_limit))
                }
            } else {
                (sender_pay_executed, Some(overwrite_storage_limit))
            },
        ))
    }

    fn enact_executed_by_estimation_request(
        &self, tx: SignedTransaction, mut executed: Executed,
        overwrite_storage_limit: Option<u64>, request: &EstimateRequest,
    ) -> DbResult<(ExecutionOutcome, EstimateExt)> {
        let estimated_storage_limit =
            overwrite_storage_limit.unwrap_or(storage_limit(&executed));
        let estimated_gas_limit = estimated_gas_limit(&executed, &tx);
        let estimation = EstimateExt {
            estimated_storage_limit,
            estimated_gas_limit,
        };

        let gas_sponsored_contract_if_eligible_sender = self
            .sponsored_contract_if_eligible_sender(&tx, SponsoredType::Gas)?;

        if gas_sponsored_contract_if_eligible_sender.is_none()
            && executed.gas_sponsor_paid
            && request.has_gas_price
        {
            executed.gas_sponsor_paid = false;
        }

        if !request.has_gas_limit {
            executed.gas_used = estimated_gas_limit;
            executed.gas_charged = estimated_gas_limit;
            executed.fee = estimated_gas_limit.mul(tx.gas_price());
        }

        // If we don't charge gas, recheck the current gas_fee is ok for
        // sponsorship.
        if !request.charge_gas()
            && request.has_gas_price
            && executed.gas_sponsor_paid
        {
            let contract = gas_sponsored_contract_if_eligible_sender.unwrap();
            let enough_balance = executed.fee
                <= self.state.sponsor_balance_for_gas(&contract)?;
            let enough_bound =
                executed.fee <= self.state.sponsor_gas_bound(&contract)?;
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
                    estimated_gas_limit.saturating_mul(*tx.gas_price())
                } else {
                    0.into()
                };
            let storage_collateral = if !executed.storage_sponsor_paid {
                U256::from(estimated_storage_limit)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                0.into()
            };
            let value_and_fee = tx
                .value()
                .saturating_add(gas_fee)
                .saturating_add(storage_collateral);
            let balance = self.state.balance(&tx.sender())?;
            if balance < value_and_fee {
                return Ok((
                    ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::NotEnoughCash {
                            required: value_and_fee.into(),
                            got: balance.into(),
                            actual_gas_cost: min(balance, gas_fee),
                            max_storage_limit_cost: storage_collateral,
                        },
                        executed,
                    ),
                    estimation,
                ));
            }
        }

        if request.has_storage_limit {
            let storage_limit = tx.storage_limit().unwrap();
            if storage_limit < estimated_storage_limit {
                return Ok((
                    ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::VmError(vm::Error::ExceedStorageLimit),
                        executed,
                    ),
                    estimation,
                ));
            }
        }

        // Revise the gas used in result, if we estimate the transaction with a
        // default large enough gas.
        if !request.has_gas_limit {
            executed.gas_charged = max(
                estimated_gas_limit - estimated_gas_limit / 4,
                executed.gas_used,
            );
            executed.fee = executed.gas_charged.saturating_mul(*tx.gas_price());
        }

        return Ok((ExecutionOutcome::Finished(executed), estimation));
    }
}

fn estimated_gas_limit(executed: &Executed, tx: &SignedTransaction) -> U256 {
    let cip130_min_gas_limit = U256::from(tx.data().len() * 100);
    let estimated =
        executed.ext_result.get::<GasLimitEstimation>().unwrap() * 7 / 6
            + executed.base_gas;
    U256::max(estimated, cip130_min_gas_limit)
}

fn storage_limit(executed: &Executed) -> u64 {
    executed
        .storage_collateralized
        .first()
        .map_or(0, |x| x.collaterals.as_u64())
}

pub fn decode_error<F, Addr: Display>(
    executed: &Executed, format_address: F,
) -> (String, String, Vec<String>)
where F: Fn(&Address) -> Addr {
    // When a revert exception happens, there is usually an error in
    // the sub-calls. So we return the trace
    // information for debugging contract.
    let errors = ErrorUnwind::from_executed(executed)
        .errors
        .iter()
        .map(|(addr, error)| format!("{}: {}", format_address(addr), error))
        .collect::<Vec<String>>();

    // Decode revert error
    let revert_error = string_revert_reason_decode(&executed.output);
    let revert_error = if !revert_error.is_empty() {
        format!(": {}", revert_error)
    } else {
        format!("")
    };

    // Try to fetch the innermost error.
    let innermost_error = if errors.len() > 0 {
        format!(" Innermost error is at {}.", errors[0])
    } else {
        String::default()
    };
    (revert_error, innermost_error, errors)
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

    fn transact_settings(
        self, charge_collateral: ChargeCollateral,
    ) -> TransactSettings {
        TransactSettings {
            charge_collateral,
            charge_gas: self.charge_gas(),
            check_epoch_bound: false,
            check_base_price: self.has_gas_price,
        }
    }

    fn first_pass_options(self) -> TransactOptions<Observer> {
        TransactOptions {
            observer: Observer::virtual_call(),
            settings: self.transact_settings(ChargeCollateral::EstimateSender),
        }
    }

    pub fn second_pass_options(self) -> TransactOptions<Observer> {
        TransactOptions {
            observer: Observer::virtual_call(),
            settings: self.transact_settings(ChargeCollateral::EstimateSponsor),
        }
    }
}
