use super::{
    execution_outcome::{ExecutionOutcome, ToRepackError, TxDropError},
    gas_required_for,
    transact_options::{ChargeCollateral, TransactOptions, TransactSettings},
    ExecutiveContext, PreCheckedExecutive,
};
use crate::{
    executive::eip7623_required_gas, executive_observer::ExecutiveObserver,
    substate::Substate,
};
use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;

use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, Space, U256, U512};
use cfx_vm_types::extract_7702_payload;
use primitives::{transaction::Action, SignedTransaction, Transaction};

macro_rules! early_return_on_err {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(exec_outcom) => {
                return Ok(Err(exec_outcom));
            }
        }
    };
}

pub struct FreshExecutive<'a, O: ExecutiveObserver> {
    context: ExecutiveContext<'a>,
    tx: &'a SignedTransaction,
    observer: O,
    settings: TransactSettings,
}

pub(super) struct CostInfo {
    /// Sender balance
    pub sender_balance: U512,
    /// The intrinsic gas (21000/53000 + tx data gas + access list gas +
    /// authorization list gas)
    pub base_gas: u64,
    /// The floor gas from EIP-7623
    pub floor_gas: u64,

    /// Transaction value + gas cost (except the sponsored part)
    pub total_cost: U512,
    /// Gas cost
    pub gas_cost: U512,
    /// Storage collateral cost
    pub storage_cost: U256,
    /// Transaction value + gas cost (except the part that eligible for
    /// sponsor)
    pub sender_intended_cost: U512,
    /// Effective gas price
    pub gas_price: U256,
    /// Burnt gas price
    pub burnt_gas_price: U256,

    /// Transaction's gas is sponsored
    pub gas_sponsored: bool,
    /// Transaction's collateral is sponsored
    pub storage_sponsored: bool,
    /// Transaction's gas is in the sponsor whitelist
    pub storage_sponsor_eligible: bool,
}

impl<'a, O: ExecutiveObserver> FreshExecutive<'a, O> {
    pub fn new(
        context: ExecutiveContext<'a>, tx: &'a SignedTransaction,
        options: TransactOptions<O>,
    ) -> Self {
        let TransactOptions {
            observer, settings, ..
        } = options;
        FreshExecutive {
            context,
            tx,
            observer,
            settings,
        }
    }

    pub(super) fn check_all(
        self,
    ) -> DbResult<Result<PreCheckedExecutive<'a, O>, ExecutionOutcome>> {
        early_return_on_err!(self.check_base_price());
        // Validate transaction nonce
        early_return_on_err!(self.check_nonce()?);

        if self.context.spec.cip152 && self.settings.forbid_eoa_with_code {
            early_return_on_err!(self.check_from_eoa_with_code()?);
        }

        // Validate transaction epoch height.
        if self.settings.check_epoch_bound {
            early_return_on_err!(self.check_epoch_bound()?);
        }

        let cost = early_return_on_err!(self.compute_cost_info()?);

        if self.context.spec.align_evm {
            early_return_on_err!(self.check_enough_balance(&cost));
        }

        early_return_on_err!(self.check_sender_exist(&cost)?);

        Ok(Ok(self.into_pre_checked(cost)))
    }

    fn into_pre_checked(self, cost: CostInfo) -> PreCheckedExecutive<'a, O> {
        PreCheckedExecutive {
            context: self.context,
            tx: self.tx,
            observer: self.observer,
            settings: self.settings,
            cost,
            substate: Substate::new(),
        }
    }
}

impl<'a, O: ExecutiveObserver> FreshExecutive<'a, O> {
    fn check_nonce(&self) -> DbResult<Result<(), ExecutionOutcome>> {
        let tx = self.tx;
        let nonce = self.context.state.nonce(&tx.sender())?;
        Ok(if *tx.nonce() < nonce {
            Err(ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(
                nonce,
                *tx.nonce(),
            )))
        } else if *tx.nonce() > nonce {
            Err(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::InvalidNonce {
                    expected: nonce,
                    got: *tx.nonce(),
                },
            ))
        } else {
            Ok(())
        })
    }

    fn check_from_eoa_with_code(
        &self,
    ) -> DbResult<Result<(), ExecutionOutcome>> {
        let sender = self.tx.sender();
        let Some(code) = self.context.state.code(&sender)? else {
            // EOA with no code
            return Ok(Ok(()));
        };

        if code.is_empty() {
            // Empty code
            return Ok(Ok(()));
        }

        if self.tx.space() == Space::Ethereum
            && extract_7702_payload(&code).is_some()
        {
            // 7702 code in eSpace is allowed
            return Ok(Ok(()));
        }

        // extract_7702_payload
        Ok(Err(ExecutionOutcome::NotExecutedDrop(
            TxDropError::SenderWithCode(sender.address),
        )))
    }

    fn check_base_price(&self) -> Result<(), ExecutionOutcome> {
        if !self.settings.check_base_price {
            return Ok(());
        }

        let burnt_gas_price = self.context.env.burnt_gas_price[self.tx.space()];
        if self.tx.gas_price() < &burnt_gas_price {
            Err(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::NotEnoughBaseFee {
                    expected: burnt_gas_price,
                    got: *self.tx.gas_price(),
                },
            ))
        } else {
            Ok(())
        }
    }

    fn check_epoch_bound(&self) -> DbResult<Result<(), ExecutionOutcome>> {
        let tx = if let Transaction::Native(ref tx) =
            self.tx.transaction.transaction.unsigned
        {
            tx
        } else {
            return Ok(Ok(()));
        };

        let env = self.context.env;

        if tx.epoch_height().abs_diff(env.epoch_height)
            > env.transaction_epoch_bound
        {
            Ok(Err(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::EpochHeightOutOfBound {
                    block_height: env.epoch_height,
                    set: *tx.epoch_height(),
                    transaction_epoch_bound: env.transaction_epoch_bound,
                },
            )))
        } else {
            Ok(Ok(()))
        }
    }

    fn check_sender_exist(
        &self, cost: &CostInfo,
    ) -> DbResult<Result<(), ExecutionOutcome>> {
        if !cost.sender_intended_cost.is_zero()
            && !self.context.state.exists(&self.tx.sender())?
        {
            // We don't want to bump nonce for non-existent account when we
            // can't charge gas fee. In this case, the sender account will
            // not be created if it does not exist.
            return Ok(Err(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::SenderDoesNotExist,
            )));
        }
        Ok(Ok(()))
    }

    // In the EVM, when the transaction sender's balance is insufficient to
    // cover the required `gas fee + transfer value`, the transaction does not
    // bump the nonce or charge a fee, which differs from Conflux. This function
    // is only used for `align_evm` testing to simulate this EVM behavior.
    fn check_enough_balance(
        &self, cost: &CostInfo,
    ) -> Result<(), ExecutionOutcome> {
        if cost.sender_balance < cost.sender_intended_cost {
            Err(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::NotEnoughBalance {
                    expected: cost.sender_intended_cost,
                    got: cost.sender_balance.try_into().unwrap(),
                },
            ))
        } else {
            Ok(())
        }
    }

    fn compute_cost_info(
        &self,
    ) -> DbResult<Result<CostInfo, ExecutionOutcome>> {
        let tx = self.tx;
        let settings = self.settings;
        let sender = tx.sender();
        let state = &self.context.state;
        let env = self.context.env;
        let spec = self.context.spec;

        let base_gas = gas_required_for(
            tx.action() == Action::Create,
            &tx.data(),
            tx.access_list(),
            tx.authorization_len(),
            &spec.to_consensus_spec(),
        );

        let floor_gas =
            eip7623_required_gas(&tx.data(), &spec.to_consensus_spec());

        let minimum_tx_gas = u64::max(base_gas, floor_gas);

        if *tx.gas() < minimum_tx_gas.into() {
            return Ok(Err(ExecutionOutcome::NotExecutedDrop(
                TxDropError::NotEnoughGasLimit {
                    expected: minimum_tx_gas.into(),
                    got: *tx.gas(),
                },
            )));
        }

        let check_base_price = self.settings.check_base_price;

        let gas_price = if !spec.cip1559 || !check_base_price {
            *tx.gas_price()
        } else {
            // actual_base_gas >= tx gas_price >= burnt_base_price
            let actual_base_gas =
                U256::min(*tx.gas_price(), env.base_gas_price[tx.space()]);
            tx.effective_gas_price(&actual_base_gas)
        };
        let max_gas_price = *tx.gas_price();

        let burnt_gas_price = env.burnt_gas_price[tx.space()];
        // gas_price >= actual_base_gas >=
        // either 1. tx gas_price >= burnt_gas_price
        // or     2. base_gas_price >= burnt_gas_price
        assert!(gas_price >= burnt_gas_price || !check_base_price);

        let sender_balance = U512::from(state.balance(&sender)?);
        let gas_cost = if settings.charge_gas {
            tx.gas().full_mul(gas_price)
        } else {
            0.into()
        };

        // EIP-1559 requires the user balance can afford "max gas price * gas limit", instead of "effective gas price * gas limit", this variable represents "(effective gas price - max gas price) * gas limit"
        let additional_gas_required_1559 = if settings.charge_gas && spec.cip645
        {
            (max_gas_price - gas_price).full_mul(*tx.gas_limit())
        } else {
            0.into()
        };
        let storage_cost =
            if let (Transaction::Native(tx), ChargeCollateral::Normal) = (
                &tx.transaction.transaction.unsigned,
                settings.charge_collateral,
            ) {
                U256::from(*tx.storage_limit())
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                U256::zero()
            };

        if sender.space == Space::Ethereum {
            assert_eq!(storage_cost, U256::zero());
            let sender_cost = U512::from(tx.value()) + gas_cost;
            let sender_intended_cost =
                sender_cost + additional_gas_required_1559;
            return Ok(Ok(CostInfo {
                sender_balance,
                base_gas,
                floor_gas,
                gas_cost,
                gas_price,
                burnt_gas_price,
                storage_cost,
                sender_intended_cost,
                total_cost: sender_cost,
                gas_sponsored: false,
                storage_sponsored: false,
                storage_sponsor_eligible: false,
            }));
        }

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
            if state.is_contract_with_code(&address.with_native_space())? {
                code_address = *address;
                if state
                    .check_contract_whitelist(&code_address, &sender.address)?
                {
                    // No need to check for gas sponsor account existence.
                    gas_sponsor_eligible = gas_cost
                        + additional_gas_required_1559
                        <= U512::from(state.sponsor_gas_bound(&code_address)?);
                    storage_sponsor_eligible =
                        state.sponsor_for_collateral(&code_address)?.is_some();
                }
            }
        }

        let code_address = code_address;
        let gas_sponsor_eligible = gas_sponsor_eligible;
        let storage_sponsor_eligible = storage_sponsor_eligible;

        // Sender pays for gas when sponsor runs out of balance.
        let sponsor_balance_for_gas =
            U512::from(state.sponsor_balance_for_gas(&code_address)?);
        let gas_sponsored =
            gas_sponsor_eligible && sponsor_balance_for_gas >= gas_cost;

        let sponsor_balance_for_storage = state
            .sponsor_balance_for_collateral(&code_address)?
            + state.available_storage_points_for_collateral(&code_address)?;
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
                sender_intended_cost += gas_cost + additional_gas_required_1559;
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

        return Ok(Ok(CostInfo {
            sender_intended_cost,
            base_gas,
            floor_gas,
            gas_cost,
            gas_price,
            burnt_gas_price,
            storage_cost,
            sender_balance,
            total_cost,
            gas_sponsored,
            storage_sponsored,
            // Only for backward compatible for a early bug.
            // The receipt reported `storage_sponsor_eligible` instead of
            // `storage_sponsored`.
            storage_sponsor_eligible,
        }));
    }
}
