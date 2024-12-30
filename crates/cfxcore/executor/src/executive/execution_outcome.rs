use super::executed::Executed;
use crate::unwrap_or_return;
use cfx_types::{Address, H256, U256, U512};
use cfx_vm_types as vm;
use primitives::{
    log_entry::build_bloom, receipt::StorageChange, LogEntry, Receipt,
    SignedTransaction, TransactionStatus,
};
use solidity_abi::string_revert_reason_decode;

#[derive(Debug)]
pub enum ExecutionOutcome {
    NotExecutedDrop(TxDropError),
    NotExecutedToReconsiderPacking(ToRepackError),
    ExecutionErrorBumpNonce(ExecutionError, Executed),
    Finished(Executed),
}
use vm::Spec;
use ExecutionOutcome::*;

#[derive(Debug)]
pub enum ToRepackError {
    /// Returned when transaction nonce does not match state nonce.
    InvalidNonce {
        /// Nonce expected.
        expected: U256,
        /// Nonce found.
        got: U256,
    },

    /// Epoch height out of bound.
    /// The transaction was correct in the block where it's packed, but
    /// falls into the error when in the epoch to execute.
    EpochHeightOutOfBound {
        block_height: u64,
        set: u64,
        transaction_epoch_bound: u64,
    },

    /// Returned when cost of transaction (value + gas_price * gas) exceeds
    /// current sponsor balance.
    NotEnoughCashFromSponsor {
        /// Minimum required gas cost.
        required_gas_cost: U512,
        /// Actual balance of gas sponsor.
        gas_sponsor_balance: U512,
        /// Minimum required storage collateral cost.
        required_storage_cost: U256,
        /// Actual balance of storage sponsor.
        storage_sponsor_balance: U256,
    },

    /// Returned when a non-sponsored transaction's sender does not exist yet.
    SenderDoesNotExist,

    NotEnoughBaseFee {
        expected: U256,
        got: U256,
    },
}

#[derive(Debug)]
pub enum TxDropError {
    /// The account nonce in world-state is larger than tx nonce
    OldNonce(U256, U256),

    /// The recipient of current tx is in invalid address field.
    /// Although it can be verified in tx packing,
    /// by spec doc, it is checked in execution.
    InvalidRecipientAddress(Address),

    /// Not enough gas limit for large transacton, only for estimation
    NotEnoughGasLimit { expected: U256, got: U256 },
}

#[derive(Debug, PartialEq)]
pub enum ExecutionError {
    /// Returned when cost of transaction (value + gas_price * gas) exceeds
    /// current sender balance.
    NotEnoughCash {
        /// Minimum required balance.
        required: U512,
        /// Actual balance.
        got: U512,
        /// Actual gas cost. This should be min(gas_fee, balance).
        actual_gas_cost: U256,
        /// Maximum storage limit cost.
        max_storage_limit_cost: U256,
    },
    VmError(vm::Error),
}

impl ExecutionOutcome {
    #[inline]
    pub fn make_receipt(
        self, accumulated_gas_used: &mut U256, spec: &Spec,
    ) -> Receipt {
        *accumulated_gas_used += self.gas_used();

        let gas_fee = self.gas_fee();
        let gas_sponsor_paid = self.gas_sponsor_paid();
        let storage_sponsor_paid = self.storage_sponsor_paid();

        let tx_outcome_status = self.outcome_status();
        let transaction_logs = self.transaction_logs();
        let storage_collateralized = self.storage_collateralized();
        let storage_released = self.storage_released();

        let burnt_fee = self.burnt_fee(spec);

        let log_bloom = build_bloom(&transaction_logs);

        Receipt::new(
            tx_outcome_status,
            *accumulated_gas_used,
            gas_fee,
            gas_sponsor_paid,
            transaction_logs,
            log_bloom,
            storage_sponsor_paid,
            storage_collateralized,
            storage_released,
            burnt_fee,
        )
    }

    #[inline]
    pub fn into_success_executed(self) -> Option<Executed> {
        match self {
            ExecutionOutcome::Finished(executed) => Some(executed),
            _ => None,
        }
    }

    #[inline]
    pub fn try_as_success_executed(&self) -> Option<&Executed> {
        match self {
            ExecutionOutcome::Finished(executed) => Some(executed),
            _ => None,
        }
    }

    #[inline]
    pub fn try_as_executed(&self) -> Option<&Executed> {
        match self {
            NotExecutedDrop(_) | NotExecutedToReconsiderPacking(_) => None,
            ExecutionErrorBumpNonce(_, executed) | Finished(executed) => {
                Some(executed)
            }
        }
    }

    #[inline]
    pub fn gas_fee(&self) -> U256 {
        let executed = unwrap_or_return!(self.try_as_executed());
        executed.fee
    }

    #[inline]
    pub fn gas_used(&self) -> U256 {
        let executed = unwrap_or_return!(self.try_as_executed());
        executed.gas_used
    }

    #[inline]
    pub fn gas_sponsor_paid(&self) -> bool {
        let executed = unwrap_or_return!(self.try_as_executed());
        executed.gas_sponsor_paid
    }

    #[inline]
    pub fn storage_sponsor_paid(&self) -> bool {
        let executed = unwrap_or_return!(self.try_as_executed());
        executed.storage_sponsor_paid
    }

    #[inline]
    pub fn transaction_logs(&self) -> Vec<LogEntry> {
        let executed = unwrap_or_return!(self.try_as_success_executed());
        executed.logs.clone()
    }

    #[inline]
    pub fn storage_collateralized(&self) -> Vec<StorageChange> {
        let executed = unwrap_or_return!(self.try_as_success_executed());
        executed.storage_collateralized.clone()
    }

    #[inline]
    pub fn storage_released(&self) -> Vec<StorageChange> {
        let executed = unwrap_or_return!(self.try_as_success_executed());
        executed.storage_released.clone()
    }

    #[inline]
    pub fn burnt_fee(&self, spec: &Spec) -> Option<U256> {
        if let Some(e) = self.try_as_executed() {
            e.burnt_fee
        } else if spec.cip1559 {
            Some(U256::zero())
        } else {
            None
        }
    }

    #[inline]
    pub fn consider_repacked(&self) -> bool {
        matches!(self, NotExecutedToReconsiderPacking(_))
    }

    #[inline]
    pub fn error_message(&self) -> String {
        match self {
            NotExecutedDrop(_) | NotExecutedToReconsiderPacking(_) => {
                "tx not executed".into()
            }
            ExecutionErrorBumpNonce(error, executed) => {
                if error == &ExecutionError::VmError(vm::Error::Reverted) {
                    let revert_reason =
                        string_revert_reason_decode(&executed.output);
                    format!("Vm reverted, {}", revert_reason)
                } else {
                    format!("{:?}", error)
                }
            }
            Finished(_) => "".into(),
        }
    }

    #[inline]
    pub fn outcome_status(&self) -> TransactionStatus {
        match self {
            NotExecutedDrop(_) | NotExecutedToReconsiderPacking(_) => {
                TransactionStatus::Skipped
            }
            ExecutionErrorBumpNonce(_, _) => TransactionStatus::Failure,
            Finished(_) => TransactionStatus::Success,
        }
    }

    #[inline]
    pub fn log(&self, tx: &SignedTransaction, block_hash: &H256) {
        match self {
            ExecutionOutcome::NotExecutedDrop(e) => {
                trace!(
                    "tx not executed, not to reconsider packing: \
                     transaction={:?},err={:?}",
                    tx,
                    e
                );
            }
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                trace!(
                    "tx not executed, to reconsider packing: \
                     transaction={:?}, err={:?}",
                    tx,
                    e
                );
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(error, _) => {
                debug!(
                    "tx execution error: err={:?}, transaction={:?}",
                    error, tx
                );
            }
            ExecutionOutcome::Finished(executed) => {
                trace!("tx executed successfully: result={:?}, transaction={:?}, in block {:?}", executed, tx, block_hash);
            }
        }
    }
}
