use super::executed::{revert_reason_decode, Executed};
use crate::{
    internal_contract::{
        make_staking_events, recover_phantom, PhantomTransaction,
    },
    observer::trace::ExecTrace,
    unwrap_or_return_default,
};
use cfx_types::{Address, H256, U256, U512};
use cfx_vm_types as vm;
use pow_types::StakingEvent;
use primitives::{
    log_entry::build_bloom, receipt::StorageChange, LogEntry, Receipt,
    SignedTransaction, TransactionOutcome,
};

#[derive(Debug)]
pub enum ExecutionOutcome {
    NotExecutedDrop(TxDropError),
    NotExecutedToReconsiderPacking(ToRepackError),
    ExecutionErrorBumpNonce(ExecutionError, Executed),
    Finished(Executed),
}
use ExecutionOutcome::*;

pub struct ProcessTxOutcome {
    pub receipt: Receipt,
    pub phantom_txs: Vec<PhantomTransaction>,
    pub tx_traces: Vec<ExecTrace>,
    pub tx_staking_events: Vec<StakingEvent>,
    pub tx_exec_error_msg: String,
    pub consider_repacked: bool,
}

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
}

#[derive(Debug)]
pub enum TxDropError {
    /// The account nonce in world-state is larger than tx nonce
    OldNonce(U256, U256),

    /// The recipient of current tx is in invalid address field.
    /// Although it can be verified in tx packing,
    /// by spec doc, it is checked in execution.
    InvalidRecipientAddress(Address),
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
    pub fn make_process_tx_outcome(
        self, accumulated_gas_used: &mut U256, tx_hash: H256,
    ) -> ProcessTxOutcome {
        let tx_traces = self.tx_traces();
        let tx_exec_error_msg = self.error_message();
        let consider_repacked = self.consider_repacked();
        let receipt = self.make_receipt(accumulated_gas_used);

        let tx_staking_events = make_staking_events(receipt.logs());

        let phantom_txs = recover_phantom(&receipt.logs(), tx_hash);

        ProcessTxOutcome {
            receipt,
            phantom_txs,
            tx_traces,
            tx_staking_events,
            tx_exec_error_msg,
            consider_repacked,
        }
    }

    #[inline]
    pub fn make_receipt(self, accumulated_gas_used: &mut U256) -> Receipt {
        *accumulated_gas_used += self.gas_used();

        let gas_fee = self.gas_fee();
        let gas_sponsor_paid = self.gas_sponsor_paid();
        let storage_sponsor_paid = self.storage_sponsor_paid();

        let tx_outcome_status = self.outcome_status();
        let transaction_logs = self.transaction_logs();
        let storage_collateralized = self.storage_collateralized();
        let storage_released = self.storage_released();

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
    fn try_as_executed(&self) -> Option<&Executed> {
        match self {
            NotExecutedDrop(_) | NotExecutedToReconsiderPacking(_) => None,
            ExecutionErrorBumpNonce(_, executed) | Finished(executed) => {
                Some(executed)
            }
        }
    }

    #[inline]
    pub fn gas_fee(&self) -> U256 {
        let executed = unwrap_or_return_default!(self.try_as_executed());
        executed.fee
    }

    #[inline]
    pub fn gas_used(&self) -> U256 {
        let executed = unwrap_or_return_default!(self.try_as_executed());
        executed.gas_used
    }

    #[inline]
    pub fn tx_traces(&self) -> Vec<ExecTrace> {
        let executed = unwrap_or_return_default!(self.try_as_executed());
        executed.trace.clone()
    }

    #[inline]
    pub fn gas_sponsor_paid(&self) -> bool {
        let executed = unwrap_or_return_default!(self.try_as_executed());
        executed.gas_sponsor_paid
    }

    #[inline]
    pub fn storage_sponsor_paid(&self) -> bool {
        let executed = unwrap_or_return_default!(self.try_as_executed());
        executed.storage_sponsor_paid
    }

    #[inline]
    pub fn transaction_logs(&self) -> Vec<LogEntry> {
        let executed =
            unwrap_or_return_default!(self.try_as_success_executed());
        executed.logs.clone()
    }

    #[inline]
    pub fn storage_collateralized(&self) -> Vec<StorageChange> {
        let executed =
            unwrap_or_return_default!(self.try_as_success_executed());
        executed.storage_collateralized.clone()
    }

    #[inline]
    pub fn storage_released(&self) -> Vec<StorageChange> {
        let executed =
            unwrap_or_return_default!(self.try_as_success_executed());
        executed.storage_released.clone()
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
                    let revert_reason = revert_reason_decode(&executed.output);
                    format!("Vm reverted, {}", revert_reason)
                } else {
                    format!("{:?}", error)
                }
            }
            Finished(_) => "".into(),
        }
    }

    #[inline]
    pub fn outcome_status(&self) -> TransactionOutcome {
        match self {
            NotExecutedDrop(_) | NotExecutedToReconsiderPacking(_) => {
                TransactionOutcome::Skipped
            }
            ExecutionErrorBumpNonce(_, _) => TransactionOutcome::Failure,
            Finished(_) => TransactionOutcome::Success,
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
