use super::super::error::{StateMismatch, TestErrorKind};
use cfx_executor::{
    executive::{
        execution_outcome::ToRepackError, Executed, ExecutionError,
        ExecutionOutcome, TxDropError,
    },
    state::{CleanupMode, State},
};
use cfx_types::{AddressSpaceUtil, AddressWithSpace, Space, U256};
use cfxkey::Address;
use eest_types::{AccountInfo, StateTestUnit};
use primitives::{transaction::TransactionError, SignedTransaction};
use std::collections::HashMap;

macro_rules! bail {
    ($e:expr) => {
        return Err($e.into())
    };
}

#[derive(Clone, Copy)]
pub enum TestOutcome<'a> {
    Consensus(&'a TransactionError),
    Execution(&'a ExecutionOutcome),
}

pub fn extract_executed(
    outcome: ExecutionOutcome, expect_exception: Option<&String>,
) -> Result<Option<Executed>, TestErrorKind> {
    use ExecutionOutcome::*;

    if let Some(fail_reason) = expect_exception {
        return if let Finished(_) = outcome {
            Err(TestErrorKind::ShouldFail {
                fail_reason: fail_reason.clone(),
            })
        } else if match_fail_reason(
            &*fail_reason,
            TestOutcome::Execution(&outcome),
        ) {
            Ok(outcome.try_into_executed())
            // Ok(None)
        } else {
            Err(TestErrorKind::InconsistentError {
                outcome,
                fail_reason: fail_reason.clone(),
            })
        };
    }

    match outcome {
        Finished(executed) => Ok(Some(executed)),
        NotExecutedDrop(_) | NotExecutedToReconsiderPacking(_) => {
            Err(TestErrorKind::ExecutionError { outcome })
        }
        ExecutionErrorBumpNonce(_, executed) => {
            // The post-execution validation will detect that the execution has
            // reverted because the expected post-execution state indicates a
            // failure, even if the test cases do not explicitly
            // specify an error message.
            Ok(Some(executed))
        }
    }
}

pub fn process_consensus_check_fail(
    error: TransactionError, expect_exception: Option<&String>,
) -> Result<(), TestErrorKind> {
    if let Some(fail_reason) = expect_exception {
        if match_fail_reason(fail_reason, TestOutcome::Consensus(&error)) {
            Ok(())
        } else {
            Err(TestErrorKind::InconsistentErrorConsensus {
                error,
                fail_reason: fail_reason.clone(),
            })
        }
    } else {
        Err(error.into())
    }
}

fn match_fail_reason(reason: &str, outcome: TestOutcome<'_>) -> bool {
    reason
        .split("|")
        .any(|reason| match_fail_single_reason(reason, outcome))
}

pub fn is_unsupport_reason(expected_reason: &Option<String>) -> bool {
    let Some(reason) = expected_reason.as_ref() else {
        return false;
    };
    match &**reason {
        // Consensus level error
        "TransactionException.GAS_ALLOWANCE_EXCEEDED" => true,
        _ => false,
    }
}

fn match_fail_single_reason(reason: &str, outcome: TestOutcome<'_>) -> bool {
    use ExecutionOutcome::*;
    use TestOutcome::*;
    match reason {
        "TransactionException.INITCODE_SIZE_EXCEEDED" => matches!(
            outcome,
            Consensus(TransactionError::CreateInitCodeSizeLimit)
        ),
        "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS" => matches!(
            outcome,
            Execution(
                ExecutionErrorBumpNonce(
                    ExecutionError::NotEnoughCash { .. },
                    _
                ) | NotExecutedToReconsiderPacking(
                    ToRepackError::SenderDoesNotExist
                        | ToRepackError::NotEnoughBalance { .. }
                )
            )
        ),
        "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS" => matches!(
            outcome,
            Execution(NotExecutedToReconsiderPacking(
                ToRepackError::NotEnoughBaseFee { .. }
            ))
        ),
        "TransactionException.INTRINSIC_GAS_TOO_LOW" => matches!(
            outcome,
            Execution(NotExecutedDrop(TxDropError::NotEnoughGasLimit { .. }))
                | Consensus(TransactionError::NotEnoughBaseGas { .. })
        ),
        "TransactionException.NONCE_IS_MAX" => matches!(
            outcome,
            Execution(ExecutionErrorBumpNonce(
                ExecutionError::NonceOverflow(_),
                _
            ))
        ),
        "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS" => {
            matches!(
                outcome,
                Consensus(TransactionError::PriortyGreaterThanMaxFee)
            )
        }
        "TransactionException.SENDER_NOT_EOA" => matches!(
            outcome,
            Execution(NotExecutedDrop(TxDropError::SenderWithCode { .. }))
        ),
        "TransactionException.TYPE_4_EMPTY_AUTHORIZATION_LIST" => matches!(
            outcome,
            Consensus(TransactionError::EmptyAuthorizationList)
        ),
        _ => false,
    }
}

pub fn check_execution_outcome(
    tx: &SignedTransaction, state: &State, unit: &StateTestUnit,
    expected_state: &HashMap<Address, AccountInfo>, gas_used: U256,
) -> Result<(), TestErrorKind> {
    for (&addr, account_info) in expected_state {
        let user_addr = addr.with_evm_space();

        // balance check
        let expected_balance = account_info.balance;
        let got_balance = state.balance(&user_addr).unwrap_or_default();
        if got_balance != expected_balance {
            // log the gas usage
            if user_addr == tx.sender() && tx.value().is_zero() {
                let before_balance =
                    unit.pre.get(&addr).map(|v| v.balance).unwrap_or_default();
                let expected_gas_used =
                    (before_balance - expected_balance) / tx.gas_price();
                if expected_gas_used != gas_used {
                    bail!(StateMismatch::GasMismatch {
                        got: gas_used,
                        expected: expected_gas_used,
                    });
                }
            }

            bail!(StateMismatch::BalanceMismatch {
                address: user_addr.address,
                got: got_balance,
                expected: expected_balance,
            });
        }

        // nonce check
        let expected_nonce = U256::from(account_info.nonce);
        let got_nonce = state.nonce(&user_addr).unwrap_or_default();
        if got_nonce != expected_nonce {
            bail!(StateMismatch::NonceMismatch {
                address: user_addr.address,
                got: got_nonce,
                expected: expected_nonce,
            })
        }

        // code check
        let got_code = match state.code(&user_addr) {
            Ok(Some(v)) => v.as_ref().to_vec(),
            _ => Default::default(),
        };
        let expected_code = account_info.code.0.clone();
        if got_code != expected_code {
            bail!(StateMismatch::CodeMismatch {
                got: hex::encode(got_code),
                expected: hex::encode(expected_code),
            });
        }

        // storage check
        for (&key, &value) in &account_info.storage {
            let mut key_bytes = [0u8; 32];
            key.to_big_endian(&mut key_bytes);
            let curr_value =
                state.storage_at(&user_addr, &key_bytes).unwrap_or_default();
            if curr_value != value {
                bail!(StateMismatch::StorageMismatch {
                    key,
                    got: curr_value,
                    expected: value,
                });
            }
        }

        // TODO: logs hash check
    }

    Ok(())
}

pub fn distribute_tx_fee_to_miner(
    state: &mut State, executed: &Executed, miner: &Address,
) {
    let to_add = match executed.burnt_fee {
        Some(burnt_fee) => executed.fee - burnt_fee,
        None => executed.fee,
    };
    let miner = AddressWithSpace {
        address: miner.clone(),
        space: Space::Ethereum,
    };
    state
        .add_balance(&miner, &to_add, CleanupMode::NoEmpty)
        .expect("should success");
}
