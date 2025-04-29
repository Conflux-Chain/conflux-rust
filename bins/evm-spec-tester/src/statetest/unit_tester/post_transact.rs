use super::super::error::{StateMismatch, TestErrorKind};
use cfx_executor::{
    executive::{
        execution_outcome::ToRepackError, Executed, ExecutionOutcome,
        TxDropError,
    },
    state::{CleanupMode, State},
};
use cfx_types::{AddressSpaceUtil, AddressWithSpace, Space, U256};
use cfxkey::Address;
use eest_types::{AccountInfo, StateTestUnit};
use primitives::{transaction::TransactionError, SignedTransaction};
use std::collections::HashMap;

const INTRINSIC_GAS_TOO_LOW: &str =
    "TransactionException.INTRINSIC_GAS_TOO_LOW";

macro_rules! bail {
    ($e:expr) => {
        return Err($e.into())
    };
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
        } else if match_fail_reason(&*fail_reason, &outcome) {
            Ok(None)
        } else {
            Err(TestErrorKind::InconsistentError {
                outcome,
                fail_reason: fail_reason.clone(),
            })
        };
    }

    Ok(match outcome {
        Finished(executed) => Some(executed),
        NotExecutedDrop(_) => None,
        NotExecutedToReconsiderPacking(_) => None,
        ExecutionErrorBumpNonce(_, executed) => Some(executed),
    })
}

fn match_fail_reason(reason: &str, outcome: &ExecutionOutcome) -> bool {
    use ExecutionOutcome::*;
    // TODO: check consistency of exception

    match reason {
        INTRINSIC_GAS_TOO_LOW => matches!(
            outcome,
            NotExecutedDrop(TxDropError::NotEnoughGasLimit { .. })
        ),
        "TransactionException.SENDER_NOT_EOA" => matches!(
            outcome,
            NotExecutedDrop(TxDropError::SenderWithCode { .. })
        ),
        "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS" => matches!(
            outcome,
            NotExecutedToReconsiderPacking(
                ToRepackError::NotEnoughBaseFee { .. }
            )
        ),
        _ => false,
    }
}

pub fn match_common_check_error(
    check: Result<(), TransactionError>, expect_exception: Option<&String>,
) -> Result<bool, TestErrorKind> {
    match (check, expect_exception.map(|v| v.as_str())) {
        (Ok(_), None) => Ok(true),
        (Ok(_), Some(_)) => {
            // expect_exception will be check again in extract_executed
            Ok(true)
        }
        (Err(e), None) => Err(TestErrorKind::CommonCheckError { tx_error: e }),
        (
            Err(TransactionError::NotEnoughBaseGas {
                required: _,
                got: _,
            }),
            Some(INTRINSIC_GAS_TOO_LOW),
        ) => Ok(false),
        (Err(e), Some(expect)) => {
            trace!("expect exception: {} actually: {}", expect, e);
            Ok(false)
        }
    }
}

pub fn check_execution_outcome(
    tx: &SignedTransaction, executed: &Executed, state: &State,
    unit: &StateTestUnit, expected_state: &HashMap<Address, AccountInfo>,
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
                if expected_gas_used != executed.gas_used {
                    bail!(StateMismatch::GasMismatch {
                        got: executed.gas_used,
                        expected: expected_gas_used,
                    });
                }
            }

            bail!(StateMismatch::BalanceMismatch {
                got: got_balance,
                expected: expected_balance,
            });
        }

        // nonce check
        let expected_nonce = U256::from(account_info.nonce);
        let got_nonce = state.nonce(&user_addr).unwrap_or_default();
        if got_nonce != expected_nonce {
            bail!(StateMismatch::NonceMismatch {
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
    state: &mut State, executed: &Executed, miner: &Address, space: Space,
) {
    let to_add = match executed.burnt_fee {
        Some(burnt_fee) => executed.fee - burnt_fee,
        None => executed.fee,
    };
    let miner = AddressWithSpace {
        address: miner.clone(),
        space,
    };
    state
        .add_balance(&miner, &to_add, CleanupMode::NoEmpty)
        .expect("should success");
}
