use super::super::error::{StateMismatch, TestErrorKind};
use cfx_executor::{
    executive::{
        execution_outcome::ToRepackError, Executed, ExecutionOutcome,
        TxDropError,
    },
    state::State,
};
use cfx_types::{AddressSpaceUtil, U256};
use cfxkey::Address;
use primitives::SignedTransaction;
use statetest_types::{AccountInfo, TestUnit};
use std::collections::HashMap;

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
        Finished(executed) => Some(dbg!(executed)),
        NotExecutedDrop(_) => None,
        NotExecutedToReconsiderPacking(_) => None,
        ExecutionErrorBumpNonce(_, executed) => Some(executed),
    })
}

fn match_fail_reason(reason: &str, outcome: &ExecutionOutcome) -> bool {
    use ExecutionOutcome::*;
    // TODO: check consistency of exception

    match reason {
        "TransactionException.INTRINSIC_GAS_TOO_LOW" => matches!(
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

pub fn check_execution_outcome(
    tx: &SignedTransaction, executed: &Executed, state: &State,
    unit: &TestUnit, expected_state: &HashMap<Address, AccountInfo>,
) -> Result<(), TestErrorKind> {
    for (&addr, account_info) in expected_state {
        // TODO: temp skip coinbase address check
        if addr == unit.env.current_coinbase {
            continue;
        }
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
    }

    Ok(())
}
