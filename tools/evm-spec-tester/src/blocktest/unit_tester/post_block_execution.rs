use crate::{bail, StateMismatch, TestErrorKind};
use cfx_executor::state::State;
use cfx_types::{Address, AddressSpaceUtil, U256};
use eest_types::AccountInfo;
use std::collections::HashMap;

pub fn check_expected_state(
    state: &State, expected_state: &HashMap<Address, AccountInfo>,
) -> Result<(), TestErrorKind> {
    for (&addr, account_info) in expected_state {
        let user_addr = addr.with_evm_space();

        // balance check
        let expected_balance = account_info.balance;
        let got_balance = state.balance(&user_addr).unwrap_or_default();
        if got_balance != expected_balance {
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
                    address: addr,
                    key,
                    got: curr_value,
                    expected: value,
                });
            }
        }
    }

    Ok(())
}
