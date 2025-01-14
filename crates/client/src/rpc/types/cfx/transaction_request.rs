// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    errors::{invalid_params, invalid_params_check},
    types::{
        address::RpcAddress,
        cfx::{
            check_rpc_address_network, check_two_rpc_address_network_match,
            to_primitive_access_list, CfxAccessList,
        },
        Bytes,
    },
    CoreResult,
};
use cfx_addr::Network;
use cfx_parameters::{
    block::{
        CIP1559_CORE_TRANSACTION_GAS_RATIO, DEFAULT_TARGET_BLOCK_GAS_LIMIT,
    },
    RATIO_BASE_TEN,
};
use cfx_types::{Address, AddressSpaceUtil, U256, U64};
use cfx_util_macros::bail;
use cfxcore_accounts::AccountProvider;
use cfxkey::Password;
use primitives::{
    transaction::{
        Action, Cip1559Transaction, Cip2930Transaction, NativeTransaction,
        TypedNativeTransaction::*, CIP1559_TYPE, CIP2930_TYPE, LEGACY_TX_TYPE,
    },
    SignedTransaction, Transaction, TransactionWithSignature,
};
use serde::{Deserialize, Serialize};
use std::{convert::Into, sync::Arc};

/// The maximum gas limit accepted by most tx pools.
pub const DEFAULT_CFX_GAS_CALL_REQUEST: u64 = DEFAULT_TARGET_BLOCK_GAS_LIMIT
    * CIP1559_CORE_TRANSACTION_GAS_RATIO
    / RATIO_BASE_TEN;

#[derive(Debug, Default, Deserialize, PartialEq, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransactionRequest {
    /// From
    pub from: Option<RpcAddress>,
    /// To
    pub to: Option<RpcAddress>,
    /// Gas Price
    pub gas_price: Option<U256>,
    /// Gas
    pub gas: Option<U256>,
    /// Value
    pub value: Option<U256>,
    /// Data
    pub data: Option<Bytes>,
    /// Nonce
    pub nonce: Option<U256>,
    /// StorageLimit
    pub storage_limit: Option<U64>,
    /// Access list in EIP-2930
    pub access_list: Option<CfxAccessList>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(rename = "type")]
    pub transaction_type: Option<U64>,
    ///
    pub chain_id: Option<U256>,
    ///
    pub epoch_height: Option<U256>,
}

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimateGasAndCollateralResponse {
    /// The recommended gas_limit.
    pub gas_limit: U256,
    /// The amount of gas used in the execution.
    pub gas_used: U256,
    /// The number of bytes collateralized in the execution.
    pub storage_collateralized: U64,
}

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckBalanceAgainstTransactionResponse {
    /// Whether the account should pay transaction fee by self.
    pub will_pay_tx_fee: bool,
    /// Whether the account should pay collateral by self.
    pub will_pay_collateral: bool,
    /// Whether the account balance is enough for this transaction.
    pub is_balance_enough: bool,
}

impl TransactionRequest {
    pub fn check_rpc_address_network(
        &self, param_name: &str, expected: &Network,
    ) -> CoreResult<()> {
        let rpc_request_network = invalid_params_check(
            param_name,
            check_two_rpc_address_network_match(
                self.from.as_ref(),
                self.to.as_ref(),
            ),
        )?;
        invalid_params_check(
            param_name,
            check_rpc_address_network(rpc_request_network, expected),
        )
        .map_err(|e| e.into())
    }

    pub fn transaction_type(&self) -> u8 {
        if let Some(tx_type) = self.transaction_type {
            tx_type.as_usize() as u8
        } else {
            if self.max_fee_per_gas.is_some()
                || self.max_priority_fee_per_gas.is_some()
            {
                CIP1559_TYPE
            } else if self.access_list.is_some() {
                CIP2930_TYPE
            } else {
                LEGACY_TX_TYPE
            }
        }
    }

    pub fn has_gas_price(&self) -> bool {
        self.gas_price.is_some()
            || self.max_fee_per_gas.is_some()
            || self.max_priority_fee_per_gas.is_some()
    }

    pub fn sign_with(
        self, epoch_height: u64, chain_id: u32, password: Option<String>,
        accounts: Arc<AccountProvider>,
    ) -> CoreResult<TransactionWithSignature> {
        let gas = self.gas.ok_or("should have gas")?;
        let nonce = self.nonce.ok_or("should have nonce")?;
        let transaction_type = self.transaction_type();
        let action = self.to.map_or(Action::Create, |rpc_addr| {
            Action::Call(rpc_addr.hex_address)
        });

        let value = self.value.unwrap_or_default();
        let storage_limit = self
            .storage_limit
            .map(|v| v.as_u64())
            .ok_or("should have storage_limit")?;
        let data = self.data.unwrap_or_default().into_vec();

        let access_list = self.access_list.unwrap_or(vec![]);

        let typed_native_tx = match transaction_type {
            LEGACY_TX_TYPE => {
                let gas_price =
                    self.gas_price.ok_or("should have gas_price")?;
                Cip155(NativeTransaction {
                    nonce,
                    action,
                    gas,
                    gas_price,
                    value,
                    storage_limit,
                    epoch_height,
                    chain_id,
                    data,
                })
            }
            CIP2930_TYPE => {
                let gas_price =
                    self.gas_price.ok_or("should have gas_price")?;
                Cip2930(Cip2930Transaction {
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    storage_limit,
                    epoch_height,
                    chain_id,
                    data,
                    access_list: to_primitive_access_list(access_list),
                })
            }
            CIP1559_TYPE => {
                let max_fee_per_gas = self
                    .max_fee_per_gas
                    .ok_or("should have max_fee_per_gas")?;
                let max_priority_fee_per_gas = self
                    .max_priority_fee_per_gas
                    .ok_or("should have max_priority_fee_per_gas")?;
                Cip1559(Cip1559Transaction {
                    nonce,
                    action,
                    gas,
                    value,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    storage_limit,
                    epoch_height,
                    chain_id,
                    data,
                    access_list: to_primitive_access_list(access_list),
                })
            }
            x => {
                return Err(
                    invalid_params("Unrecognized transaction type", x).into()
                );
            }
        };

        let tx = Transaction::Native(typed_native_tx);
        let password = password.map(Password::from);
        let sig = accounts
            .sign(
                self.from.unwrap().into(),
                password,
                tx.hash_for_compute_signature(),
            )
            // TODO: sign error into secret store error codes.
            .map_err(|e| format!("failed to sign transaction: {:?}", e))?;

        Ok(tx.with_signature(sig))
    }

    pub fn sign_call(
        self, epoch_height: u64, chain_id: u32, max_gas: Option<U256>,
    ) -> CoreResult<SignedTransaction> {
        let max_gas = max_gas.unwrap_or(DEFAULT_CFX_GAS_CALL_REQUEST.into());
        let gas = self.gas.unwrap_or(max_gas);
        if gas > max_gas {
            bail!(invalid_params(
                "gas",
                format!("specified gas is larger than max gas {:?}", max_gas)
            ))
        }
        let transaction_type = self.transaction_type();
        let nonce = self.nonce.unwrap_or_default();
        let action = self.to.map_or(Action::Create, |rpc_addr| {
            Action::Call(rpc_addr.hex_address)
        });

        let value = self.value.unwrap_or_default();
        let storage_limit = self
            .storage_limit
            .map(|v| v.as_u64())
            .unwrap_or(std::u64::MAX);
        let data = self.data.unwrap_or_default().into_vec();

        let gas_price = self.gas_price.unwrap_or(1.into());
        let max_fee_per_gas = self
            .max_fee_per_gas
            .or(self.max_priority_fee_per_gas)
            .unwrap_or(gas_price);
        let max_priority_fee_per_gas =
            self.max_priority_fee_per_gas.unwrap_or(U256::zero());
        let access_list = self.access_list.unwrap_or(vec![]);

        let transaction = match transaction_type {
            LEGACY_TX_TYPE => Cip155(NativeTransaction {
                nonce,
                action,
                gas,
                gas_price,
                value,
                storage_limit,
                epoch_height,
                chain_id,
                data,
            }),
            CIP2930_TYPE => Cip2930(Cip2930Transaction {
                nonce,
                gas_price,
                gas,
                action,
                value,
                storage_limit,
                epoch_height,
                chain_id,
                data,
                access_list: to_primitive_access_list(access_list),
            }),
            CIP1559_TYPE => Cip1559(Cip1559Transaction {
                nonce,
                action,
                gas,
                value,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                storage_limit,
                epoch_height,
                chain_id,
                data,
                access_list: to_primitive_access_list(access_list),
            }),
            x => {
                return Err(
                    invalid_params("Unrecognized transaction type", x).into()
                );
            }
        };

        let from = self
            .from
            .map_or_else(|| Address::zero(), |rpc_addr| rpc_addr.hex_address);

        Ok(transaction.fake_sign_rpc(from.with_native_space()))
    }
}

#[cfg(test)]
mod tests {
    use super::TransactionRequest;

    use crate::rpc::types::address::RpcAddress;
    use cfx_addr::Network;
    use cfx_types::{H160, U256, U64};
    use rustc_hex::FromHex;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn call_request_deserialize() {
        let expected = TransactionRequest {
            from: Some(
                RpcAddress::try_from_h160(
                    H160::from_low_u64_be(1),
                    Network::Main,
                )
                .unwrap(),
            ),
            to: Some(
                RpcAddress::try_from_h160(
                    H160::from_low_u64_be(2),
                    Network::Main,
                )
                .unwrap(),
            ),
            gas_price: Some(U256::from(1)),
            gas: Some(U256::from(2)),
            value: Some(U256::from(3)),
            data: Some(vec![0x12, 0x34, 0x56].into()),
            storage_limit: Some(U64::from_str("7b").unwrap()),
            nonce: Some(U256::from(4)),
            ..Default::default()
        };

        let s = r#"{
            "from":"CFX:TYPE.BUILTIN:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJC4EYEY6",
            "to":"CFX:TYPE.BUILTIN:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJD0WN6U9U",
            "gasPrice":"0x1",
            "gas":"0x2",
            "value":"0x3",
            "data":"0x123456",
            "storageLimit":"0x7b",
            "nonce":"0x4"
        }"#;
        let deserialized_result = serde_json::from_str::<TransactionRequest>(s);
        assert!(
            deserialized_result.is_ok(),
            "serialized str should look like {}",
            serde_json::to_string(&expected).unwrap()
        );
        assert_eq!(deserialized_result.unwrap(), expected);
    }

    #[test]
    fn call_request_deserialize2() {
        let expected = TransactionRequest {
            from: Some(RpcAddress::try_from_h160(H160::from_str("160e8dd61c5d32be8058bb8eb970870f07233155").unwrap(),  Network::Main ).unwrap()),
            to: Some(RpcAddress::try_from_h160(H160::from_str("846e8dd67c5d32be8058bb8eb970870f07244567").unwrap(), Network::Main).unwrap()),
            gas_price: Some(U256::from_str("9184e72a000").unwrap()),
            gas: Some(U256::from_str("76c0").unwrap()),
            value: Some(U256::from_str("9184e72a").unwrap()),
            storage_limit: Some(U64::from_str("3344adf").unwrap()),
            data: Some("d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675".from_hex::<Vec<u8>>().unwrap().into()),
            nonce: None,
            ..Default::default()
        };

        let s = r#"{
            "from": "CFX:TYPE.USER:AANA7DS0DVSXFTYANC727SNUU6HUSJ3VMYC3F1AY93",
            "to": "CFX:TYPE.CONTRACT:ACCG7DS0TVSXFTYANC727SNUU6HUSKCFP6KB3NFJ02",
            "gas": "0x76c0",
            "gasPrice": "0x9184e72a000",
            "value": "0x9184e72a",
            "storageLimit":"0x3344adf",
            "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
        }"#;
        let deserialized_result = serde_json::from_str::<TransactionRequest>(s);
        assert!(
            deserialized_result.is_ok(),
            "serialized str should look like {}",
            serde_json::to_string(&expected).unwrap()
        );
        assert_eq!(deserialized_result.unwrap(), expected);
    }

    #[test]
    fn call_request_deserialize_empty() {
        let expected = TransactionRequest {
            from: Some(
                RpcAddress::try_from_h160(
                    H160::from_low_u64_be(1),
                    Network::Main,
                )
                .unwrap(),
            ),
            to: None,
            gas_price: None,
            gas: None,
            value: None,
            data: None,
            storage_limit: None,
            nonce: None,
            ..Default::default()
        };

        let s = r#"{"from":"CFX:TYPE.BUILTIN:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJC4EYEY6"}"#;
        let deserialized_result = serde_json::from_str::<TransactionRequest>(s);
        assert!(
            deserialized_result.is_ok(),
            "serialized str should look like {}",
            serde_json::to_string(&expected).unwrap()
        );
        assert_eq!(deserialized_result.unwrap(), expected);
    }
}
