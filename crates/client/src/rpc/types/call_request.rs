// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    error_codes::invalid_params,
    types::{
        address::RpcAddress,
        errors::{check_rpc_address_network, RcpAddressNetworkInconsistent},
        Bytes,
    },
    RpcResult,
};
use cfx_addr::Network;
use cfx_types::{Address, AddressSpaceUtil, H256, U256, U64};
use cfxcore::rpc_errors::invalid_params_check;
use cfxcore_accounts::AccountProvider;
use cfxkey::Password;
use primitives::{
    transaction::{
        native_transaction::NativeTransaction as PrimitiveTransaction, Action,
    },
    AccessList, AccessListItem, SignedTransaction, Transaction,
    TransactionWithSignature,
};
use std::{cmp::min, convert::From, sync::Arc};

// use serde_json::de::ParserNumber::U64;

/// The MAX_GAS_CALL_REQUEST is one magnitude higher than block gas limit and
/// not too high that a call_virtual consumes too much resource.
pub const MAX_GAS_CALL_REQUEST: u64 = 15_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreAccessListItem {
    pub address: RpcAddress,
    pub storage_keys: Vec<H256>,
}

pub type CoreAccessList = Vec<CoreAccessListItem>;

fn to_primitive_access_list(list: CoreAccessList) -> AccessList {
    list.into_iter()
        .map(|item| AccessListItem {
            address: item.address.hex_address,
            storage_keys: item.storage_keys,
        })
        .collect()
}

#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRequest {
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
    pub access_list: Option<CoreAccessList>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(rename = "type")]
    pub transaction_type: Option<U64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxRequest {
    pub from: RpcAddress,
    pub to: Option<RpcAddress>,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Option<Bytes>,
    pub nonce: Option<U256>,
    pub storage_limit: Option<U256>,
    pub chain_id: Option<U256>,
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

impl SendTxRequest {
    pub fn check_rpc_address_network(
        &self, param_name: &str, expected: &Network,
    ) -> RpcResult<()> {
        let rpc_request_network = invalid_params_check(
            param_name,
            rpc_call_request_network(Some(&self.from), self.to.as_ref()),
        )?;
        invalid_params_check(
            param_name,
            check_rpc_address_network(rpc_request_network, expected),
        )
    }

    pub fn sign_with(
        self, best_epoch_height: u64, chain_id: u32, password: Option<String>,
        accounts: Arc<AccountProvider>,
    ) -> RpcResult<TransactionWithSignature> {
        let tx = PrimitiveTransaction {
            nonce: self.nonce.unwrap_or_default().into(),
            gas_price: self.gas_price.into(),
            gas: self.gas.into(),
            action: match self.to {
                None => Action::Create,
                Some(address) => Action::Call(address.into()),
            },
            value: self.value.into(),
            storage_limit: self.storage_limit.unwrap_or_default().as_usize()
                as u64,
            epoch_height: self
                .epoch_height
                .unwrap_or(best_epoch_height.into())
                .as_usize() as u64,
            chain_id: self.chain_id.unwrap_or(chain_id.into()).as_u32(),
            data: self.data.unwrap_or(Bytes::new(vec![])).into(),
        };

        if tx.epoch_height == u64::MAX {
            return Err("Can not sign Ethereum like transaction by RPC.".into());
        }

        let password = password.map(Password::from);
        let sig = accounts
            .sign(
                self.from.into(),
                password,
                Transaction::from(tx.clone()).signature_hash(),
            )
            // TODO: sign error into secret store error codes.
            .map_err(|e| format!("failed to sign transaction: {:?}", e))?;

        Ok(Transaction::from(tx).with_signature(sig))
    }
}

pub fn sign_call(
    epoch_height: u64, chain_id: u32, request: CallRequest,
) -> RpcResult<SignedTransaction> {
    use primitives::transaction::*;
    use TypedNativeTransaction::*;

    let max_gas = U256::from(MAX_GAS_CALL_REQUEST);
    let gas = min(request.gas.unwrap_or(max_gas), max_gas);

    let nonce = request.nonce.unwrap_or_default();
    let action = request.to.map_or(Action::Create, |rpc_addr| {
        Action::Call(rpc_addr.hex_address)
    });

    let value = request.value.unwrap_or_default();
    let storage_limit = request
        .storage_limit
        .map(|v| v.as_u64())
        .unwrap_or(std::u64::MAX);
    let data = request.data.unwrap_or_default().into_vec();

    let default_type_id = if request.max_fee_per_gas.is_some()
        || request.max_priority_fee_per_gas.is_some()
    {
        2
    } else if request.access_list.is_some() {
        1
    } else {
        0
    };
    let transaction_type = request
        .transaction_type
        .unwrap_or(U64::from(default_type_id));

    let gas_price = request.gas_price.unwrap_or(1.into());
    let max_fee_per_gas = request
        .max_fee_per_gas
        .or(request.max_priority_fee_per_gas)
        .unwrap_or(gas_price);
    let max_priority_fee_per_gas =
        request.max_priority_fee_per_gas.unwrap_or(U256::zero());
    let access_list = request.access_list.unwrap_or(vec![]);

    let transaction = match transaction_type.as_usize() {
        0 => Cip155(NativeTransaction {
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
        1 => Cip2930(Cip2930Transaction {
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
        2 => Cip1559(Cip1559Transaction {
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

    let from = request
        .from
        .map_or_else(|| Address::zero(), |rpc_addr| rpc_addr.hex_address);

    Ok(transaction.fake_sign_rpc(from.with_native_space()))
}

pub fn rpc_call_request_network(
    from: Option<&RpcAddress>, to: Option<&RpcAddress>,
) -> Result<Option<Network>, RcpAddressNetworkInconsistent> {
    let request_network = from.map(|rpc_addr| rpc_addr.network);
    match request_network {
        None => Ok(to.map(|rpc_addr| rpc_addr.network)),
        Some(network) => {
            if let Some(to) = to {
                if to.network != network {
                    return Err(RcpAddressNetworkInconsistent {
                        from_network: network,
                        to_network: to.network,
                    });
                }
            }
            Ok(Some(network))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CallRequest;

    use crate::rpc::types::address::RpcAddress;
    use cfx_addr::Network;
    use cfx_types::{H160, U256, U64};
    use rustc_hex::FromHex;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn call_request_deserialize() {
        let expected = CallRequest {
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
        let deserialized_result = serde_json::from_str::<CallRequest>(s);
        assert!(
            deserialized_result.is_ok(),
            "serialized str should look like {}",
            serde_json::to_string(&expected).unwrap()
        );
        assert_eq!(deserialized_result.unwrap(), expected);
    }

    #[test]
    fn call_request_deserialize2() {
        let expected = CallRequest {
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
        let deserialized_result = serde_json::from_str::<CallRequest>(s);
        assert!(
            deserialized_result.is_ok(),
            "serialized str should look like {}",
            serde_json::to_string(&expected).unwrap()
        );
        assert_eq!(deserialized_result.unwrap(), expected);
    }

    #[test]
    fn call_request_deserialize_empty() {
        let expected = CallRequest {
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
        let deserialized_result = serde_json::from_str::<CallRequest>(s);
        assert!(
            deserialized_result.is_ok(),
            "serialized str should look like {}",
            serde_json::to_string(&expected).unwrap()
        );
        assert_eq!(deserialized_result.unwrap(), expected);
    }
}
