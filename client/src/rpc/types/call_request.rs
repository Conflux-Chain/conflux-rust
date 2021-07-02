// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    types::{
        address::RpcAddress,
        errors::{check_rpc_address_network, RcpAddressNetworkInconsistent},
        Bytes,
    },
    RpcResult,
};
use cfx_addr::Network;
use cfx_types::{address_util::AddressUtil, Address, U256, U64};
use cfxcore::rpc_errors::invalid_params_check;
use cfxcore_accounts::AccountProvider;
use cfxkey::Password;
use primitives::{
    transaction::Action, SignedTransaction,
    Transaction as PrimitiveTransaction, TransactionWithSignature,
};
use std::{cmp::min, sync::Arc};

// use serde_json::de::ParserNumber::U64;

/// The MAX_GAS_CALL_REQUEST is one magnitude higher than block gas limit and
/// not too high that a call_virtual consumes too much resource.
pub const MAX_GAS_CALL_REQUEST: u64 = 500_000_000;

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
    ) -> RpcResult<TransactionWithSignature>
    {
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

        let password = password.map(Password::from);
        let sig = accounts
            .sign(self.from.into(), password, tx.signature_hash())
            // TODO: sign error into secret store error codes.
            .map_err(|e| format!("failed to sign transaction: {:?}", e))?;

        Ok(tx.with_signature(sig))
    }
}

pub fn sign_call(
    epoch_height: u64, chain_id: u32, request: CallRequest,
) -> RpcResult<SignedTransaction> {
    let max_gas = U256::from(MAX_GAS_CALL_REQUEST);
    let gas = min(request.gas.unwrap_or(max_gas), max_gas);
    let from = request.from.map_or_else(
        || {
            let mut address = Address::random();
            address.set_user_account_type_bits();
            address
        },
        |rpc_addr| rpc_addr.hex_address,
    );

    Ok(PrimitiveTransaction {
        nonce: request.nonce.unwrap_or_default(),
        action: request.to.map_or(Action::Create, |rpc_addr| {
            Action::Call(rpc_addr.hex_address)
        }),
        gas,
        gas_price: request.gas_price.unwrap_or(1.into()),
        value: request.value.unwrap_or_default(),
        storage_limit: request
            .storage_limit
            .map(|v| v.as_u64())
            .unwrap_or(std::u64::MAX),
        epoch_height,
        chain_id,
        data: request.data.unwrap_or_default().into_vec(),
    }
    .fake_sign(from))
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
            nonce: None
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
