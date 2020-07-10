// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::Bytes;
use cfx_types::{address_util::AddressUtil, Address, H160, U256, U64};
use primitives::{
    transaction::Action, SignedTransaction, Transaction as PrimitiveTransaction,
};
use std::cmp::min;

// use serde_json::de::ParserNumber::U64;

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRequest {
    /// From
    pub from: Option<H160>,
    /// To
    pub to: Option<H160>,
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

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimateGasAndCollateralResponse {
    /// The amount of gas used in the execution.
    pub gas_used: U256,
    /// The number of bytes collateralized in the execution.
    pub storage_collateralized: U256,
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

pub fn sign_call(
    epoch_height: u64, chain_id: u32, request: CallRequest,
) -> SignedTransaction {
    let max_gas = U256::from(500_000_000);
    let gas = min(request.gas.unwrap_or(max_gas), max_gas);
    let from = request.from.unwrap_or_else(|| {
        let mut address = Address::random();
        address.set_user_account_type_bits();
        address
    });

    PrimitiveTransaction {
        nonce: request.nonce.unwrap_or_default(),
        action: request.to.map_or(Action::Create, Action::Call),
        gas,
        gas_price: request.gas_price.unwrap_or_default(),
        value: request.value.unwrap_or_default(),
        storage_limit: request
            .storage_limit
            .map(|v| v.as_u64())
            .unwrap_or(std::u64::MAX),
        epoch_height,
        chain_id,
        data: request.data.unwrap_or_default().into_vec(),
    }
    .fake_sign(from)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rustc_hex::FromHex;
    use serde_json;

    use cfx_types::{H160, U256, U64};

    use super::CallRequest;

    #[test]
    fn call_request_deserialize() {
        let s = r#"{
            "from":"0x0000000000000000000000000000000000000001",
            "to":"0x0000000000000000000000000000000000000002",
            "gasPrice":"0x1",
            "gas":"0x2",
            "value":"0x3",
            "data":"0x123456",
            "storageLimit":"0x7b",
            "nonce":"0x4"
        }"#;
        let deserialized: CallRequest = serde_json::from_str(s).unwrap();

        assert_eq!(
            deserialized,
            CallRequest {
                from: Some(H160::from_low_u64_be(1)),
                to: Some(H160::from_low_u64_be(2)),
                gas_price: Some(U256::from(1)),
                gas: Some(U256::from(2)),
                value: Some(U256::from(3)),
                data: Some(vec![0x12, 0x34, 0x56].into()),
                storage_limit: Some(U64::from_str("7b").unwrap()),
                nonce: Some(U256::from(4)),
            }
        );
    }

    #[test]
    fn call_request_deserialize2() {
        let s = r#"{
            "from": "0xb60e8dd61c5d32be8058bb8eb970870f07233155",
            "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
            "gas": "0x76c0",
            "gasPrice": "0x9184e72a000",
            "value": "0x9184e72a",
            "storageLimit":"0x3344adf",
            "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
        }"#;
        let deserialized: CallRequest = serde_json::from_str(s).unwrap();

        assert_eq!(deserialized, CallRequest {
            from: Some(H160::from_str("b60e8dd61c5d32be8058bb8eb970870f07233155").unwrap()),
            to: Some(H160::from_str("d46e8dd67c5d32be8058bb8eb970870f07244567").unwrap()),
            gas_price: Some(U256::from_str("9184e72a000").unwrap()),
            gas: Some(U256::from_str("76c0").unwrap()),
            value: Some(U256::from_str("9184e72a").unwrap()),
            storage_limit: Some(U64::from_str("3344adf").unwrap()),
            data: Some("d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675".from_hex().unwrap().into()),
            nonce: None
        });
    }

    #[test]
    fn call_request_deserialize_empty() {
        let s = r#"{"from":"0x0000000000000000000000000000000000000001"}"#;
        let deserialized: CallRequest = serde_json::from_str(s).unwrap();

        assert_eq!(
            deserialized,
            CallRequest {
                from: Some(H160::from_low_u64_be(1)),
                to: None,
                gas_price: None,
                gas: None,
                value: None,
                data: None,
                storage_limit: None,
                nonce: None,
            }
        );
    }
}
