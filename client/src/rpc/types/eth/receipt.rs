// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

use crate::rpc::types::eth::Log;
use cfx_types::{Bloom as H2048, H160, H256, U256, U64};

/// Receipt
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// Transaction Hash
    pub transaction_hash: H256,
    /// Transaction index
    pub transaction_index: U256,
    /// Block hash
    pub block_hash: H256,
    /// Sender
    pub from: H160,
    /// Recipient
    pub to: Option<H160>,
    /// Block number
    pub block_number: U256,
    /// Cumulative gas used
    pub cumulative_gas_used: U256,
    /// Gas used
    pub gas_used: U256,
    /// Contract address
    pub contract_address: Option<H160>,
    /// Logs
    pub logs: Vec<Log>,
    /// Logs bloom
    pub logs_bloom: H2048,
    /// Status code
    #[serde(rename = "status")]
    pub status_code: U64,
    /// Effective gas price
    pub effective_gas_price: U256,
    /// Detailed error message if tx execution is unsuccessful. Error message
    /// is None if tx execution is successful or it can not be offered.
    /// Error message can not be offered by light client.
    pub tx_exec_error_msg: Option<String>,
}

// impl Receipt {
//     fn outcome_to_state_root(outcome: TransactionOutcome) -> Option<H256> {
//         match outcome {
//             TransactionOutcome::Unknown | TransactionOutcome::StatusCode(_)
// => None,             TransactionOutcome::StateRoot(root) => Some(root),
//         }
//     }
//
//     fn outcome_to_status_code(outcome: &TransactionOutcome) -> Option<U64> {
//         match *outcome {
//             TransactionOutcome::Unknown | TransactionOutcome::StateRoot(_) =>
// None,             TransactionOutcome::StatusCode(ref code) => Some((*code as
// u64).into()),         }
//     }
// }
//
// impl From<LocalizedReceipt> for Receipt {
//     fn from(r: LocalizedReceipt) -> Self {
//         Receipt {
//             to: r.to.map(Into::into),
//             from: Some(r.from),
//             transaction_type: r.transaction_type.to_U64_option_id(),
//             transaction_hash: Some(r.transaction_hash),
//             transaction_index: Some(r.transaction_index.into()),
//             block_hash: Some(r.block_hash),
//             block_number: Some(r.block_number.into()),
//             cumulative_gas_used: r.cumulative_gas_used,
//             gas_used: Some(r.gas_used),
//             contract_address: r.contract_address.map(Into::into),
//             logs: r.logs.into_iter().map(Into::into).collect(),
//             status_code: Self::outcome_to_status_code(&r.outcome),
//             state_root: Self::outcome_to_state_root(r.outcome),
//             logs_bloom: r.log_bloom,
//             effective_gas_price: r.effective_gas_price,
//         }
//     }
// }
//
// impl From<RichReceipt> for Receipt {
//     fn from(r: RichReceipt) -> Self {
//         Receipt {
//             from: Some(r.from),
//             to: r.to.map(Into::into),
//             transaction_type: r.transaction_type.to_U64_option_id(),
//             transaction_hash: Some(r.transaction_hash),
//             transaction_index: Some(r.transaction_index.into()),
//             block_hash: None,
//             block_number: None,
//             cumulative_gas_used: r.cumulative_gas_used,
//             gas_used: Some(r.gas_used),
//             contract_address: r.contract_address.map(Into::into),
//             logs: r.logs.into_iter().map(Into::into).collect(),
//             status_code: Self::outcome_to_status_code(&r.outcome),
//             state_root: Self::outcome_to_state_root(r.outcome),
//             logs_bloom: r.log_bloom,
//             effective_gas_price: r.effective_gas_price,
//         }
//     }
// }
//
// impl From<TypedReceipt> for Receipt {
//     fn from(r: TypedReceipt) -> Self {
//         let transaction_type = r.tx_type().to_U64_option_id();
//         let legacy_receipt = r.receipt().clone();
//         Receipt {
//             from: None,
//             to: None,
//             transaction_type,
//             transaction_hash: None,
//             transaction_index: None,
//             block_hash: None,
//             block_number: None,
//             cumulative_gas_used: legacy_receipt.gas_used,
//             gas_used: None,
//             contract_address: None,
//             logs: legacy_receipt.logs.into_iter().map(Into::into).collect(),
//             status_code:
// Self::outcome_to_status_code(&legacy_receipt.outcome),
// state_root: Self::outcome_to_state_root(legacy_receipt.outcome),
// logs_bloom: legacy_receipt.log_bloom,             effective_gas_price:
// Default::default(),         }
//     }
// }
//
// #[cfg(test)]
// mod tests {
//     use ethereum_types::{Bloom, H256};
//     use serde_json;
//     use types::transaction::TypedTxId;
//     use v1::types::{Log, Receipt};
//
//     #[test]
//     fn receipt_serialization() {
//         let s =
// r#"{"type":"0x1","transactionHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// transactionIndex":"0x0","blockHash":"
// 0xed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5","from":
// null,"to":null,"blockNumber":"0x4510c","cumulativeGasUsed":"0x20","gasUsed":"
// 0x10","contractAddress":null,"logs":[{"address":"
// 0x33990122638b9132ca29c723bdf037f1a891a70c","topics":["
// 0xa6697e974e6a320f454390be03f74955e8978f1a6971ea6730542e37b66179bc","
// 0x4861736852656700000000000000000000000000000000000000000000000000"],"data":"
// 0x","blockHash":"
// 0xed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5","
// blockNumber":"0x4510c","transactionHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// transactionIndex":"0x0","logIndex":"0x1","transactionLogIndex":null,"type":"
// mined","removed":false}],"root":"
// 0x000000000000000000000000000000000000000000000000000000000000000a","
// logsBloom":"
// 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f"
// ,"status":"0x1","effectiveGasPrice":"0x0"}"#;
//
//         let receipt = Receipt {
//             from: None,
//             to: None,
//             transaction_type: TypedTxId::AccessList.to_U64_option_id(),
//             transaction_hash: Some(H256::zero()),
//             transaction_index: Some(0.into()),
//             block_hash: Some(
//
// "ed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5"
//                     .parse()
//                     .unwrap(),
//             ),
//             block_number: Some(0x4510c.into()),
//             cumulative_gas_used: 0x20.into(),
//             gas_used: Some(0x10.into()),
//             contract_address: None,
//             logs: vec![Log {
//                 address:
// "33990122638b9132ca29c723bdf037f1a891a70c".parse().unwrap(),
// topics: vec![
// "a6697e974e6a320f454390be03f74955e8978f1a6971ea6730542e37b66179bc"
//                         .parse()
//                         .unwrap(),
//
// "4861736852656700000000000000000000000000000000000000000000000000"
//                         .parse()
//                         .unwrap(),
//                 ],
//                 data: vec![].into(),
//                 block_hash: Some(
//
// "ed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5"
//                         .parse()
//                         .unwrap(),
//                 ),
//                 block_number: Some(0x4510c.into()),
//                 transaction_hash: Some(H256::zero()),
//                 transaction_index: Some(0.into()),
//                 transaction_log_index: None,
//                 log_index: Some(1.into()),
//                 removed: false,
//             }],
//             logs_bloom: Bloom::from_low_u64_be(15),
//             state_root: Some(H256::from_low_u64_be(10)),
//             status_code: Some(1u64.into()),
//             effective_gas_price: Default::default(),
//         };
//
//         let serialized = serde_json::to_string(&receipt).unwrap();
//         assert_eq!(serialized, s);
//     }
// }
