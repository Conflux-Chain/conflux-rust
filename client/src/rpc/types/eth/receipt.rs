// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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
