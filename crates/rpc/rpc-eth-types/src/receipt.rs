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

use crate::Log;
use cfx_types::{Bloom as H2048, H160, H256, U256, U64};
use serde::Serialize;

/// Receipt
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U64>,
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
    /// The gas fee charged in the execution of the transaction.
    pub gas_fee: U256,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burnt_gas_fee: Option<U256>,
}
