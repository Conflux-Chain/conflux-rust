// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{Bytes, H256, U256};
use cfx_types::Address;
use primitives::{receipt::Receipt as PrimitiveReceipt, TransactionAddress};
use serde_derive::Serialize;

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// The total gas used in the block following execution of the transaction.
    pub gas_used: U256,
    /// Transaction outcome.
    pub outcome_status: u8,
    /// Block hash
    pub block_hash: H256,
    /// Transaction index within the block
    pub index: usize,
    /// Addresses of contracts created during execution of transaction.
    /// Ordered from earliest creation.
    ///
    /// eg. sender creates contract A and A in constructor creates contract B
    ///
    /// B creation ends first, and it will be the first element of the vector.
    pub contracts_created: Vec<Address>,
    /// Transaction output.
    pub output: Bytes,
}

impl Receipt {
    pub fn new(
        receipt: PrimitiveReceipt, transaction_adress: TransactionAddress,
    ) -> Receipt {
        Receipt {
            gas_used: receipt.gas_used.into(),
            outcome_status: receipt.outcome_status,
            block_hash: transaction_adress.block_hash.into(),
            index: transaction_adress.index,
            contracts_created: receipt.contracts_created.into(),
            output: receipt.output.into(),
        }
    }
}
