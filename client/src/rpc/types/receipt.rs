// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{H256, U256};
use cfx_types::Address;
use cfxcore::{executive::contract_address, vm::CreateContractAddress};
use primitives::{
    receipt::Receipt as PrimitiveReceipt, transaction::Action,
    SignedTransaction as PrimitiveTransaction, TransactionAddress,
};
use serde_derive::Serialize;

#[derive(Debug, Serialize, Clone, Deserialize)]
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
    /// Address of contracts created during execution of transaction.
    pub contract_created: Option<Address>,
}

impl Receipt {
    pub fn new(
        transaction: PrimitiveTransaction, receipt: PrimitiveReceipt,
        transaction_address: TransactionAddress,
    ) -> Receipt
    {
        let mut address = None;
        if Action::Create == transaction.action {
            let (created_address, _) = contract_address(
                CreateContractAddress::FromSenderAndNonce,
                &transaction.sender,
                &transaction.nonce,
                &transaction.data,
            );
            address = Some(created_address);
        }
        Receipt {
            gas_used: receipt.gas_used.into(),
            outcome_status: receipt.outcome_status,
            block_hash: transaction_address.block_hash.into(),
            index: transaction_address.index,
            contract_created: address,
        }
    }
}
