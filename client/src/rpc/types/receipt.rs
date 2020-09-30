// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::Log;
use cfx_types::{Address, Bloom, H256, U256, U64};
use cfxcore::{executive::contract_address, vm::CreateContractAddress};
use primitives::{
    receipt::Receipt as PrimitiveReceipt, transaction::Action,
    SignedTransaction as PrimitiveTransaction, TransactionIndex,
};
use serde_derive::Serialize;

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// Transaction hash.
    pub transaction_hash: H256,
    /// Transaction index within the block.
    pub index: U64,
    /// Block hash.
    pub block_hash: H256,
    /// epoch number where this transaction was in.
    pub epoch_number: Option<U64>,
    /// address of the sender.
    pub from: Address,
    /// address of the receiver, null when it's a contract creation
    /// transaction.
    pub to: Option<Address>,
    /// The gas used in the execution of the transaction.
    pub gas_used: U256,
    /// The gas fee charged in the execution of the transaction.
    pub gas_fee: U256,
    /// Address of contracts created during execution of transaction.
    pub contract_created: Option<Address>,
    /// Array of log objects, which this transaction generated.
    pub logs: Vec<Log>,
    /// Bloom filter for light clients to quickly retrieve related logs.
    pub logs_bloom: Bloom,
    /// state root.
    pub state_root: H256,
    /// Transaction outcome.
    pub outcome_status: U64,
    /// Detailed error message if tx execution is unsuccessful. Error message
    /// is None if tx execution is successful or it can not be offered.
    /// Error message can not be offered by light client.
    pub tx_exec_error_msg: Option<String>,
}

impl Receipt {
    pub fn new(
        transaction: PrimitiveTransaction, receipt: PrimitiveReceipt,
        transaction_index: TransactionIndex, prior_gas_used: U256,
        epoch_number: Option<u64>, block_number: u64,
        maybe_state_root: Option<H256>, tx_exec_error_msg: Option<String>,
    ) -> Receipt
    {
        let mut address = None;
        if Action::Create == transaction.action && receipt.outcome_status == 0 {
            let (created_address, _) = contract_address(
                CreateContractAddress::FromSenderNonceAndCodeHash,
                block_number.into(),
                &transaction.sender,
                &transaction.nonce,
                &transaction.data,
            );
            address = Some(created_address);
        }
        Receipt {
            transaction_hash: transaction.hash.into(),
            index: U64::from(transaction_index.index),
            block_hash: transaction_index.block_hash.into(),
            gas_used: (receipt.accumulated_gas_used - prior_gas_used).into(),
            gas_fee: receipt.gas_fee.into(),
            from: transaction.sender,
            to: match &transaction.action {
                Action::Create => None,
                Action::Call(address) => Some(address.clone()),
            },
            outcome_status: U64::from(receipt.outcome_status),
            contract_created: address,
            logs: receipt.logs.into_iter().map(Log::from).collect(),
            logs_bloom: receipt.log_bloom,
            state_root: maybe_state_root
                .map_or_else(Default::default, Into::into),
            epoch_number: epoch_number.map(U64::from),
            tx_exec_error_msg,
        }
    }
}
