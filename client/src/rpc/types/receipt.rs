// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{Log, H256, U256};
use cfx_types::{Address, Bloom};
use cfxcore::{executive::contract_address, vm::CreateContractAddress};
use primitives::{
    receipt::Receipt as PrimitiveReceipt, transaction::Action,
    SignedTransaction as PrimitiveTransaction, TransactionAddress,
};
use serde_derive::Serialize;

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// Transaction hash.
    pub transaction_hash: H256,
    /// Transaction index within the block.
    pub index: usize,
    /// Block hash.
    pub block_hash: H256,
    /// epoch number where this transaction was in.
    pub epoch_number: Option<u64>,
    /// address of the sender.
    pub from: Address,
    /// address of the receiver, null when it's a contract creation
    /// transaction.
    pub to: Option<Address>,
    /// The total gas used in the block following execution of the transaction.
    pub gas_used: U256,
    /// Address of contracts created during execution of transaction.
    pub contract_created: Option<Address>,
    /// Array of log objects, which this transaction generated.
    pub logs: Vec<Log>,
    /// Bloom filter for light clients to quickly retrieve related logs.
    pub logs_bloom: Bloom,
    /// state root.
    pub state_root: H256,
    /// Transaction outcome.
    pub outcome_status: u8,
}

impl Receipt {
    pub fn new(
        transaction: PrimitiveTransaction, receipt: PrimitiveReceipt,
        transaction_address: TransactionAddress,
    ) -> Receipt
    {
        let mut address = None;
        if Action::Create == transaction.action && receipt.outcome_status == 0 {
            let (created_address, _) = contract_address(
                CreateContractAddress::FromSenderAndNonce,
                &transaction.sender,
                &transaction.nonce,
                &transaction.data,
            );
            address = Some(created_address);
        }
        Receipt {
            transaction_hash: transaction.hash.into(),
            index: transaction_address.index,
            block_hash: transaction_address.block_hash.into(),
            gas_used: receipt.gas_used.into(),
            from: transaction.sender,
            to: match transaction.action {
                Action::Create => None,
                Action::Call(ref address) => Some(address.clone()),
            },
            outcome_status: receipt.outcome_status,
            contract_created: address,
            logs: receipt.logs.into_iter().map(Log::from).collect(),
            logs_bloom: receipt.log_bloom,
            state_root: Default::default(),
            epoch_number: None,
        }
    }

    pub fn set_state_root(&mut self, state_root: H256) {
        self.state_root = state_root;
    }

    pub fn set_epoch_number(&mut self, epoch_number: Option<u64>) {
        self.epoch_number = epoch_number;
    }
}
