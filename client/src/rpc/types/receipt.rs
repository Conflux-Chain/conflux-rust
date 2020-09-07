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

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
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
}

impl Receipt {
    pub fn new(
        transaction: PrimitiveTransaction, receipt: PrimitiveReceipt,
        transaction_index: TransactionIndex, prior_gas_used: U256,
        epoch_number: Option<u64>, maybe_state_root: Option<H256>,
    ) -> Receipt
    {
        let mut address = None;
        if Action::Create == transaction.action && receipt.outcome_status == 0 {
            let (created_address, _) = contract_address(
                CreateContractAddress::FromSenderNonceAndCodeHash,
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
            to: match transaction.action {
                Action::Create => None,
                Action::Call(ref address) => Some(address.clone()),
            },
            outcome_status: U64::from(receipt.outcome_status),
            contract_created: address,
            logs: receipt.logs.into_iter().map(Log::from).collect(),
            logs_bloom: receipt.log_bloom,
            state_root: maybe_state_root
                .map_or_else(Default::default, Into::into),
            epoch_number: epoch_number.map(U64::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_types::H160;
    use primitives::{
        TransactionWithSignature, TransactionWithSignatureSerializePart,
    };

    #[test]
    fn test_receipt_serialize() {
        let bloom: [u8; 256] = [0; 256];
        let receipt = Receipt {
            transaction_hash: H256([0xff; 32]),
            index: U64::one(),
            block_hash: H256([0xff; 32]),
            epoch_number: None,
            from: H160([0xff; 20]),
            to: None,
            gas_used: U256::one(),
            gas_fee: U256::one(),
            contract_created: None,
            logs: vec![],
            logs_bloom: Bloom(bloom),
            state_root: H256([0xff; 32]),
            outcome_status: U64::one(),
        };
        let serialize = serde_json::to_string(&receipt).unwrap();
        assert_eq!(serialize,"{\"transactionHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"index\":\"0x1\",\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"epochNumber\":null,\"from\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"to\":null,\"gasUsed\":\"0x1\",\"gasFee\":\"0x1\",\"contractCreated\":null,\"logs\":[],\"logsBloom\":\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"stateRoot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"outcomeStatus\":\"0x1\"}");
    }
    #[test]
    fn test_receipt_deserialize() {
        let serialize = "{\"transactionHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"index\":\"0x1\",\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"epochNumber\":null,\"from\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"to\":null,\"gasUsed\":\"0x1\",\"gasFee\":\"0x1\",\"contractCreated\":null,\"logs\":[],\"logsBloom\":\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"stateRoot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"outcomeStatus\":\"0x1\"}";
        let deserialize: Receipt = serde_json::from_str(serialize).unwrap();
        let bloom: [u8; 256] = [0; 256];
        let receipt = Receipt {
            transaction_hash: H256([0xff; 32]),
            index: U64::one(),
            block_hash: H256([0xff; 32]),
            epoch_number: None,
            from: H160([0xff; 20]),
            to: None,
            gas_used: U256::one(),
            gas_fee: U256::one(),
            contract_created: None,
            logs: vec![],
            logs_bloom: Bloom(bloom),
            state_root: H256([0xff; 32]),
            outcome_status: U64::one(),
        };
        assert_eq!(deserialize, receipt);
    }
    #[test]
    fn test_receipt_new() {
        let transaction = PrimitiveTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: Default::default(),
                    v: 0,
                    r: U256::one(),
                    s: U256::one(),
                },
                hash: H256([0xff; 32]),
                rlp_size: None,
            },
            sender: H160([0xff; 20]),
            public: None,
        };
        let bloom: [u8; 256] = [0; 256];
        let pri_receipt = PrimitiveReceipt {
            accumulated_gas_used: U256::one(),
            gas_fee: U256::one(),
            gas_sponsor_paid: false,
            log_bloom: Bloom(bloom),
            logs: vec![],
            outcome_status: 0,
            storage_sponsor_paid: false,
            storage_collateralized: vec![],
            storage_released: vec![],
        };
        let transaction_index = TransactionIndex {
            block_hash: H256([0xff; 32]),
            index: 0,
        };
        let receipt = Receipt::new(
            transaction,
            pri_receipt,
            transaction_index,
            U256::one(),
            None,
            None,
        );
        let receipt_info = serde_json::to_string(&receipt).unwrap();
        assert_eq!(receipt_info,
        r#"{"transactionHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","index":"0x0","blockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","epochNumber":null,"from":"0xffffffffffffffffffffffffffffffffffffffff","to":null,"gasUsed":"0x0","gasFee":"0x1","contractCreated":"0x8c2152e51c66962b151a4262b950c1a14bbcdee5","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","outcomeStatus":"0x0"}"#);
    }
    #[test]
    fn test_receipt_new_one() {
        let transaction = PrimitiveTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: Default::default(),
                    v: 0,
                    r: U256::one(),
                    s: U256::one(),
                },
                hash: H256([0xff; 32]),
                rlp_size: None,
            },
            sender: H160([0xff; 20]),
            public: None,
        };
        let bloom: [u8; 256] = [0; 256];
        let pri_receipt = PrimitiveReceipt {
            accumulated_gas_used: U256::one(),
            gas_fee: U256::one(),
            gas_sponsor_paid: false,
            log_bloom: Bloom(bloom),
            logs: vec![],
            outcome_status: 1,
            storage_sponsor_paid: false,
            storage_collateralized: vec![],
            storage_released: vec![],
        };
        let transaction_index = TransactionIndex {
            block_hash: H256([0xff; 32]),
            index: 0,
        };
        let receipt = Receipt::new(
            transaction,
            pri_receipt,
            transaction_index,
            U256::one(),
            None,
            None,
        );
        let receipt_info = serde_json::to_string(&receipt).unwrap();
        assert_eq!(receipt_info,
                   "{\"transactionHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"index\":\"0x0\",\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"epochNumber\":null,\"from\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"to\":null,\"gasUsed\":\"0x0\",\"gasFee\":\"0x1\",\"contractCreated\":null,\"logs\":[],\"logsBloom\":\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"stateRoot\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"outcomeStatus\":\"0x1\"}");
    }
}
