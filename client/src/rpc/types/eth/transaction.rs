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

use crate::rpc::types::Bytes;
use cfx_types::{H160, H256, H512, U256, U64};
use cfxcore::{executive::contract_address, vm::CreateContractAddress};
use primitives::{transaction::eip155_signature, Action, SignedTransaction};
use rlp::Encodable;
use serde::Serialize;

/// Transaction
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    // /// transaction type
    // #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    // pub transaction_type: Option<U64>,
    /// Hash
    pub hash: H256,
    /// Nonce
    pub nonce: U256,
    /// Block hash
    pub block_hash: Option<H256>,
    /// Block number
    pub block_number: Option<U256>,
    /// Transaction Index
    pub transaction_index: Option<U256>,
    /// Sender
    pub from: H160,
    /// Recipient
    pub to: Option<H160>,
    /// Transfered value
    pub value: U256,
    /// Gas Price
    pub gas_price: U256,
    /// Max fee per gas
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    /// Gas
    pub gas: U256,
    /// Data
    pub input: Bytes,
    /// Creates contract
    pub creates: Option<H160>,
    /// Raw transaction data
    pub raw: Bytes,
    /// Public key of the signer.
    pub public_key: Option<H512>,
    /// The network id of the transaction, if any.
    pub chain_id: Option<U64>,
    /// The standardised V field of the signature (0 or 1). Used by legacy
    /// transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard_v: Option<U256>,
    /// The standardised V field of the signature.
    pub v: U256,
    /// The R field of the signature.
    pub r: U256,
    /// The S field of the signature.
    pub s: U256,
    // Whether tx is success
    pub status: Option<U64>,
    /* /// Transaction activates at specified block.
     * pub condition: Option<TransactionCondition>,
     * /// optional access list
     * #[serde(skip_serializing_if = "Option::is_none")]
     * pub access_list: Option<AccessList>,
     * /// miner bribe
     * #[serde(skip_serializing_if = "Option::is_none")]
     * pub max_priority_fee_per_gas: Option<U256>, */
}

impl Transaction {
    /// Convert `SignedTransaction` into RPC Transaction.
    pub fn from_signed(
        t: &SignedTransaction,
        block_info: (Option<H256>, Option<U256>, Option<U256>),
        exec_info: (Option<U64>, Option<H160>),
    ) -> Transaction
    {
        let signature = t.signature();
        // We only support EIP-155
        // let access_list = match t.as_unsigned() {
        //     TypedTransaction::AccessList(tx) => {
        //         Some(tx.access_list.clone().into_iter().map(Into::into).
        // collect())     }
        //     TypedTransaction::EIP1559Transaction(tx) => Some(
        //         tx.transaction
        //             .access_list
        //             .clone()
        //             .into_iter()
        //             .map(Into::into)
        //             .collect(),
        //     ),
        //     TypedTransaction::Legacy(_) => None,
        // };

        Transaction {
            hash: t.hash(),
            nonce: *t.nonce(),
            block_hash: block_info.0,
            block_number: block_info.1,
            transaction_index: block_info.2,
            from: t.sender().address,
            to: match t.action() {
                Action::Create => None,
                Action::Call(ref address) => Some(*address),
            },
            value: *t.value(),
            gas_price: *t.gas_price(),
            max_fee_per_gas: None,
            gas: *t.gas(),
            input: Bytes::new(t.data().clone()),
            creates: exec_info.1,
            raw: Bytes::new(t.transaction.transaction.rlp_bytes()),
            public_key: t.public().map(Into::into),
            chain_id: t.chain_id().map(|x| U64::from(x as u64)),
            standard_v: Some(signature.v().into()),
            v: eip155_signature::add_chain_replay_protection(
                signature.v(),
                t.chain_id().map(|x| x as u64),
            )
            .into(), /* The protected EIP155 v */
            r: signature.r().into(),
            s: signature.s().into(),
            status: exec_info.0,
        }
    }

    pub fn deployed_contract_address(t: &SignedTransaction) -> Option<H160> {
        match t.action() {
            Action::Create => {
                let (new_contract_address, _) = contract_address(
                    CreateContractAddress::FromSenderNonce,
                    0.into(),
                    &t.sender(),
                    t.nonce(),
                    t.data(),
                );
                Some(new_contract_address.address)
            }
            Action::Call(_) => None,
        }
    }
}

/*#[cfg(test)]
mod tests {
    use super::{LocalTransactionStatus, Transaction};
    use ethereum_types::H256;
    use serde_json;
    use types::transaction::TypedTxId;
    use v1::types::AccessListItem;

    #[test]
    fn test_transaction_serialize() {
        let mut t = Transaction::default();
        t.transaction_type = TypedTxId::AccessList.to_U64_option_id();
        t.access_list = Some(vec![AccessListItem::default()]);
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(
            serialized,
            r#"{"type":"0x1","hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":null,"blockNumber":null,"transactionIndex":null,"from":"0x0000000000000000000000000000000000000000","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","input":"0x","creates":null,"raw":"0x","publicKey":null,"chainId":null,"v":"0x0","r":"0x0","s":"0x0","condition":null,"accessList":[{"address":"0x0000000000000000000000000000000000000000","storageKeys":[]}]}"#
        );
    }

    #[test]
    fn test_local_transaction_status_serialize() {
        let tx_ser = serde_json::to_string(&Transaction::default()).unwrap();
        let status1 = LocalTransactionStatus::Pending;
        let status2 = LocalTransactionStatus::Future;
        let status3 = LocalTransactionStatus::Mined(Transaction::default());
        let status4 = LocalTransactionStatus::Dropped(Transaction::default());
        let status5 = LocalTransactionStatus::Invalid(Transaction::default());
        let status6 =
            LocalTransactionStatus::Rejected(Transaction::default(), "Just because".into());
        let status7 = LocalTransactionStatus::Replaced(
            Transaction::default(),
            5.into(),
            H256::from_low_u64_be(10),
        );

        assert_eq!(
            serde_json::to_string(&status1).unwrap(),
            r#"{"status":"pending"}"#
        );
        assert_eq!(
            serde_json::to_string(&status2).unwrap(),
            r#"{"status":"future"}"#
        );
        assert_eq!(
            serde_json::to_string(&status3).unwrap(),
            r#"{"status":"mined","transaction":"#.to_owned() + &format!("{}", tx_ser) + r#"}"#
        );
        assert_eq!(
            serde_json::to_string(&status4).unwrap(),
            r#"{"status":"dropped","transaction":"#.to_owned() + &format!("{}", tx_ser) + r#"}"#
        );
        assert_eq!(
            serde_json::to_string(&status5).unwrap(),
            r#"{"status":"invalid","transaction":"#.to_owned() + &format!("{}", tx_ser) + r#"}"#
        );
        assert_eq!(
            serde_json::to_string(&status6).unwrap(),
            r#"{"status":"rejected","transaction":"#.to_owned()
                + &format!("{}", tx_ser)
                + r#","error":"Just because"}"#
        );
        assert_eq!(
            serde_json::to_string(&status7).unwrap(),
            r#"{"status":"replaced","transaction":"#.to_owned()
                + &format!("{}", tx_ser)
                + r#","hash":"0x000000000000000000000000000000000000000000000000000000000000000a","gasPrice":"0x5"}"#
        );
    }
}*/
