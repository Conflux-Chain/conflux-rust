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

use crate::Bytes;
use cfx_types::{
    cal_contract_address, CreateContractAddressType, H160, H256, H512, U256,
    U64,
};
use primitives::{
    transaction::eth_transaction::eip155_signature, AccessList, Action,
    SignedTransaction,
};
use rlp::Encodable;
use serde::{Deserialize, Serialize};

/// Transaction
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    /// transaction type
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U64>,
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
    pub gas_price: Option<U256>,
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
    pub raw: Option<Bytes>,
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
    /// Optional access list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessList>,
    /// miner bribe
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y_parity: Option<U64>,
    /* /// Transaction activates at specified block.
     * pub condition: Option<TransactionCondition>, */
}

impl Transaction {
    /// Convert `SignedTransaction` into RPC Transaction.
    pub fn from_signed(
        t: &SignedTransaction,
        block_info: (Option<H256>, Option<U256>, Option<U256>),
        exec_info: (Option<U64>, Option<H160>),
    ) -> Transaction {
        let signature = t.signature();

        // for 2718 tx, the v should be equal to the signature.v and y_parity
        let (v, y_parity) = if t.is_2718() {
            (U256::from(signature.v()), Some(U64::from(signature.v())))
        } else {
            (
                eip155_signature::add_chain_replay_protection(
                    signature.v(),
                    t.chain_id().map(|x| x as u64),
                )
                .into(),
                None,
            )
        };

        // for phantom tx, it's r and s are set to 'tx.from', which lead some
        // txs r and s to 0 which is not valid in some ethereum tools,
        // so we set them to chain_id
        let mut r: U256 = signature.r().into();
        let mut s: U256 = signature.s().into();
        if r == U256::zero() || s == U256::zero() {
            let chain_id = t
                .chain_id()
                .map(|x| U256::from(x as u64))
                .expect("should have chain_id");
            r = chain_id;
            s = chain_id;
        }

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
            gas_price: Some(*t.gas_price()),
            gas: *t.gas(),
            input: Bytes::new(t.data().clone()),
            creates: exec_info.1,
            raw: Some(Bytes::new(t.transaction.transaction.rlp_bytes())),
            public_key: t.public().map(Into::into),
            chain_id: t.chain_id().map(|x| U64::from(x as u64)),
            standard_v: Some(signature.v().into()),
            v,
            r,
            s,
            status: exec_info.0,
            access_list: t.access_list().cloned(),
            max_fee_per_gas: t.after_1559().then_some(*t.gas_price()),
            max_priority_fee_per_gas: t
                .after_1559()
                .then_some(*t.max_priority_gas_price()),
            y_parity,
            transaction_type: Some(U64::from(t.type_id())),
        }
    }

    pub fn deployed_contract_address(t: &SignedTransaction) -> Option<H160> {
        match t.action() {
            Action::Create => {
                let (new_contract_address, _) = cal_contract_address(
                    CreateContractAddressType::FromSenderNonce,
                    0,
                    &t.sender().address,
                    t.nonce(),
                    t.data(),
                );
                Some(new_contract_address)
            }
            Action::Call(_) => None,
        }
    }
}
