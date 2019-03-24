// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    Bytes, H160 as RpcH160, H256 as RpcH256, U256 as RpcU256,
};
use keylib::Error;
use primitives::{
    transaction::Action, SignedTransaction,
    Transaction as PrimitiveTransaction, TransactionAddress,
    TransactionWithSignature,
};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: RpcH256,
    pub nonce: RpcU256,
    pub block_hash: Option<RpcH256>,
    pub transaction_index: Option<RpcU256>,
    pub from: RpcH160,
    pub to: Option<RpcH160>,
    pub value: RpcU256,
    pub gas_price: RpcU256,
    pub gas: RpcU256,
    pub data: Bytes,
    /// The standardised V field of the signature.
    pub v: RpcU256,
    /// The R field of the signature.
    pub r: RpcU256,
    /// The S field of the signature.
    pub s: RpcU256,
}

impl Transaction {
    pub fn from_signed(
        t: &SignedTransaction, transaction_address: Option<TransactionAddress>,
    ) -> Transaction {
        Transaction {
            hash: t.transaction.hash().into(),
            nonce: t.nonce.into(),
            block_hash: transaction_address
                .clone()
                .map(|x| x.block_hash.into()),
            transaction_index: transaction_address
                .clone()
                .map(|x| x.index.into()),
            from: t.sender().into(),
            to: match t.action {
                Action::Create => None,
                Action::Call(ref address) => Some(address.clone().into()),
            },
            value: t.value.into(),
            gas_price: t.gas_price.into(),
            gas: t.gas.into(),
            data: t.data.clone().into(),
            v: t.transaction.v.into(),
            r: t.transaction.r.into(),
            s: t.transaction.s.into(),
        }
    }

    pub fn into_signed(self) -> Result<SignedTransaction, Error> {
        let tx_with_sig = TransactionWithSignature {
            unsigned: PrimitiveTransaction {
                nonce: self.nonce.into(),
                gas_price: self.gas_price.into(),
                gas: self.gas.into(),
                action: match self.to {
                    None => Action::Create,
                    Some(address) => Action::Call(address.into()),
                },
                value: self.value.into(),
                data: self.data.into(),
            },
            v: self.v.as_usize() as u8,
            r: self.r.into(),
            s: self.s.into(),
            hash: self.hash.into(),
        };
        let public = tx_with_sig.recover_public()?;
        Ok(SignedTransaction::new(public, tx_with_sig))
    }
}
