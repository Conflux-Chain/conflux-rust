// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    receipt::Receipt, Bytes, H160 as RpcH160, H256 as RpcH256, U256 as RpcU256,
};
use cfxcore_accounts::AccountProvider;
use cfxkey::{Error, Password};
use primitives::{
    transaction::Action, SignedTransaction,
    Transaction as PrimitiveTransaction, TransactionWithSignature,
    TransactionWithSignatureSerializePart,
};
use std::sync::Arc;

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
    pub contract_created: Option<RpcH160>,
    pub data: Bytes,
    pub storage_limit: RpcU256,
    pub epoch_height: RpcU256,
    pub chain_id: RpcU256,
    pub status: Option<RpcU256>,
    /// The standardised V field of the signature.
    pub v: RpcU256,
    /// The R field of the signature.
    pub r: RpcU256,
    /// The S field of the signature.
    pub s: RpcU256,
}

impl Transaction {
    pub fn from_signed(
        t: &SignedTransaction, receipt: Option<Receipt>,
    ) -> Transaction {
        let mut contract_created = None;
        let mut status: Option<RpcU256> = None;
        if let Some(ref receipt) = receipt {
            if let Some(ref address) = receipt.contract_created {
                contract_created = Some(address.clone().into());
            }
            status = Some(receipt.outcome_status.into());
        }
        Transaction {
            hash: t.transaction.hash().into(),
            nonce: t.nonce.into(),
            block_hash: receipt.clone().map(|x| x.block_hash),
            transaction_index: receipt.map(|x| x.index.into()),
            status,
            contract_created,
            from: t.sender().into(),
            to: match t.action {
                Action::Create => None,
                Action::Call(ref address) => Some(address.clone().into()),
            },
            value: t.value.into(),
            gas_price: t.gas_price.into(),
            gas: t.gas.into(),
            data: t.data.clone().into(),
            storage_limit: t.storage_limit.into(),
            epoch_height: t.epoch_height.into(),
            chain_id: t.chain_id.into(),
            v: t.transaction.v.into(),
            r: t.transaction.r.into(),
            s: t.transaction.s.into(),
        }
    }

    pub fn into_signed(self) -> Result<SignedTransaction, Error> {
        let tx_with_sig = TransactionWithSignature {
            transaction: TransactionWithSignatureSerializePart {
                unsigned: PrimitiveTransaction {
                    nonce: self.nonce.into(),
                    gas_price: self.gas_price.into(),
                    gas: self.gas.into(),
                    action: match self.to {
                        None => Action::Create,
                        Some(address) => Action::Call(address.into()),
                    },
                    value: self.value.into(),
                    storage_limit: self.storage_limit.as_usize() as u64,
                    epoch_height: self.epoch_height.as_usize() as u64,
                    chain_id: self.chain_id.as_usize() as u64,
                    data: self.data.into(),
                },
                v: self.v.as_usize() as u8,
                r: self.r.into(),
                s: self.s.into(),
            },
            hash: self.hash.into(),
            rlp_size: None,
        };
        let public = tx_with_sig.recover_public()?;
        Ok(SignedTransaction::new(public, tx_with_sig))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxRequest {
    pub from: RpcH160,
    pub to: Option<RpcH160>,
    pub gas: RpcU256,
    pub gas_price: RpcU256,
    pub value: RpcU256,
    pub data: Option<Bytes>,
    pub nonce: Option<RpcU256>,
    pub storage_limit: Option<RpcU256>,
    pub chain_id: Option<RpcU256>,
    pub epoch_height: Option<RpcU256>,
}

impl SendTxRequest {
    pub fn sign_with(
        self, best_epoch_height: u64, chain_id: u64, password: Option<String>,
        accounts: Arc<AccountProvider>,
    ) -> Result<TransactionWithSignature, String>
    {
        let tx = PrimitiveTransaction {
            nonce: self.nonce.unwrap_or_default().into(),
            gas_price: self.gas_price.into(),
            gas: self.gas.into(),
            action: match self.to {
                None => Action::Create,
                Some(address) => Action::Call(address.into()),
            },
            value: self.value.into(),
            storage_limit: self
                .storage_limit
                .unwrap_or(std::u64::MAX.into())
                .as_usize() as u64,
            epoch_height: self
                .epoch_height
                .unwrap_or(best_epoch_height.into())
                .as_usize() as u64,
            chain_id: self.chain_id.unwrap_or(chain_id.into()).as_usize()
                as u64,
            data: self.data.unwrap_or(Bytes::new(vec![])).into(),
        };

        let password = password.map(Password::from);
        let sig = accounts
            .sign(self.from.into(), password, tx.hash())
            .map_err(|e| format!("failed to sign transaction: {:?}", e))?;

        Ok(tx.with_signature(sig))
    }
}
