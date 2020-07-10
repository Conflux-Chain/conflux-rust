// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{receipt::Receipt, Bytes};
use cfx_types::{H160, H256, U256, U64};
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
    pub hash: H256,
    pub nonce: U256,
    pub block_hash: Option<H256>,
    pub transaction_index: Option<U64>,
    pub from: H160,
    pub to: Option<H160>,
    pub value: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub contract_created: Option<H160>,
    pub data: Bytes,
    pub storage_limit: U256,
    pub epoch_height: U256,
    pub chain_id: U256,
    pub status: Option<U64>,
    /// The standardised V field of the signature.
    pub v: U256,
    /// The R field of the signature.
    pub r: U256,
    /// The S field of the signature.
    pub s: U256,
}

impl Transaction {
    pub fn from_signed(
        t: &SignedTransaction, receipt: Option<Receipt>,
    ) -> Transaction {
        let mut contract_created = None;
        let mut status: Option<U64> = None;
        if let Some(ref receipt) = receipt {
            if let Some(ref address) = receipt.contract_created {
                contract_created = Some(address.clone().into());
            }
            status = Some(receipt.outcome_status);
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
                    storage_limit: self.storage_limit.as_u64(),
                    epoch_height: self.epoch_height.as_u64(),
                    chain_id: self.chain_id.as_u32(),
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
    pub from: H160,
    pub to: Option<H160>,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Option<Bytes>,
    pub nonce: Option<U256>,
    pub storage_limit: Option<U256>,
    pub chain_id: Option<U256>,
    pub epoch_height: Option<U256>,
}

impl SendTxRequest {
    pub fn sign_with(
        self, best_epoch_height: u64, chain_id: u32, password: Option<String>,
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
            chain_id: self.chain_id.unwrap_or(chain_id.into()).as_u32(),
            data: self.data.unwrap_or(Bytes::new(vec![])).into(),
        };

        let password = password.map(Password::from);
        let sig = accounts
            .sign(self.from.into(), password, tx.hash())
            .map_err(|e| format!("failed to sign transaction: {:?}", e))?;

        Ok(tx.with_signature(sig))
    }
}
