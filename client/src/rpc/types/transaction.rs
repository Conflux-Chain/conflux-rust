// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{receipt::Receipt, Bytes, RpcAddress};
use cfx_addr::Network;
use cfx_types::{H256, U256, U64};
use cfxkey::Error;
use primitives::{
    transaction::Action, SignedTransaction,
    Transaction as PrimitiveTransaction, TransactionIndex,
    TransactionWithSignature, TransactionWithSignatureSerializePart,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: H256,
    pub nonce: U256,
    pub block_hash: Option<H256>,
    pub transaction_index: Option<U64>,
    pub from: RpcAddress,
    pub to: Option<RpcAddress>,
    pub value: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub contract_created: Option<RpcAddress>,
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

pub enum PackedOrExecuted {
    Packed(TransactionIndex),
    Executed(Receipt),
}

impl Transaction {
    pub fn default(network: Network) -> Result<Transaction, String> {
        Ok(Transaction {
            hash: Default::default(),
            nonce: Default::default(),
            block_hash: Default::default(),
            transaction_index: Default::default(),
            from: RpcAddress::null(network)?,
            to: Default::default(),
            value: Default::default(),
            gas_price: Default::default(),
            gas: Default::default(),
            contract_created: Default::default(),
            data: Default::default(),
            storage_limit: Default::default(),
            epoch_height: Default::default(),
            chain_id: Default::default(),
            status: Default::default(),
            v: Default::default(),
            r: Default::default(),
            s: Default::default(),
        })
    }

    pub fn from_signed(
        t: &SignedTransaction,
        maybe_packed_or_executed: Option<PackedOrExecuted>, network: Network,
    ) -> Result<Transaction, String>
    {
        let mut contract_created = None;
        let mut status: Option<U64> = None;
        let mut block_hash = None;
        let mut transaction_index = None;
        match maybe_packed_or_executed {
            None => {}
            Some(PackedOrExecuted::Packed(tx_index)) => {
                block_hash = Some(tx_index.block_hash);
                transaction_index = Some(tx_index.index.into());
            }
            Some(PackedOrExecuted::Executed(receipt)) => {
                block_hash = Some(receipt.block_hash);
                transaction_index = Some(receipt.index.into());
                if let Some(ref address) = receipt.contract_created {
                    contract_created = Some(address.clone());
                }
                status = Some(receipt.outcome_status);
            }
        }
        Ok(Transaction {
            hash: t.transaction.hash().into(),
            nonce: t.nonce.into(),
            block_hash,
            transaction_index,
            status,
            contract_created,
            from: RpcAddress::try_from_h160(t.sender(), network)?,
            to: match t.action {
                Action::Create => None,
                Action::Call(ref address) => {
                    Some(RpcAddress::try_from_h160(address.clone(), network)?)
                }
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
        })
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

#[derive(Default, Serialize)]
pub struct TxWithPoolInfo {
    pub exist: bool,
    pub packed: bool,
    pub local_nonce: U256,
    pub local_balance: U256,
    pub state_nonce: U256,
    pub state_balance: U256,
    pub local_balance_enough: bool,
    pub state_balance_enough: bool,
}

#[derive(Default, Serialize)]
pub struct TxPoolPendingInfo {
    pub pending_count: usize,
    pub min_nonce: U256,
    pub max_nonce: U256,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPendingInfo {
    pub local_nonce: U256,
    pub pending_count: U256,
    pub pending_nonce: U256,
    pub next_pending_tx: H256,
}
