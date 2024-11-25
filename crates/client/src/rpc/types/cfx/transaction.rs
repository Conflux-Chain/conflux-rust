// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    cfx::{from_primitive_access_list, receipt::Receipt, CfxAccessList},
    eth::Transaction as ETHTransaction,
    Bytes, RpcAddress,
};
use cfx_addr::Network;
use cfx_types::{Space, H256, U256, U64};
use cfxkey::Error;
use primitives::{
    transaction::{
        eth_transaction::Eip155Transaction,
        native_transaction::NativeTransaction, Action,
    },
    SignedTransaction, Transaction as PrimitiveTransaction, TransactionIndex,
    TransactionWithSignature, TransactionWithSignatureSerializePart,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WrapTransaction {
    NativeTransaction(Transaction),
    EthTransaction(ETHTransaction),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<Space>,
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
    pub chain_id: Option<U256>,
    pub status: Option<U64>,
    /// Optional access list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<CfxAccessList>,
    /// miner bribe
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    /// Max fee per gas
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    /// The standardised V field of the signature.
    pub v: U256,
    /// The R field of the signature.
    pub r: U256,
    /// The S field of the signature.
    pub s: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y_parity: Option<U64>,
}

pub enum PackedOrExecuted {
    Packed(TransactionIndex),
    Executed(Receipt),
}

impl Transaction {
    pub fn default(network: Network) -> Result<Transaction, String> {
        Ok(Transaction {
            space: None,
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
            chain_id: Some(U256::one()),
            status: Default::default(),
            v: Default::default(),
            r: Default::default(),
            s: Default::default(),
            access_list: Default::default(),
            max_priority_fee_per_gas: Default::default(),
            max_fee_per_gas: Default::default(),
            y_parity: Default::default(),
            transaction_type: Default::default(),
        })
    }

    pub fn from_signed(
        t: &SignedTransaction,
        maybe_packed_or_executed: Option<PackedOrExecuted>, network: Network,
    ) -> Result<Transaction, String> {
        let mut contract_created = None;
        let mut status: Option<U64> = None;
        let mut block_hash = None;
        let mut transaction_index = None;
        match maybe_packed_or_executed {
            None => {}
            Some(PackedOrExecuted::Packed(tx_index)) => {
                block_hash = Some(tx_index.block_hash);
                transaction_index = Some(
                    tx_index.rpc_index.unwrap_or(tx_index.real_index).into(),
                );
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
        let (storage_limit, epoch_height) =
            if let PrimitiveTransaction::Native(ref tx) = t.unsigned {
                (*tx.storage_limit(), *tx.epoch_height())
            } else {
                (0, 0)
            };
        let space = match t.space() {
            Space::Native => None,
            Space::Ethereum => Some(Space::Ethereum),
        };
        Ok(Transaction {
            space,
            hash: t.transaction.hash().into(),
            nonce: t.nonce().into(),
            block_hash,
            transaction_index,
            status,
            contract_created,
            from: RpcAddress::try_from_h160(t.sender().address, network)?,
            to: match t.action() {
                Action::Create => None,
                Action::Call(ref address) => {
                    Some(RpcAddress::try_from_h160(address.clone(), network)?)
                }
            },
            value: t.value().into(),
            gas_price: t.gas_price().into(),
            gas: t.gas().into(),
            data: t.data().clone().into(),
            storage_limit: storage_limit.into(),
            epoch_height: epoch_height.into(),
            chain_id: t.chain_id().map(|x| U256::from(x as u64)),
            access_list: t
                .access_list()
                .cloned()
                .map(|list| from_primitive_access_list(list, network)),
            max_fee_per_gas: t.after_1559().then_some(*t.gas_price()),
            max_priority_fee_per_gas: t
                .after_1559()
                .then_some(*t.max_priority_gas_price()),
            y_parity: t.is_2718().then_some(t.transaction.v.into()),
            transaction_type: Some(U64::from(t.type_id())),
            v: t.transaction.v.into(),
            r: t.transaction.r.into(),
            s: t.transaction.s.into(),
        })
    }

    pub fn into_signed(self) -> Result<SignedTransaction, Error> {
        let tx_with_sig = TransactionWithSignature {
            transaction: TransactionWithSignatureSerializePart {
                unsigned: if self.space == Some(Space::Ethereum) {
                    Eip155Transaction {
                        nonce: self.nonce.into(),
                        gas_price: self.gas_price.into(),
                        gas: self.gas.into(),
                        action: match self.to {
                            None => Action::Create,
                            Some(address) => Action::Call(address.into()),
                        },
                        value: self.value.into(),
                        chain_id: self.chain_id.map(|x| x.as_u32()),
                        data: self.data.into(),
                    }
                    .into()
                } else {
                    NativeTransaction {
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
                        chain_id: self
                            .chain_id
                            .ok_or(Error::Custom(
                                "Native transaction must have chain_id".into(),
                            ))?
                            .as_u32(),
                        data: self.data.into(),
                    }
                    .into()
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
