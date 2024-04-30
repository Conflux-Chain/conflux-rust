use crate::{
    transaction::AccessList, Action, SignedTransaction, Transaction,
    TransactionWithSignature, TransactionWithSignatureSerializePart,
};
use bytes::Bytes;
use cfx_types::{AddressWithSpace, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde_derive::{Deserialize, Serialize};
use crate::transaction::AccessListItem;

#[derive(
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
    RlpEncodable,
    RlpDecodable,
    Serialize,
    Deserialize,
)]
pub struct NativeTransaction {
    /// Nonce.
    pub nonce: U256,
    /// Gas price.
    pub gas_price: U256,
    /// Gas paid up front for transaction execution.
    pub gas: U256,
    /// Action, can be either call or contract create.
    pub action: Action,
    /// Transferred value.
    pub value: U256,
    /// Maximum storage increasement in this execution.
    pub storage_limit: u64,
    /// The epoch height of the transaction. A transaction
    /// can only be packed between the epochs of [epoch_height -
    /// TRANSACTION_EPOCH_BOUND, epoch_height + TRANSACTION_EPOCH_BOUND]
    pub epoch_height: u64,
    /// The chain id of the transaction
    pub chain_id: u32,
    /// Transaction data.
    pub data: Bytes,
}

impl NativeTransaction {
    /// Specify the sender; this won't survive the serialize/deserialize
    /// process, but can be cloned.
    pub fn fake_sign(self, from: AddressWithSpace) -> SignedTransaction {
        SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: Transaction::Native(
                        TypedNativeTransaction::Cip155(self),
                    ),
                    r: U256::one(),
                    s: U256::one(),
                    v: 0,
                },
                hash: H256::zero(),
                rlp_size: None,
            }
            .compute_hash(),
            sender: from.address,
            public: None,
        }
    }
}

#[derive(
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
    RlpEncodable,
    RlpDecodable,
    Serialize,
    Deserialize,
)]
pub struct Cip2930Transaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub action: Action,
    pub value: U256,
    pub storage_limit: u64,
    pub epoch_height: u64,
    pub chain_id: u32,
    pub data: Bytes,
    // We do not use `AccessList` here because we need `Vec` for rlp derive.
    pub access_list: Vec<AccessListItem>,
}

#[derive(
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
    RlpEncodable,
    RlpDecodable,
    Serialize,
    Deserialize,
)]
pub struct Cip1559Transaction {
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas: U256,
    pub action: Action,
    pub value: U256,
    pub storage_limit: u64,
    pub epoch_height: u64,
    pub chain_id: u32,
    pub data: Bytes,
    // We do not use `AccessList` here because we need `Vec` for rlp derive.
    pub access_list: Vec<AccessListItem>,
}

macro_rules! access_common_ref {
    ($field:ident, $ty:ty) => {
        pub fn $field(&self) -> &$ty {
            match self {
                TypedNativeTransaction::Cip155(tx) => &tx.$field,
                TypedNativeTransaction::Cip2930(tx) => &tx.$field,
                TypedNativeTransaction::Cip1559(tx) => &tx.$field,
            }
        }
    };
}

impl TypedNativeTransaction {
    access_common_ref!(gas, U256);

    access_common_ref!(data, Bytes);

    access_common_ref!(nonce, U256);

    access_common_ref!(action, Action);

    access_common_ref!(value, U256);

    access_common_ref!(chain_id, u32);

    access_common_ref!(epoch_height, u64);

    access_common_ref!(storage_limit, u64);

    pub fn gas_price(&self) -> &U256 {
        match self {
            TypedNativeTransaction::Cip155(tx) => &tx.gas_price,
            TypedNativeTransaction::Cip1559(tx) => &tx.max_fee_per_gas,
            TypedNativeTransaction::Cip2930(tx) => &tx.gas_price,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypedNativeTransaction {
    Cip155(NativeTransaction),
    Cip2930(Cip2930Transaction),
    Cip1559(Cip1559Transaction),
}
