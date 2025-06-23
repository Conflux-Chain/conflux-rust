use super::AuthorizationListItem;
use crate::{
    bytes::Bytes, transaction::AccessList, AccessListItem, Action,
    AuthorizationList, SignedTransaction, Transaction,
    TransactionWithSignature, TransactionWithSignatureSerializePart,
};
use cfx_types::{AddressWithSpace, H256, U256};
use cfxkey::Address;
use rlp::{Encodable, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde_derive::{Deserialize, Serialize};

impl Eip155Transaction {
    /// Fake sign phantom transactions.
    // The signature is part of the hash input. This implementation
    // ensures that phantom transactions whose fields are identical
    // will have different hashes.
    pub fn fake_sign_phantom(
        self, from: AddressWithSpace,
    ) -> SignedTransaction {
        SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: Transaction::Ethereum(
                        EthereumTransaction::Eip155(self),
                    ),
                    // we use sender address for `r` and `s` so that
                    // phantom transactions with matching
                    // fields from different senders
                    // will have different hashes
                    r: U256::from(from.address.as_ref()),
                    s: U256::from(from.address.as_ref()),
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

    /// Fake sign call requests in `eth_call`.
    // `fake_sign_phantom` will use zero signature when the sender is the
    // zero address, and that will fail basic signature verification.
    pub fn fake_sign_rpc(self, from: AddressWithSpace) -> SignedTransaction {
        SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: Transaction::Ethereum(
                        EthereumTransaction::Eip155(self),
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

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Eip155Transaction {
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
    /// The chain id of the transaction
    pub chain_id: Option<u32>,
    /// Transaction data.
    pub data: Bytes,
}

impl Encodable for Eip155Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.chain_id {
            Some(chain_id) => {
                s.begin_list(9);
                s.append(&self.nonce);
                s.append(&self.gas_price);
                s.append(&self.gas);
                s.append(&self.action);
                s.append(&self.value);
                s.append(&self.data);
                s.append(&chain_id);
                s.append(&0u8);
                s.append(&0u8);
            }
            None => {
                s.begin_list(6);
                s.append(&self.nonce);
                s.append(&self.gas_price);
                s.append(&self.gas);
                s.append(&self.action);
                s.append(&self.value);
                s.append(&self.data);
            }
        }
    }
}

#[derive(
    Default,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpDecodable,
)]
pub struct Eip2930Transaction {
    pub chain_id: u32,
    pub nonce: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub action: Action,
    pub value: U256,
    pub data: Bytes,
    pub access_list: Vec<AccessListItem>,
}

#[derive(
    Default,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpDecodable,
)]
pub struct Eip1559Transaction {
    pub chain_id: u32,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas: U256,
    pub action: Action,
    pub value: U256,
    pub data: Bytes,
    pub access_list: Vec<AccessListItem>,
}

#[derive(
    Default,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpDecodable,
)]
pub struct Eip7702Transaction {
    pub chain_id: u32,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas: U256,
    pub destination: Address,
    pub value: U256,
    pub data: Bytes,
    pub access_list: Vec<AccessListItem>,
    pub authorization_list: Vec<AuthorizationListItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthereumTransaction {
    Eip155(Eip155Transaction),
    Eip1559(Eip1559Transaction),
    Eip2930(Eip2930Transaction),
    Eip7702(Eip7702Transaction),
}
use EthereumTransaction::*;

impl EthereumTransaction {
    pub fn fake_sign_rpc(self, from: AddressWithSpace) -> SignedTransaction {
        SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: Transaction::Ethereum(self),
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

macro_rules! eth_access_common_ref {
    ($field:ident, $ty:ty) => {
        pub fn $field(&self) -> &$ty {
            match self {
                EthereumTransaction::Eip155(tx) => &tx.$field,
                EthereumTransaction::Eip2930(tx) => &tx.$field,
                EthereumTransaction::Eip1559(tx) => &tx.$field,
                EthereumTransaction::Eip7702(tx) => &tx.$field,
            }
        }
    };
}

impl EthereumTransaction {
    eth_access_common_ref!(gas, U256);

    eth_access_common_ref!(data, Bytes);

    eth_access_common_ref!(nonce, U256);

    eth_access_common_ref!(value, U256);

    pub fn action(&self) -> Action {
        match self {
            Eip155(tx) => tx.action,
            Eip1559(tx) => tx.action,
            Eip2930(tx) => tx.action,
            Eip7702(tx) => Action::Call(tx.destination),
        }
    }

    pub fn gas_price(&self) -> &U256 {
        match self {
            Eip155(tx) => &tx.gas_price,
            Eip1559(tx) => &tx.max_fee_per_gas,
            Eip2930(tx) => &tx.gas_price,
            Eip7702(tx) => &tx.max_fee_per_gas,
        }
    }

    pub fn max_priority_gas_price(&self) -> &U256 {
        match self {
            Eip155(tx) => &tx.gas_price,
            Eip1559(tx) => &tx.max_priority_fee_per_gas,
            Eip2930(tx) => &tx.gas_price,
            Eip7702(tx) => &tx.max_priority_fee_per_gas,
        }
    }

    pub fn chain_id(&self) -> Option<u32> {
        match self {
            Eip155(tx) => tx.chain_id,
            Eip1559(tx) => Some(tx.chain_id),
            Eip2930(tx) => Some(tx.chain_id),
            Eip7702(tx) => Some(tx.chain_id),
        }
    }

    pub fn nonce_mut(&mut self) -> &mut U256 {
        match self {
            Eip155(tx) => &mut tx.nonce,
            Eip2930(tx) => &mut tx.nonce,
            Eip1559(tx) => &mut tx.nonce,
            Eip7702(tx) => &mut tx.nonce,
        }
    }

    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Eip155(tx) => &mut tx.data,
            Eip2930(tx) => &mut tx.data,
            Eip1559(tx) => &mut tx.data,
            Eip7702(tx) => &mut tx.data,
        }
    }

    pub fn access_list(&self) -> Option<&AccessList> {
        match self {
            Eip155(_tx) => None,
            Eip2930(tx) => Some(&tx.access_list),
            Eip1559(tx) => Some(&tx.access_list),
            Eip7702(tx) => Some(&tx.access_list),
        }
    }

    pub fn authorization_list(&self) -> Option<&AuthorizationList> {
        if let Eip7702(tx) = self {
            Some(&tx.authorization_list)
        } else {
            None
        }
    }
}

/// Replay protection logic for v part of transaction's signature
pub mod eip155_signature {
    /// Adds chain id into v
    pub fn add_chain_replay_protection(v: u8, chain_id: Option<u64>) -> u64 {
        v as u64
            + if let Some(n) = chain_id {
                35 + n * 2
            } else {
                27
            }
    }

    /// Returns refined v
    /// 0 if `v` would have been 27 under "Electrum" notation, 1 if 28 or 4 if
    /// invalid.
    pub fn extract_standard_v(v: u64) -> u8 {
        match v {
            v if v == 27 => 0,
            v if v == 28 => 1,
            v if v >= 35 => ((v - 1) % 2) as u8,
            _ => 4,
        }
    }

    pub fn extract_chain_id_from_legacy_v(v: u64) -> Option<u64> {
        if v >= 35 {
            Some((v - 35) / 2 as u64)
        } else {
            None
        }
    }
}
