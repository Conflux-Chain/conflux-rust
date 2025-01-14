// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod eth_transaction;
pub mod native_transaction;

pub use eth_transaction::{
    Eip1559Transaction, Eip155Transaction, Eip2930Transaction,
    EthereumTransaction,
};
pub use native_transaction::{
    Cip1559Transaction, Cip2930Transaction, NativeTransaction,
    TypedNativeTransaction,
};

use crate::{
    bytes::Bytes,
    hash::keccak,
    keylib::{
        self, public_to_address, recover, verify_public, Public, Secret,
        Signature,
    },
};
use cfx_types::{
    Address, AddressSpaceUtil, AddressWithSpace, BigEndianHash, Space, H160,
    H256, U256,
};
use eth_transaction::eip155_signature;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rlp::{self, Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use std::{
    error, fmt,
    ops::{Deref, DerefMut},
};
use unexpected::OutOfBounds;

/// Fake address for unsigned transactions.
pub const UNSIGNED_SENDER: Address = H160([0xff; 20]);

pub const TYPED_NATIVE_TX_PREFIX: &[u8; 3] = b"cfx";
pub const TYPED_NATIVE_TX_PREFIX_BYTE: u8 = TYPED_NATIVE_TX_PREFIX[0];
pub const LEGACY_TX_TYPE: u8 = 0x00;
pub const EIP2930_TYPE: u8 = 0x01;
pub const EIP1559_TYPE: u8 = 0x02;
pub const CIP2930_TYPE: u8 = 0x01;
pub const CIP1559_TYPE: u8 = 0x02;

/// Shorter id for transactions in compact blocks
// TODO should be u48
pub type TxShortId = u64;

pub type TxPropagateId = u32;

// FIXME: Most errors here are bounded for TransactionPool and intended for rpc,
// FIXME: however these are unused, they are not errors for transaction itself.
// FIXME: Transaction verification and consensus related error can be separated.
#[derive(Debug, PartialEq, Clone, Eq)]
/// Errors concerning transaction processing.
pub enum TransactionError {
    /// Transaction is already imported to the queue
    AlreadyImported,
    /// Chain id in the transaction doesn't match the chain id of the network.
    ChainIdMismatch {
        expected: u32,
        got: u32,
        space: Space,
    },
    /// Epoch height out of bound.
    EpochHeightOutOfBound {
        block_height: u64,
        set: u64,
        transaction_epoch_bound: u64,
    },
    /// The gas paid for transaction is lower than base gas.
    NotEnoughBaseGas {
        /// Absolute minimum gas required.
        required: U256,
        /// Gas provided.
        got: U256,
    },
    /// Transaction is not valid anymore (state already has higher nonce)
    Stale,
    /// Transaction has too low fee
    /// (there is already a transaction with the same sender-nonce but higher
    /// gas price)
    TooCheapToReplace,
    /// Transaction was not imported to the queue because limit has been
    /// reached.
    LimitReached,
    /// Transaction's gas price is below threshold.
    InsufficientGasPrice {
        /// Minimal expected gas price
        minimal: U256,
        /// Transaction gas price
        got: U256,
    },
    /// Transaction's gas is below currently set minimal gas requirement.
    InsufficientGas {
        /// Minimal expected gas
        minimal: U256,
        /// Transaction gas
        got: U256,
    },
    /// Sender doesn't have enough funds to pay for this transaction
    InsufficientBalance {
        /// Senders balance
        balance: U256,
        /// Transaction cost
        cost: U256,
    },
    /// Transactions gas is higher then current gas limit
    GasLimitExceeded {
        /// Current gas limit
        limit: U256,
        /// Declared transaction gas
        got: U256,
    },
    /// Transaction's gas limit (aka gas) is invalid.
    InvalidGasLimit(OutOfBounds<U256>),
    /// Signature error
    InvalidSignature(String),
    /// Transaction too big
    TooBig,
    /// Invalid RLP encoding
    InvalidRlp(String),
    ZeroGasPrice,
    /// Transaction types have not been activated
    FutureTransactionType,
    /// Receiver with invalid type bit.
    InvalidReceiver,
    /// Transaction nonce exceeds local limit.
    TooLargeNonce,
}

impl From<keylib::Error> for TransactionError {
    fn from(err: keylib::Error) -> Self {
        TransactionError::InvalidSignature(format!("{}", err))
    }
}

impl From<rlp::DecoderError> for TransactionError {
    fn from(err: rlp::DecoderError) -> Self {
        TransactionError::InvalidRlp(format!("{}", err))
    }
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::TransactionError::*;
        let msg = match *self {
            AlreadyImported => "Already imported".into(),
            ChainIdMismatch { expected, got, space } => {
                format!("Chain id mismatch, expected {}, got {}, space {:?}", expected, got, space)
            }
            EpochHeightOutOfBound {
                block_height,
                set,
                transaction_epoch_bound,
            } => format!(
                "EpochHeight out of bound:\
                 block_height {}, transaction epoch_height {}, transaction_epoch_bound {}",
                block_height, set, transaction_epoch_bound
            ),
            NotEnoughBaseGas { got, required } => format!(
                "Transaction gas {} less than intrinsic gas {}",
                got, required
            ),
            Stale => "No longer valid".into(),
            TooCheapToReplace => "Gas price too low to replace".into(),
            LimitReached => "Transaction limit reached".into(),
            InsufficientGasPrice { minimal, got } => format!(
                "Insufficient gas price. Min={}, Given={}",
                minimal, got
            ),
            InsufficientGas { minimal, got } => {
                format!("Insufficient gas. Min={}, Given={}", minimal, got)
            }
            InsufficientBalance { balance, cost } => format!(
                "Insufficient balance for transaction. Balance={}, Cost={}",
                balance, cost
            ),
            GasLimitExceeded { limit, got } => {
                format!("Gas limit exceeded. Limit={}, Given={}", limit, got)
            }
            InvalidGasLimit(ref err) => format!("Invalid gas limit. {}", err),
            InvalidSignature(ref err) => {
                format!("Transaction has invalid signature: {}.", err)
            }
            TooBig => "Transaction too big".into(),
            InvalidRlp(ref err) => {
                format!("Transaction has invalid RLP structure: {}.", err)
            }
            ZeroGasPrice => "Zero gas price is not allowed".into(),
            FutureTransactionType => "Ethereum like transaction should have u64::MAX storage limit".into(),
            InvalidReceiver => "Sending transaction to invalid address. The first four bits of address must be 0x0, 0x1, or 0x8.".into(),
            TooLargeNonce => "Transaction nonce is too large.".into(),
        };

        f.write_fmt(format_args!("Transaction error ({})", msg))
    }
}

impl error::Error for TransactionError {
    fn description(&self) -> &str { "Transaction error" }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Create creates new contract.
    Create,
    /// Calls contract at given address.
    /// In the case of a transfer, this is the receiver's address.'
    Call(Address),
}

impl Default for Action {
    fn default() -> Action { Action::Create }
}

impl Decodable for Action {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.is_empty() {
            Ok(Action::Create)
        } else {
            Ok(Action::Call(rlp.as_val()?))
        }
    }
}

impl Encodable for Action {
    fn rlp_append(&self, stream: &mut RlpStream) {
        match *self {
            Action::Create => stream.append_internal(&""),
            Action::Call(ref address) => stream.append_internal(address),
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

impl Encodable for AccessListItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.address);
        s.append_list(&self.storage_keys);
    }
}

impl Decodable for AccessListItem {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            address: rlp.val_at(0)?,
            storage_keys: rlp.list_at(1)?,
        })
    }
}

pub type AccessList = Vec<AccessListItem>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transaction {
    Native(TypedNativeTransaction),
    Ethereum(EthereumTransaction),
}

impl Default for Transaction {
    fn default() -> Self {
        Transaction::Native(TypedNativeTransaction::Cip155(Default::default()))
    }
}

impl From<NativeTransaction> for Transaction {
    fn from(tx: NativeTransaction) -> Self {
        Self::Native(TypedNativeTransaction::Cip155(tx))
    }
}

impl From<Eip155Transaction> for Transaction {
    fn from(tx: Eip155Transaction) -> Self {
        Self::Ethereum(EthereumTransaction::Eip155(tx))
    }
}

macro_rules! access_common_ref {
    ($field:ident, $ty:ty) => {
        pub fn $field(&self) -> &$ty {
            match self {
                Transaction::Native(tx) => tx.$field(),
                Transaction::Ethereum(tx) => tx.$field(),
            }
        }
    };
}

#[allow(unused)]
macro_rules! access_common {
    ($field:ident, $ty:ident) => {
        pub fn $field(&self) -> $ty {
            match self {
                Transaction::Native(tx) => tx.$field,
                Transaction::Ethereum(tx) => tx.$field,
            }
        }
    };
}
impl Transaction {
    access_common_ref!(gas, U256);

    access_common_ref!(gas_price, U256);

    access_common_ref!(max_priority_gas_price, U256);

    access_common_ref!(data, Bytes);

    access_common_ref!(nonce, U256);

    access_common_ref!(action, Action);

    access_common_ref!(value, U256);

    pub fn chain_id(&self) -> Option<u32> {
        match self {
            Transaction::Native(tx) => Some(*tx.chain_id()),
            Transaction::Ethereum(tx) => tx.chain_id().clone(),
        }
    }

    pub fn storage_limit(&self) -> Option<u64> {
        match self {
            Transaction::Native(tx) => Some(*tx.storage_limit()),
            Transaction::Ethereum(_tx) => None,
        }
    }

    pub fn nonce_mut(&mut self) -> &mut U256 {
        match self {
            Transaction::Native(tx) => tx.nonce_mut(),
            Transaction::Ethereum(tx) => tx.nonce_mut(),
        }
    }

    pub fn type_id(&self) -> u8 {
        match self {
            Transaction::Native(TypedNativeTransaction::Cip155(_))
            | Transaction::Ethereum(EthereumTransaction::Eip155(_)) => 0,

            Transaction::Native(TypedNativeTransaction::Cip2930(_))
            | Transaction::Ethereum(EthereumTransaction::Eip2930(_)) => 1,

            Transaction::Native(TypedNativeTransaction::Cip1559(_))
            | Transaction::Ethereum(EthereumTransaction::Eip1559(_)) => 2,
        }
    }

    pub fn is_legacy(&self) -> bool {
        matches!(
            self,
            Transaction::Native(TypedNativeTransaction::Cip155(_))
                | Transaction::Ethereum(EthereumTransaction::Eip155(_))
        )
    }

    pub fn is_2718(&self) -> bool { !self.is_legacy() }

    pub fn after_1559(&self) -> bool {
        matches!(
            self,
            Transaction::Native(TypedNativeTransaction::Cip1559(_))
                | Transaction::Ethereum(EthereumTransaction::Eip1559(_))
        )
    }

    pub fn access_list(&self) -> Option<&AccessList> {
        match self {
            Transaction::Native(tx) => tx.access_list(),
            Transaction::Ethereum(tx) => tx.access_list(),
        }
    }
}

impl Transaction {
    pub fn priority_gas_price(&self, base_price: &U256) -> U256 {
        std::cmp::min(
            *self.max_priority_gas_price(),
            self.gas_price() - base_price,
        )
    }

    pub fn effective_gas_price(&self, base_price: &U256) -> U256 {
        base_price + self.priority_gas_price(base_price)
    }

    // This function returns the hash value used in calculating the transaction
    // signature. It is different from transaction hash. The transaction
    // hash also contains signatures.
    pub fn hash_for_compute_signature(&self) -> H256 {
        let mut s = RlpStream::new();
        let mut type_prefix = vec![];
        match self {
            Transaction::Native(TypedNativeTransaction::Cip155(tx)) => {
                s.append(tx);
            }
            Transaction::Native(TypedNativeTransaction::Cip1559(tx)) => {
                s.append(tx);
                type_prefix.extend_from_slice(TYPED_NATIVE_TX_PREFIX);
                type_prefix.push(CIP1559_TYPE);
            }
            Transaction::Native(TypedNativeTransaction::Cip2930(tx)) => {
                s.append(tx);
                type_prefix.extend_from_slice(TYPED_NATIVE_TX_PREFIX);
                type_prefix.push(CIP2930_TYPE);
            }
            Transaction::Ethereum(EthereumTransaction::Eip155(tx)) => {
                s.append(tx);
            }
            Transaction::Ethereum(EthereumTransaction::Eip1559(tx)) => {
                s.append(tx);
                type_prefix.push(EIP1559_TYPE);
            }
            Transaction::Ethereum(EthereumTransaction::Eip2930(tx)) => {
                s.append(tx);
                type_prefix.push(EIP2930_TYPE);
            }
        };
        let encoded = s.as_raw();
        let mut out = vec![0; type_prefix.len() + encoded.len()];
        out[0..type_prefix.len()].copy_from_slice(&type_prefix);
        out[type_prefix.len()..].copy_from_slice(&encoded);
        keccak(&out)
    }

    pub fn space(&self) -> Space {
        match self {
            Transaction::Native(_) => Space::Native,
            Transaction::Ethereum(_) => Space::Ethereum,
        }
    }

    pub fn sign(self, secret: &Secret) -> SignedTransaction {
        let sig =
            crate::keylib::sign(secret, &self.hash_for_compute_signature())
                .expect(
                    "data is valid and context has signing capabilities; qed",
                );
        let tx_with_sig = self.with_signature(sig);
        let public = tx_with_sig
            .recover_public()
            .expect("secret is valid so it's recoverable");
        SignedTransaction::new(public, tx_with_sig)
    }

    /// Signs the transaction with signature.
    pub fn with_signature(self, sig: Signature) -> TransactionWithSignature {
        TransactionWithSignature {
            transaction: TransactionWithSignatureSerializePart {
                unsigned: self,
                r: sig.r().into(),
                s: sig.s().into(),
                v: sig.v(),
            },
            hash: H256::zero(),
            rlp_size: None,
        }
        .compute_hash()
    }
}

impl MallocSizeOf for Transaction {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.data().size_of(ops)
    }
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionWithSignatureSerializePart {
    /// Plain Transaction.
    pub unsigned: Transaction,
    /// The V field of the signature; helps describe which half of the curve
    /// our point falls in.
    pub v: u8,
    /// The R field of the signature; helps describe the point on the curve.
    pub r: U256,
    /// The S field of the signature; helps describe the point on the curve.
    pub s: U256,
}

impl Encodable for TransactionWithSignatureSerializePart {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.unsigned {
            Transaction::Native(TypedNativeTransaction::Cip155(ref tx)) => {
                s.begin_list(4);
                s.append(tx);
                s.append(&self.v);
                s.append(&self.r);
                s.append(&self.s);
            }
            Transaction::Ethereum(EthereumTransaction::Eip155(ref tx)) => {
                let Eip155Transaction {
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    data,
                    chain_id,
                } = tx;
                let legacy_v = eip155_signature::add_chain_replay_protection(
                    self.v,
                    chain_id.map(|x| x as u64),
                );
                s.begin_list(9);
                s.append(nonce);
                s.append(gas_price);
                s.append(gas);
                s.append(action);
                s.append(value);
                s.append(data);
                s.append(&legacy_v);
                s.append(&self.r);
                s.append(&self.s);
            }
            Transaction::Ethereum(EthereumTransaction::Eip2930(ref tx)) => {
                s.append_raw(&[EIP2930_TYPE], 0);
                s.begin_list(11);
                s.append(&tx.chain_id);
                s.append(&tx.nonce);
                s.append(&tx.gas_price);
                s.append(&tx.gas);
                s.append(&tx.action);
                s.append(&tx.value);
                s.append(&tx.data);
                s.append_list(&tx.access_list);
                s.append(&self.v);
                s.append(&self.r);
                s.append(&self.s);
            }
            Transaction::Ethereum(EthereumTransaction::Eip1559(ref tx)) => {
                s.append_raw(&[EIP1559_TYPE], 0);
                s.begin_list(12);
                s.append(&tx.chain_id);
                s.append(&tx.nonce);
                s.append(&tx.max_priority_fee_per_gas);
                s.append(&tx.max_fee_per_gas);
                s.append(&tx.gas);
                s.append(&tx.action);
                s.append(&tx.value);
                s.append(&tx.data);
                s.append_list(&tx.access_list);
                s.append(&self.v);
                s.append(&self.r);
                s.append(&self.s);
            }
            Transaction::Native(TypedNativeTransaction::Cip2930(ref tx)) => {
                s.append_raw(TYPED_NATIVE_TX_PREFIX, 0);
                s.append_raw(&[CIP2930_TYPE], 0);
                s.begin_list(4);
                s.append(tx);
                s.append(&self.v);
                s.append(&self.r);
                s.append(&self.s);
            }
            Transaction::Native(TypedNativeTransaction::Cip1559(ref tx)) => {
                s.append_raw(TYPED_NATIVE_TX_PREFIX, 0);
                s.append_raw(&[CIP1559_TYPE], 0);
                s.begin_list(4);
                s.append(tx);
                s.append(&self.v);
                s.append(&self.r);
                s.append(&self.s);
            }
        }
    }
}

impl Decodable for TransactionWithSignatureSerializePart {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() == 0 {
            return Err(DecoderError::RlpInvalidLength);
        }
        if rlp.is_list() {
            match rlp.item_count()? {
                4 => {
                    let unsigned: NativeTransaction = rlp.val_at(0)?;
                    let v: u8 = rlp.val_at(1)?;
                    let r: U256 = rlp.val_at(2)?;
                    let s: U256 = rlp.val_at(3)?;
                    Ok(TransactionWithSignatureSerializePart {
                        unsigned: Transaction::Native(
                            TypedNativeTransaction::Cip155(unsigned),
                        ),
                        v,
                        r,
                        s,
                    })
                }
                9 => {
                    let nonce: U256 = rlp.val_at(0)?;
                    let gas_price: U256 = rlp.val_at(1)?;
                    let gas: U256 = rlp.val_at(2)?;
                    let action: Action = rlp.val_at(3)?;
                    let value: U256 = rlp.val_at(4)?;
                    let data: Vec<u8> = rlp.val_at(5)?;
                    let legacy_v: u64 = rlp.val_at(6)?;
                    let r: U256 = rlp.val_at(7)?;
                    let s: U256 = rlp.val_at(8)?;

                    let v = eip155_signature::extract_standard_v(legacy_v);
                    let chain_id =
                        match eip155_signature::extract_chain_id_from_legacy_v(
                            legacy_v,
                        ) {
                            Some(chain_id) if chain_id > (u32::MAX as u64) => {
                                return Err(DecoderError::Custom(
                                    "Does not support chain_id >= 2^32",
                                ));
                            }
                            chain_id => chain_id.map(|x| x as u32),
                        };

                    Ok(TransactionWithSignatureSerializePart {
                        unsigned: Transaction::Ethereum(
                            EthereumTransaction::Eip155(Eip155Transaction {
                                nonce,
                                gas_price,
                                gas,
                                action,
                                value,
                                chain_id,
                                data,
                            }),
                        ),
                        v,
                        r,
                        s,
                    })
                }
                _ => Err(DecoderError::RlpInvalidLength),
            }
        } else {
            match rlp.as_raw()[0] {
                TYPED_NATIVE_TX_PREFIX_BYTE => {
                    if rlp.as_raw().len() <= 4
                        || rlp.as_raw()[0..3] != *TYPED_NATIVE_TX_PREFIX
                    {
                        return Err(DecoderError::RlpInvalidLength);
                    }
                    match rlp.as_raw()[3] {
                        CIP2930_TYPE => {
                            let rlp = Rlp::new(&rlp.as_raw()[4..]);
                            if rlp.item_count()? != 4 {
                                return Err(DecoderError::RlpIncorrectListLen);
                            }

                            let tx = rlp.val_at(0)?;
                            let v = rlp.val_at(1)?;
                            let r = rlp.val_at(2)?;
                            let s = rlp.val_at(3)?;
                            Ok(TransactionWithSignatureSerializePart {
                                unsigned: Transaction::Native(
                                    TypedNativeTransaction::Cip2930(tx),
                                ),
                                v,
                                r,
                                s,
                            })
                        }
                        CIP1559_TYPE => {
                            let rlp = Rlp::new(&rlp.as_raw()[4..]);
                            if rlp.item_count()? != 4 {
                                return Err(DecoderError::RlpIncorrectListLen);
                            }

                            let tx = rlp.val_at(0)?;
                            let v = rlp.val_at(1)?;
                            let r = rlp.val_at(2)?;
                            let s = rlp.val_at(3)?;
                            Ok(TransactionWithSignatureSerializePart {
                                unsigned: Transaction::Native(
                                    TypedNativeTransaction::Cip1559(tx),
                                ),
                                v,
                                r,
                                s,
                            })
                        }
                        _ => Err(DecoderError::RlpInvalidLength),
                    }
                }
                EIP2930_TYPE => {
                    let rlp = Rlp::new(&rlp.as_raw()[1..]);
                    if rlp.item_count()? != 11 {
                        return Err(DecoderError::RlpIncorrectListLen);
                    }

                    let tx = Eip2930Transaction {
                        chain_id: rlp.val_at(0)?,
                        nonce: rlp.val_at(1)?,
                        gas_price: rlp.val_at(2)?,
                        gas: rlp.val_at(3)?,
                        action: rlp.val_at(4)?,
                        value: rlp.val_at(5)?,
                        data: rlp.val_at(6)?,
                        access_list: rlp.list_at(7)?,
                    };
                    let v = rlp.val_at(8)?;
                    let r = rlp.val_at(9)?;
                    let s = rlp.val_at(10)?;
                    Ok(TransactionWithSignatureSerializePart {
                        unsigned: Transaction::Ethereum(
                            EthereumTransaction::Eip2930(tx),
                        ),
                        v,
                        r,
                        s,
                    })
                }
                EIP1559_TYPE => {
                    let rlp = Rlp::new(&rlp.as_raw()[1..]);
                    if rlp.item_count()? != 12 {
                        return Err(DecoderError::RlpIncorrectListLen);
                    }

                    let tx = Eip1559Transaction {
                        chain_id: rlp.val_at(0)?,
                        nonce: rlp.val_at(1)?,
                        max_priority_fee_per_gas: rlp.val_at(2)?,
                        max_fee_per_gas: rlp.val_at(3)?,
                        gas: rlp.val_at(4)?,
                        action: rlp.val_at(5)?,
                        value: rlp.val_at(6)?,
                        data: rlp.val_at(7)?,
                        access_list: rlp.list_at(8)?,
                    };
                    let v = rlp.val_at(9)?;
                    let r = rlp.val_at(10)?;
                    let s = rlp.val_at(11)?;
                    Ok(TransactionWithSignatureSerializePart {
                        unsigned: Transaction::Ethereum(
                            EthereumTransaction::Eip1559(tx),
                        ),
                        v,
                        r,
                        s,
                    })
                }
                _ => Err(DecoderError::RlpInvalidLength),
            }
        }
    }
}

impl Deref for TransactionWithSignatureSerializePart {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target { &self.unsigned }
}

impl DerefMut for TransactionWithSignatureSerializePart {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.unsigned }
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionWithSignature {
    /// Serialize part.
    pub transaction: TransactionWithSignatureSerializePart,
    /// Hash of the transaction
    #[serde(skip)]
    pub hash: H256,
    /// The transaction size when serialized in rlp
    #[serde(skip)]
    pub rlp_size: Option<usize>,
}

impl Deref for TransactionWithSignature {
    type Target = TransactionWithSignatureSerializePart;

    fn deref(&self) -> &Self::Target { &self.transaction }
}

impl DerefMut for TransactionWithSignature {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.transaction }
}

impl Decodable for TransactionWithSignature {
    fn decode(tx_rlp: &Rlp) -> Result<Self, DecoderError> {
        let rlp_size = Some(tx_rlp.as_raw().len());
        // The item count of TransactionWithSignatureSerializePart is checked in
        // its decoding.
        let hash;
        let transaction;
        if tx_rlp.is_list() {
            hash = keccak(tx_rlp.as_raw());
            // Vanilla tx encoding.
            transaction = tx_rlp.as_val()?;
        } else {
            // Typed tx encoding is wrapped as an RLP string.
            let b: Vec<u8> = tx_rlp.as_val()?;
            hash = keccak(&b);
            transaction = rlp::decode(&b)?;
        };
        Ok(TransactionWithSignature {
            transaction,
            hash,
            rlp_size,
        })
    }
}

impl Encodable for TransactionWithSignature {
    fn rlp_append(&self, s: &mut RlpStream) {
        match &self.transaction.unsigned {
            Transaction::Native(TypedNativeTransaction::Cip155(_))
            | Transaction::Ethereum(EthereumTransaction::Eip155(_)) => {
                s.append_internal(&self.transaction);
            }
            _ => {
                // Typed tx encoding is wrapped as an RLP string.
                s.append_internal(&rlp::encode(&self.transaction));
            }
        }
    }
}

impl TransactionWithSignature {
    pub fn new_unsigned(tx: Transaction) -> Self {
        TransactionWithSignature {
            transaction: TransactionWithSignatureSerializePart {
                unsigned: tx,
                s: 0.into(),
                r: 0.into(),
                v: 0,
            },
            hash: Default::default(),
            rlp_size: None,
        }
    }

    /// Used to compute hash of created transactions
    fn compute_hash(mut self) -> TransactionWithSignature {
        let hash = keccak(&*self.transaction.rlp_bytes());
        self.hash = hash;
        self
    }

    /// Checks whether signature is empty.
    pub fn is_unsigned(&self) -> bool { self.r.is_zero() && self.s.is_zero() }

    /// Construct a signature object from the sig.
    pub fn signature(&self) -> Signature {
        let r: H256 = BigEndianHash::from_uint(&self.r);
        let s: H256 = BigEndianHash::from_uint(&self.s);
        Signature::from_rsv(&r, &s, self.v)
    }

    /// Checks whether the signature has a low 's' value.
    pub fn check_low_s(&self) -> Result<(), keylib::Error> {
        if !self.signature().is_low_s() {
            Err(keylib::Error::InvalidSignature)
        } else {
            Ok(())
        }
    }

    pub fn check_y_parity(&self) -> Result<(), keylib::Error> {
        if self.is_2718() && self.v > 1 {
            // In Typed transactions (EIP-2718), v means y_parity, which must be
            // 0 or 1
            Err(keylib::Error::InvalidYParity)
        } else {
            Ok(())
        }
    }

    pub fn hash(&self) -> H256 { self.hash }

    /// Recovers the public key of the sender.
    pub fn recover_public(&self) -> Result<Public, keylib::Error> {
        Ok(recover(
            &self.signature(),
            &self.unsigned.hash_for_compute_signature(),
        )?)
    }

    pub fn rlp_size(&self) -> usize {
        self.rlp_size.unwrap_or_else(|| self.rlp_bytes().len())
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self, DecoderError> {
        Ok(TransactionWithSignature {
            transaction: Rlp::new(raw).as_val()?,
            hash: keccak(raw),
            rlp_size: Some(raw.len()),
        })
    }
}

impl MallocSizeOf for TransactionWithSignature {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.unsigned.size_of(ops)
    }
}

/// A signed transaction with successfully recovered `sender`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction: TransactionWithSignature,
    pub sender: Address,
    pub public: Option<Public>,
}

// The default encoder for local storage.
impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.transaction);
        s.append(&self.sender);
        s.append(&self.public);
    }
}

impl Decodable for SignedTransaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(SignedTransaction {
            transaction: rlp.val_at(0)?,
            sender: rlp.val_at(1)?,
            public: rlp.val_at(2)?,
        })
    }
}

impl Deref for SignedTransaction {
    type Target = TransactionWithSignature;

    fn deref(&self) -> &Self::Target { &self.transaction }
}

impl DerefMut for SignedTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.transaction }
}

impl From<SignedTransaction> for TransactionWithSignature {
    fn from(tx: SignedTransaction) -> Self { tx.transaction }
}

impl SignedTransaction {
    /// Try to verify transaction and recover sender.
    pub fn new(public: Public, transaction: TransactionWithSignature) -> Self {
        if transaction.is_unsigned() {
            SignedTransaction {
                transaction,
                sender: UNSIGNED_SENDER,
                public: None,
            }
        } else {
            let sender = public_to_address(
                &public,
                transaction.space() == Space::Native,
            );
            SignedTransaction {
                transaction,
                sender,
                public: Some(public),
            }
        }
    }

    pub fn new_unsigned(transaction: TransactionWithSignature) -> Self {
        SignedTransaction {
            transaction,
            sender: UNSIGNED_SENDER,
            public: None,
        }
    }

    pub fn set_public(&mut self, public: Public) {
        let type_nibble = self.unsigned.space() == Space::Native;
        self.sender = public_to_address(&public, type_nibble);
        self.public = Some(public);
    }

    /// Returns transaction sender.
    pub fn sender(&self) -> AddressWithSpace {
        self.sender.with_space(self.space())
    }

    pub fn nonce(&self) -> &U256 { self.transaction.nonce() }

    /// Checks if signature is empty.
    pub fn is_unsigned(&self) -> bool { self.transaction.is_unsigned() }

    pub fn hash(&self) -> H256 { self.transaction.hash() }

    pub fn gas(&self) -> &U256 { &self.transaction.gas() }

    pub fn gas_price(&self) -> &U256 { &self.transaction.gas_price() }

    pub fn gas_limit(&self) -> &U256 { &self.transaction.gas() }

    pub fn storage_limit(&self) -> Option<u64> {
        self.transaction.storage_limit()
    }

    pub fn rlp_size(&self) -> usize { self.transaction.rlp_size() }

    pub fn public(&self) -> &Option<Public> { &self.public }

    pub fn verify_public(&self, skip: bool) -> Result<bool, keylib::Error> {
        if self.public.is_none() {
            return Ok(false);
        }

        if !skip {
            let public = self.public.unwrap();
            Ok(verify_public(
                &public,
                &self.signature(),
                &self.unsigned.hash_for_compute_signature(),
            )?)
        } else {
            Ok(true)
        }
    }
}

impl MallocSizeOf for SignedTransaction {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.transaction.size_of(ops)
    }
}
