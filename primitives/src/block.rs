// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    transaction::TxShortId, BlockHeader, SignedTransaction,
    TransactionWithSignature,
};
use byteorder::{ByteOrder, LittleEndian};
use cfx_types::{H256, U256};
use heapsize::HeapSizeOf;
use keccak_hash::keccak;
use rand::Rng;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use siphasher::sip::SipHasher24;
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    hash::Hasher,
    sync::Arc,
};

pub const MAX_TRANSACTION_COUNT_PER_BLOCK: usize = 20000;
pub const MAX_BLOCK_SIZE_IN_BYTES: usize = 4 * 1024 * 1024;

pub type BlockNumber = u64;

/// A block, encoded as it is on the block chain.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    /// The header hash of this block.
    pub block_header: BlockHeader,
    /// The transactions in this block.
    pub transactions: Vec<Arc<SignedTransaction>>,
    /// Approximated rlp size of the block.
    pub approximated_rlp_size: usize,
    /// Approximated rlp size of block with transaction public key.
    pub approximated_rlp_size_with_public: usize,
}

impl HeapSizeOf for Block {
    fn heap_size_of_children(&self) -> usize {
        self.block_header.heap_size_of_children()
            + SignedTransaction::heap_size_of_iter(self.transactions.iter())
    }
}

impl Block {
    pub fn new(
        block_header: BlockHeader, transactions: Vec<Arc<SignedTransaction>>,
    ) -> Self {
        Self::new_with_rlp_size(block_header, transactions, None, None)
    }

    pub fn new_with_rlp_size(
        block_header: BlockHeader, transactions: Vec<Arc<SignedTransaction>>,
        rlp_size: Option<usize>, rlp_size_with_public: Option<usize>,
    ) -> Self
    {
        let approximated_rlp_size = match rlp_size {
            Some(size) => size,
            None => transactions
                .iter()
                .fold(block_header.approximated_rlp_size(), |accum, tx| {
                    accum + tx.rlp_size()
                }),
        };

        let approximated_rlp_size_with_public = match rlp_size_with_public {
            Some(size) => size,
            None => approximated_rlp_size + transactions.len() * 84, /* Sender(20B) + Public(64B) */
        };

        Block {
            block_header,
            transactions,
            approximated_rlp_size,
            approximated_rlp_size_with_public,
        }
    }

    pub fn hash(&self) -> H256 { self.block_header.hash() }

    /// Approximated rlp size of the block.
    pub fn approximated_rlp_size(&self) -> usize { self.approximated_rlp_size }

    /// Approximated rlp size of block with transaction public key.
    pub fn approximated_rlp_size_with_public(&self) -> usize {
        self.approximated_rlp_size_with_public
    }

    pub fn total_gas(&self) -> U256 {
        let mut sum = U256::from(0);
        for t in &self.transactions {
            sum += t.gas;
        }
        sum
    }

    pub fn size(&self) -> usize {
        let mut ret = self.block_header.size();
        for t in &self.transactions {
            ret += t.size();
        }
        ret
    }

    pub fn transaction_hashes(&self) -> Vec<H256> {
        self.transactions
            .iter()
            .map(|tx| tx.hash())
            .collect::<Vec<_>>()
    }

    /// Construct a new compact block with random nonce
    /// This block will be relayed with the new compact block to prevent
    /// adversaries to make tx shortId collision
    pub fn to_compact(&self) -> CompactBlock {
        let nonce: u64 = rand::thread_rng().gen();
        let (k0, k1) = get_shortid_key(&self.block_header, &nonce);
        CompactBlock {
            block_header: self.block_header.clone(),
            nonce,
            tx_short_ids: self
                .transactions
                .iter()
                .map(|tx| from_tx_hash(&tx.hash(), k0, k1))
                .collect(),
            // reconstructed_txes constructed here will not be used
            reconstructed_txes: Vec::new(),
        }
    }

    pub fn compute_transaction_root(
        transactions: &Vec<Arc<SignedTransaction>>,
    ) -> H256 {
        let mut rlp_stream = RlpStream::new_list(transactions.len());
        for tx in transactions {
            rlp_stream.append(tx.as_ref());
        }
        keccak(rlp_stream.out())
    }

    pub fn encode_body_with_tx_public(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.begin_list(self.transactions.len());
        for tx in &self.transactions {
            stream.append(tx.as_ref());
        }
        stream.drain()
    }

    pub fn decode_body_with_tx_public(
        rlp: &Rlp,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }

        let signed_transactions = rlp.as_list()?;
        let mut transactions = Vec::with_capacity(signed_transactions.len());
        for tx in signed_transactions {
            transactions.push(Arc::new(tx));
        }

        Ok(transactions)
    }

    pub fn encode_with_tx_public(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream
            .begin_list(2)
            .append(&self.block_header)
            .append_raw(&*self.encode_body_with_tx_public(), 1);
        stream.drain()
    }

    pub fn decode_with_tx_public(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(Block::new_with_rlp_size(
            rlp.val_at(0)?,
            Self::decode_body_with_tx_public(&rlp.at(1)?)?,
            None,
            Some(rlp.as_raw().len()),
        ))
    }
}

// The encode of Block only serializes TransactionWithSignature
// without "sender" and "public" fields.
impl Encodable for Block {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2).append(&self.block_header);
        stream.begin_list(self.transactions.len());
        for tx in &self.transactions {
            stream.append(&tx.transaction);
        }
    }
}

// The decode of Block only deserializes TransactionWithSignature
// without "sender" and "public" fields. So need to recover public later.
impl Decodable for Block {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.as_raw().len() != rlp.payload_info()?.total() {
            return Err(DecoderError::RlpIsTooBig);
        }
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let transactions = rlp.list_at::<TransactionWithSignature>(1)?;

        let mut signed_transactions = Vec::with_capacity(transactions.len());
        for tx in transactions {
            let signed = SignedTransaction::new_unsigned(tx);
            signed_transactions.push(Arc::new(signed));
        }

        Ok(Block::new_with_rlp_size(
            rlp.val_at(0)?,
            signed_transactions,
            Some(rlp.as_raw().len()),
            None,
        ))
    }
}

// TODO Some optimization may be made if short_id hash collission is detected,
// but should be rare
#[derive(Clone, PartialEq)]
pub struct CompactBlock {
    /// The block header
    pub block_header: BlockHeader,
    /// The nonce for use in short id calculation
    pub nonce: u64,
    /// A list of tx short ids
    pub tx_short_ids: Vec<TxShortId>,
    /// Store the txes reconstructed, None means not received
    pub reconstructed_txes: Vec<Option<Arc<SignedTransaction>>>,
}

impl Debug for CompactBlock {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "CompactBlock{{ block_header: {:?}, nonce: {:?}}}",
            self.block_header, self.nonce
        )
    }
}

impl HeapSizeOf for CompactBlock {
    fn heap_size_of_children(&self) -> usize {
        self.tx_short_ids.heap_size_of_children()
            + self.reconstructed_txes.heap_size_of_children()
    }
}

impl CompactBlock {
    /// Find tx in tx_cache that matches tx_short_ids to fill in
    /// reconstruced_txes Return the differentially encoded index of missing
    /// transactions Now should only called once after CompactBlock is
    /// decoded
    pub fn build_partial(
        &mut self, tx_cache: &HashMap<H256, Arc<SignedTransaction>>,
    ) -> Vec<usize> {
        self.reconstructed_txes
            .resize(self.tx_short_ids.len(), None);
        let mut short_id_to_index =
            HashMap::with_capacity(self.tx_short_ids.len());
        for (i, id) in self.tx_short_ids.iter().enumerate() {
            short_id_to_index.insert(id, i);
        }
        let (k0, k1) = get_shortid_key(&self.block_header, &self.nonce);
        for (tx_hash, tx) in tx_cache {
            let short_id = from_tx_hash(tx_hash, k0, k1);
            match short_id_to_index.remove(&short_id) {
                Some(index) => {
                    self.reconstructed_txes[index] = Some(tx.clone());
                }
                None => {}
            }
        }
        let mut missing_index = Vec::new();
        for index in short_id_to_index.values() {
            missing_index.push(*index);
        }
        missing_index.sort();
        let mut last = 0;
        let mut missing_encoded = Vec::new();
        for index in missing_index {
            missing_encoded.push(index - last);
            last = index + 1;
        }
        missing_encoded
    }

    pub fn hash(&self) -> H256 { self.block_header.hash() }
}

fn get_shortid_key(header: &BlockHeader, nonce: &u64) -> (u64, u64) {
    let mut stream = RlpStream::new();
    stream.begin_list(2).append(header).append(nonce);
    let to_hash = stream.out();
    let key_hash: [u8; 32] = keccak(to_hash).into();
    let k0 = LittleEndian::read_u64(&key_hash[0..8]);
    let k1 = LittleEndian::read_u64(&key_hash[8..16]);
    (k0, k1)
}

/// Compute Tx ShortId from hash. The algorithm is from Bitcoin BIP152
fn from_tx_hash(hash: &H256, k0: u64, k1: u64) -> TxShortId {
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(hash.as_ref());
    hasher.finish() & 0x00ffffff_ffffffff
}

impl Encodable for CompactBlock {
    fn rlp_append(&self, steam: &mut RlpStream) {
        steam
            .begin_list(3)
            .append(&self.block_header)
            .append(&self.nonce)
            .append_list(&self.tx_short_ids);
    }
}

impl Decodable for CompactBlock {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(CompactBlock {
            block_header: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            tx_short_ids: rlp.list_at(2)?,
            reconstructed_txes: Vec::new(),
        })
    }
}
