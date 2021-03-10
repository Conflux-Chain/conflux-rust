// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{BlockHeader, SignedTransaction, TransactionWithSignature};
use byteorder::{ByteOrder, LittleEndian};
use cfx_types::{H256, U256};
use keccak_hash::keccak;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rand::Rng;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use siphasher::sip::SipHasher24;
use std::{
    fmt::{Debug, Formatter},
    hash::Hasher,
    sync::Arc,
};

pub type BlockNumber = u64;
pub type BlockHeight = u64;

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

impl MallocSizeOf for Block {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.block_header.size_of(ops) + self.transactions.size_of(ops)
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
    ) -> Self {
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

    pub fn hash(&self) -> H256 {
        self.block_header.hash()
    }

    /// Approximated rlp size of the block.
    pub fn approximated_rlp_size(&self) -> usize {
        self.approximated_rlp_size
    }

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

    /// The size filled in the RPC response. It returns the approximate rlp size
    /// of the block.
    pub fn size(&self) -> usize {
        // FIXME: Because the approximate rlp size of the header may deviate
        // FIXME: from the real rlp, now we always recalculate this to
        // FIXME: avoid it failing the test case. One possible long term
        // FIXME: correct solution is to implement a size calculation
        // FIXME: that is consistent with the rlp.
        self.transactions
            .iter()
            .fold(0, |accum, tx| accum + tx.rlp_size())
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
        let (k0, k1) =
            CompactBlock::get_shortid_key(&self.block_header, &nonce);
        CompactBlock {
            block_header: self.block_header.clone(),
            nonce,
            tx_short_ids: CompactBlock::create_shortids(
                &self.transactions,
                k0,
                k1,
            ),
            // reconstructed_txns constructed here will not be used
            reconstructed_txns: Vec::new(),
        }
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
    pub tx_short_ids: Vec<u8>,
    /// Store the txns reconstructed, None means not received
    pub reconstructed_txns: Vec<Option<Arc<SignedTransaction>>>,
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

impl MallocSizeOf for CompactBlock {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.tx_short_ids.size_of(ops) + self.reconstructed_txns.size_of(ops)
    }
}

impl CompactBlock {
    const SHORT_ID_SIZE_IN_BYTES: usize = 6;

    pub fn len(&self) -> usize {
        self.tx_short_ids.len() / CompactBlock::SHORT_ID_SIZE_IN_BYTES
    }

    pub fn hash(&self) -> H256 {
        self.block_header.hash()
    }

    pub fn get_shortid_key(header: &BlockHeader, nonce: &u64) -> (u64, u64) {
        let mut stream = RlpStream::new();
        stream.begin_list(2).append(header).append(nonce);
        let to_hash = stream.out();
        let key_hash: [u8; 32] = keccak(to_hash).into();
        let k0 = LittleEndian::read_u64(&key_hash[0..8]);
        let k1 = LittleEndian::read_u64(&key_hash[8..16]);
        (k0, k1)
    }

    /// Compute Tx ShortId from hash
    pub fn create_shortids(
        transactions: &Vec<Arc<SignedTransaction>>, k0: u64, k1: u64,
    ) -> Vec<u8> {
        let mut short_ids: Vec<u8> = vec![];

        for tx in transactions {
            let hash = tx.hash();
            let random = CompactBlock::get_random_bytes(&hash, k0, k1);

            short_ids.push(((random & 0xff00) >> 8) as u8);
            short_ids.push((random & 0xff) as u8);
            short_ids.push(hash[28]);
            short_ids.push(hash[29]);
            short_ids.push(hash[30]);
            short_ids.push(hash[31]);
        }
        short_ids
    }

    pub fn to_u16(v1: u8, v2: u8) -> u16 {
        ((v1 as u16) << 8) + v2 as u16
    }

    pub fn to_u32(v1: u8, v2: u8, v3: u8, v4: u8) -> u32 {
        ((v1 as u32) << 24)
            + ((v2 as u32) << 16)
            + ((v3 as u32) << 8)
            + v4 as u32
    }

    pub fn get_random_bytes(
        transaction_id: &H256, key1: u64, key2: u64,
    ) -> u16 {
        let mut hasher = SipHasher24::new_with_keys(key1, key2);
        hasher.write(transaction_id.as_ref());
        (hasher.finish() & 0xffff) as u16
    }

    pub fn get_decomposed_short_ids(&self) -> (Vec<u16>, Vec<u32>) {
        let mut random_bytes_vector: Vec<u16> = Vec::new();
        let mut fixed_bytes_vector: Vec<u32> = Vec::new();

        for i in (0..self.tx_short_ids.len())
            .step_by(CompactBlock::SHORT_ID_SIZE_IN_BYTES)
        {
            random_bytes_vector.push(CompactBlock::to_u16(
                self.tx_short_ids[i],
                self.tx_short_ids[i + 1],
            ));
            fixed_bytes_vector.push(CompactBlock::to_u32(
                self.tx_short_ids[i + 2],
                self.tx_short_ids[i + 3],
                self.tx_short_ids[i + 4],
                self.tx_short_ids[i + 5],
            ));
        }

        (random_bytes_vector, fixed_bytes_vector)
    }
}

impl Encodable for CompactBlock {
    fn rlp_append(&self, steam: &mut RlpStream) {
        steam
            .begin_list(3)
            .append(&self.block_header)
            .append(&self.nonce)
            .append(&self.tx_short_ids);
    }
}

impl Decodable for CompactBlock {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let short_ids: Vec<u8> = rlp.val_at(2)?;
        if short_ids.len() % CompactBlock::SHORT_ID_SIZE_IN_BYTES != 0 {
            return Err(DecoderError::Custom("Compact Block length Error!"));
        }
        Ok(CompactBlock {
            block_header: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            tx_short_ids: short_ids,
            reconstructed_txns: Vec::new(),
        })
    }
}
