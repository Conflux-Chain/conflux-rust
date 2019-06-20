// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::state_root::*;
use crate::{
    bytes::Bytes,
    hash::{keccak, KECCAK_EMPTY_LIST_RLP},
    receipt::Receipt,
};
use cfx_types::{Address, H256, U256};
use heapsize::HeapSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};

#[derive(Clone, Debug, Eq)]
pub struct BlockHeaderRlpPart {
    /// Parent hash.
    parent_hash: H256,
    /// Block height
    height: u64,
    /// Block timestamp.
    timestamp: u64,
    /// Block author.
    author: Address,
    /// Transactions root.
    transactions_root: H256,
    /// Deferred state root.
    deferred_state_root: StateRoot,
    /// Deferred block receipts root.
    deferred_receipts_root: H256,
    /// Block difficulty.
    difficulty: U256,
    /// Whether it is an adaptive block (from GHAST algorithm)
    adaptive: bool,
    /// Gas limit.
    gas_limit: U256,
    /// Referee hashes
    referee_hashes: Vec<H256>,
    /// Nonce of the block
    nonce: u64,
}

impl PartialEq for BlockHeaderRlpPart {
    fn eq(&self, o: &BlockHeaderRlpPart) -> bool {
        self.parent_hash == o.parent_hash
            && self.height == o.height
            && self.timestamp == o.timestamp
            && self.author == o.author
            && self.transactions_root == o.transactions_root
            && self.deferred_state_root == o.deferred_state_root
            && self.deferred_receipts_root == o.deferred_receipts_root
            && self.difficulty == o.difficulty
            && self.adaptive == o.adaptive
            && self.gas_limit == o.gas_limit
            && self.referee_hashes == o.referee_hashes
    }
}

/// A block header.
#[derive(Clone, Debug, Eq)]
pub struct BlockHeader {
    rlp_part: BlockHeaderRlpPart,
    /// Hash of the block
    hash: Option<H256>,
    /// POW quality of the block
    pub pow_quality: U256,
    /// Approximated rlp size of the block header
    pub approximated_rlp_size: usize,
    // TODO: the state root auxiliary information can be derived from
    // TODO: consensus graph and should be moved out from p2p messages,
    // TODO: however to reduce complexity of the code we keep it
    // TODO: temporarily.
    pub state_root_aux_info: StateRootAuxInfo,
}

impl Deref for BlockHeader {
    type Target = BlockHeaderRlpPart;

    fn deref(&self) -> &Self::Target { &self.rlp_part }
}

impl DerefMut for BlockHeader {
    fn deref_mut(&mut self) -> &mut BlockHeaderRlpPart { &mut self.rlp_part }
}

impl HeapSizeOf for BlockHeader {
    fn heap_size_of_children(&self) -> usize {
        mem::size_of::<Self>() + self.referee_hashes.heap_size_of_children()
    }
}

impl PartialEq for BlockHeader {
    fn eq(&self, o: &BlockHeader) -> bool { self.rlp_part == o.rlp_part }
}

impl BlockHeader {
    /// Approximated rlp size of the block header.
    pub fn approximated_rlp_size(&self) -> usize { self.approximated_rlp_size }

    /// Get the parent_hash field of the header.
    pub fn parent_hash(&self) -> &H256 { &self.parent_hash }

    /// Get the block height
    pub fn height(&self) -> u64 { self.height }

    /// Get the timestamp field of the header.
    pub fn timestamp(&self) -> u64 { self.timestamp }

    /// Get the author field of the header.
    pub fn author(&self) -> &Address { &self.author }

    /// Get the transactions root field of the header.
    pub fn transactions_root(&self) -> &H256 { &self.transactions_root }

    /// Get the deferred state root field of the header.
    pub fn deferred_state_root(&self) -> &StateRoot {
        &self.deferred_state_root
    }

    pub fn deferred_state_root_with_aux_info(
        &self,
    ) -> (&StateRoot, &StateRootAuxInfo) {
        (&self.deferred_state_root, &self.state_root_aux_info)
    }

    /// Get the deferred block receipts root field of the header.
    pub fn deferred_receipts_root(&self) -> &H256 {
        &self.deferred_receipts_root
    }

    /// Get the difficulty field of the header.
    pub fn difficulty(&self) -> &U256 { &self.difficulty }

    /// Get the adaptive field of the header
    pub fn adaptive(&self) -> bool { self.adaptive }

    /// Get the gas limit field of the header.
    pub fn gas_limit(&self) -> &U256 { &self.gas_limit }

    /// Get the referee hashes field of the header.
    pub fn referee_hashes(&self) -> &Vec<H256> { &self.referee_hashes }

    /// Get the nonce field of the header.
    pub fn nonce(&self) -> u64 { self.nonce }

    /// Set the nonce field of the header.
    pub fn set_nonce(&mut self, nonce: u64) { self.nonce = nonce; }

    /// Compute the hash of the block.
    pub fn compute_hash(&mut self) -> H256 {
        let hash = self.hash();
        self.hash = Some(hash);
        hash
    }

    /// Get the hash of the block.
    pub fn hash(&self) -> H256 {
        self.hash.unwrap_or_else(|| keccak(self.rlp()))
    }

    /// Get the hash of PoW problem.
    pub fn problem_hash(&self) -> H256 { keccak(self.rlp_without_nonce()) }

    /// Get the RLP representation of this header(except nonce).
    pub fn rlp_without_nonce(&self) -> Bytes {
        let mut stream = RlpStream::new();
        self.stream_rlp_without_nonce(&mut stream);
        stream.out()
    }

    /// Get the RLP representation of this header.
    pub fn rlp(&self) -> Bytes {
        let mut stream = RlpStream::new();
        self.stream_rlp(&mut stream);
        stream.out()
    }

    /// Place this header(except nonce) into an RLP stream `stream`.
    fn stream_rlp_without_nonce(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1 as u8 } else { 0 as u8 };
        stream
            .begin_list(11)
            .append(&self.parent_hash)
            .append(&self.height)
            .append(&self.timestamp)
            .append(&self.author)
            .append(&self.transactions_root)
            .append(&self.deferred_state_root)
            .append(&self.deferred_receipts_root)
            .append(&self.difficulty)
            .append(&adaptive_n)
            .append(&self.gas_limit)
            .append_list(&self.referee_hashes);
    }

    /// Place this header into an RLP stream `stream`.
    fn stream_rlp(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1 as u8 } else { 0 as u8 };
        stream
            .begin_list(12)
            .append(&self.parent_hash)
            .append(&self.height)
            .append(&self.timestamp)
            .append(&self.author)
            .append(&self.transactions_root)
            .append(&self.deferred_state_root)
            .append(&self.deferred_receipts_root)
            .append(&self.difficulty)
            .append(&adaptive_n)
            .append(&self.gas_limit)
            .append_list(&self.referee_hashes)
            .append(&self.nonce);
    }

    // TODO: calculate previous_snapshot_root & intermediate_delta_epoch_id in
    // TODO: consensus graph and remove this method.
    /// Place this header into an RLP stream `stream` for p2p messages.
    fn stream_wire_rlp(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1 as u8 } else { 0 as u8 };
        stream
            .begin_list(13)
            .append(&self.parent_hash)
            .append(&self.height)
            .append(&self.timestamp)
            .append(&self.author)
            .append(&self.transactions_root)
            .append(&self.deferred_state_root)
            .append(&self.deferred_receipts_root)
            .append(&self.difficulty)
            .append(&adaptive_n)
            .append(&self.gas_limit)
            .append_list(&self.referee_hashes)
            .append(&self.nonce)
            .append(&self.state_root_aux_info);
    }

    pub fn size(&self) -> usize {
        // FIXME: We need to revisit the size of block header once we finished
        // the persistent storage part
        0
    }
}

pub struct BlockHeaderBuilder {
    parent_hash: H256,
    height: u64,
    timestamp: u64,
    author: Address,
    transactions_root: H256,
    deferred_state_root: StateRoot,
    deferred_state_root_aux_info: StateRootAuxInfo,
    deferred_receipts_root: H256,
    difficulty: U256,
    adaptive: bool,
    gas_limit: U256,
    referee_hashes: Vec<H256>,
    nonce: u64,
}

impl BlockHeaderBuilder {
    pub fn new() -> Self {
        Self {
            parent_hash: H256::default(),
            height: 0,
            timestamp: 0,
            author: Address::default(),
            transactions_root: KECCAK_EMPTY_LIST_RLP,
            deferred_state_root: Default::default(),
            deferred_state_root_aux_info: Default::default(),
            deferred_receipts_root: KECCAK_EMPTY_LIST_RLP,
            difficulty: U256::default(),
            adaptive: false,
            gas_limit: U256::zero(),
            referee_hashes: Vec::new(),
            nonce: 0,
        }
    }

    pub fn with_parent_hash(&mut self, parent_hash: H256) -> &mut Self {
        self.parent_hash = parent_hash;
        self
    }

    pub fn with_height(&mut self, height: u64) -> &mut Self {
        self.height = height;
        self
    }

    pub fn with_timestamp(&mut self, timestamp: u64) -> &mut Self {
        self.timestamp = timestamp;
        self
    }

    pub fn with_author(&mut self, author: Address) -> &mut Self {
        self.author = author;
        self
    }

    pub fn with_transactions_root(
        &mut self, transactions_root: H256,
    ) -> &mut Self {
        self.transactions_root = transactions_root;
        self
    }

    pub fn with_deferred_state_root(
        &mut self, deferred_state_root_with_aux_info: StateRootWithAuxInfo,
    ) -> &mut Self {
        self.deferred_state_root = deferred_state_root_with_aux_info.state_root;
        self.deferred_state_root_aux_info =
            deferred_state_root_with_aux_info.aux_info;

        self
    }

    pub fn with_deferred_receipts_root(
        &mut self, deferred_receipts_root: H256,
    ) -> &mut Self {
        self.deferred_receipts_root = deferred_receipts_root;
        self
    }

    pub fn with_difficulty(&mut self, difficulty: U256) -> &mut Self {
        self.difficulty = difficulty;
        self
    }

    pub fn with_adaptive(&mut self, adaptive: bool) -> &mut Self {
        self.adaptive = adaptive;
        self
    }

    pub fn with_gas_limit(&mut self, gas_limit: U256) -> &mut Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn with_referee_hashes(
        &mut self, referee_hashes: Vec<H256>,
    ) -> &mut Self {
        self.referee_hashes = referee_hashes;
        self
    }

    pub fn with_nonce(&mut self, nonce: u64) -> &mut Self {
        self.nonce = nonce;
        self
    }

    pub fn build(&self) -> BlockHeader {
        let mut block_header = BlockHeader {
            rlp_part: BlockHeaderRlpPart {
                parent_hash: self.parent_hash,
                height: self.height,
                timestamp: self.timestamp,
                author: self.author,
                transactions_root: self.transactions_root,
                deferred_state_root: self.deferred_state_root.clone(),
                deferred_receipts_root: self.deferred_receipts_root,
                difficulty: self.difficulty,
                adaptive: self.adaptive,
                gas_limit: self.gas_limit,
                referee_hashes: self.referee_hashes.clone(),
                nonce: self.nonce,
            },
            hash: None,
            pow_quality: U256::zero(),
            approximated_rlp_size: 0,
            state_root_aux_info: self.deferred_state_root_aux_info.clone(),
        };

        block_header.approximated_rlp_size =
            mem::size_of::<BlockHeaderRlpPart>()
                + block_header.referee_hashes.heap_size_of_children();

        block_header
    }

    pub fn compute_block_receipts_root(
        receipts: &Vec<Arc<Vec<Receipt>>>,
    ) -> H256 {
        let mut rlp_stream = RlpStream::new_list(receipts.len());
        for r in receipts {
            rlp_stream.append_list(r.as_ref());
        }

        keccak(rlp_stream.out())
    }
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, stream: &mut RlpStream) {
        self.stream_wire_rlp(stream);
    }
}

impl Decodable for BlockHeader {
    fn decode(r: &Rlp) -> Result<Self, DecoderError> {
        let rlp_size = r.as_raw().len();
        let mut header = BlockHeader {
            rlp_part: BlockHeaderRlpPart {
                parent_hash: r.val_at(0)?,
                height: r.val_at(1)?,
                timestamp: r.val_at(2)?,
                author: r.val_at(3)?,
                transactions_root: r.val_at(4)?,
                deferred_state_root: r.val_at(5)?,
                deferred_receipts_root: r.val_at(6)?,
                difficulty: r.val_at(7)?,
                adaptive: r.val_at::<u8>(8)? == 1,
                gas_limit: r.val_at(9)?,
                referee_hashes: r.list_at(10)?,
                nonce: r.val_at(11)?,
            },
            hash: None,
            pow_quality: U256::zero(),
            approximated_rlp_size: rlp_size,
            state_root_aux_info: r.val_at(12)?,
        };
        header.compute_hash();

        Ok(header)
    }
}
