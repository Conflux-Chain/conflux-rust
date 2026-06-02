// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod base_price;
pub use base_price::{
    compute_next_price, compute_next_price_tuple, estimate_gas_used_boundary,
    estimate_max_possible_gas,
};

use crate::{
    block::BlockHeight, bytes::Bytes, hash::keccak, pos::PosBlockId,
    receipt::BlockReceipts, MERKLE_NULL_NODE, NULL_EPOCH,
};
use cfx_parameters::block::{cspace_block_gas_limit, espace_block_gas_limit};
use cfx_types::{
    Address, Bloom, Space, SpaceMap, H256, KECCAK_EMPTY_BLOOM, U256,
};
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf, MallocSizeOfOps};
use once_cell::sync::OnceCell;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};

const HEADER_LIST_MIN_LEN: usize = 13;
/// The height to start fixing the wrong encoding/decoding of the `custom`
/// field.
pub static CIP112_TRANSITION_HEIGHT: OnceCell<u64> = OnceCell::new();

pub const BASE_PRICE_CHANGE_DENOMINATOR: usize = 8;

/// Block-header `custom` fields as one raw-RLP blob instead of a `Vec<Bytes>`,
/// so a peer header packed with tiny RLP items can't amplify into a per-item
/// allocation (remote OOM). `raw` is re-emitted verbatim via
/// `append_raw(&raw, count)`, byte-identical to the old encoding — block hashes
/// unchanged, no hardfork.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CustomData {
    raw: Bytes,
    count: usize,
    /// Old per-item length sum (raw len pre-CIP112, content len post-CIP112).
    data_len: usize,
}

impl MallocSizeOf for CustomData {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.raw.size_of(ops)
    }
}

impl CustomData {
    fn from_items(items: &[Bytes], height: u64) -> Self {
        if items.is_empty() {
            return Self::default();
        }
        let value_encoded =
            height >= *CIP112_TRANSITION_HEIGHT.get().expect("initialized");
        let mut raw = Vec::new();
        let mut data_len = 0;
        for item in items {
            data_len += item.len();
            if value_encoded {
                raw.extend_from_slice(rlp::encode(item).as_ref());
            } else {
                raw.extend_from_slice(item);
            }
        }
        Self {
            raw,
            count: items.len(),
            data_len,
        }
    }

    /// Byte-for-byte reproduces the old decode: post-CIP112 decode then
    /// canonically re-encode; pre-CIP112 keep raw RLP verbatim.
    fn from_rlp(
        r: &Rlp, custom_start: usize, height: u64,
    ) -> Result<Self, DecoderError> {
        let item_count = r.item_count()?;
        let count = item_count.saturating_sub(custom_start);
        if count == 0 {
            return Ok(Self::default());
        }
        let value_encoded =
            height >= *CIP112_TRANSITION_HEIGHT.get().expect("initialized");
        let mut raw = Vec::new();
        let mut data_len = 0;
        if value_encoded {
            // Re-encode each item canonically, reusing one stream (its buffer
            // survives `clear`) so a header with many items can't force a fresh
            // allocation per item.
            let mut scratch = RlpStream::new();
            for i in custom_start..item_count {
                let content: Bytes = r.val_at(i)?;
                data_len += content.len();
                scratch.clear();
                scratch.append(&content);
                raw.extend_from_slice(scratch.as_raw());
            }
        } else {
            for i in custom_start..item_count {
                let item_raw = r.at(i)?.as_raw();
                data_len += item_raw.len();
                raw.extend_from_slice(item_raw);
            }
        }
        Ok(Self {
            raw,
            count,
            data_len,
        })
    }

    fn raw_items(&self) -> RawItemIter<'_> {
        RawItemIter {
            raw: &self.raw,
            offset: 0,
        }
    }
}

struct RawItemIter<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for RawItemIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.offset >= self.raw.len() {
            return None;
        }
        let total = Rlp::new(&self.raw[self.offset..])
            .payload_info()
            .ok()?
            .total();
        let item = &self.raw[self.offset..self.offset + total];
        self.offset += total;
        Some(item)
    }
}

#[derive(Clone, Debug, Eq)]
pub struct BlockHeaderRlpPart {
    /// Parent hash.
    parent_hash: H256,
    /// Block height
    height: BlockHeight,
    /// Block timestamp.
    timestamp: u64,
    /// Block author.
    author: Address,
    /// Transactions root.
    transactions_root: H256,
    /// Deferred state root.
    deferred_state_root: H256,
    /// Deferred block receipts root.
    deferred_receipts_root: H256,
    /// Deferred block logs bloom hash.
    deferred_logs_bloom_hash: H256,
    /// Blame indicates the number of ancestors whose
    /// state_root/receipts_root/logs_bloom_hash/blame are not correct.
    /// It acts as a vote to help light client determining the
    /// state_root/receipts_root/logs_bloom_hash are correct or not.
    blame: u32,
    /// Block difficulty.
    difficulty: U256,
    /// Whether it is an adaptive block (from GHAST algorithm)
    adaptive: bool,
    /// Gas limit.
    gas_limit: U256,
    /// Referee hashes
    referee_hashes: Vec<H256>,
    /// Customized information
    custom: CustomData,
    /// Nonce of the block
    nonce: U256,
    /// Referred PoS block ID.
    pos_reference: Option<H256>,
    /// `[core_space_base_price, espace_base_price]`.
    base_price: Option<BasePrice>,
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
            && self.deferred_logs_bloom_hash == o.deferred_logs_bloom_hash
            && self.blame == o.blame
            && self.difficulty == o.difficulty
            && self.adaptive == o.adaptive
            && self.gas_limit == o.gas_limit
            && self.referee_hashes == o.referee_hashes
            && self.custom == o.custom
            && self.pos_reference == o.pos_reference
            && self.base_price == o.base_price
    }
}

/// A block header.
#[derive(Clone, Debug, Eq)]
pub struct BlockHeader {
    rlp_part: BlockHeaderRlpPart,
    /// Hash of the block
    hash: Option<H256>,
    /// POW quality of the block
    pub pow_hash: Option<H256>,
    /// Approximated rlp size of the block header
    pub approximated_rlp_size: usize,
}

impl Deref for BlockHeader {
    type Target = BlockHeaderRlpPart;

    fn deref(&self) -> &Self::Target { &self.rlp_part }
}

impl DerefMut for BlockHeader {
    fn deref_mut(&mut self) -> &mut BlockHeaderRlpPart { &mut self.rlp_part }
}

impl MallocSizeOf for BlockHeader {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.referee_hashes.size_of(ops) + self.custom.size_of(ops)
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
    pub fn deferred_state_root(&self) -> &H256 { &self.deferred_state_root }

    /// Get the deferred block receipts root field of the header.
    pub fn deferred_receipts_root(&self) -> &H256 {
        &self.deferred_receipts_root
    }

    /// Get the deferred block logs bloom hash field of the header.
    pub fn deferred_logs_bloom_hash(&self) -> &H256 {
        &self.deferred_logs_bloom_hash
    }

    /// Get the blame field of the header
    pub fn blame(&self) -> u32 { self.blame }

    /// Get the difficulty field of the header.
    pub fn difficulty(&self) -> &U256 { &self.difficulty }

    /// Get the adaptive field of the header
    pub fn adaptive(&self) -> bool { self.adaptive }

    /// Get the gas limit field of the header.
    pub fn gas_limit(&self) -> &U256 { &self.gas_limit }

    pub fn core_space_gas_limit(&self) -> U256 {
        cspace_block_gas_limit(
            self.base_price.is_some(),
            self.gas_limit().to_owned(),
        )
    }

    pub fn espace_gas_limit(&self, can_pack: bool) -> U256 {
        espace_block_gas_limit(can_pack, self.gas_limit().to_owned())
    }

    /// Get the referee hashes field of the header.
    pub fn referee_hashes(&self) -> &Vec<H256> { &self.referee_hashes }

    pub fn custom_count(&self) -> usize { self.custom.count }

    pub fn custom_data_len(&self) -> usize { self.custom.data_len }

    /// Bounded walk to `idx` — can't be forced to materialise a huge header.
    pub fn custom_item(&self, idx: usize) -> Option<Bytes> {
        let raw_item = self.custom.raw_items().nth(idx)?;
        Some(self.decode_custom_item(raw_item))
    }

    /// For already-validated headers only (e.g. RPC).
    pub fn custom_items(&self) -> Vec<Bytes> {
        self.custom
            .raw_items()
            .map(|raw_item| self.decode_custom_item(raw_item))
            .collect()
    }

    fn custom_value_encoded(&self) -> bool {
        self.height >= *CIP112_TRANSITION_HEIGHT.get().expect("initialized")
    }

    fn decode_custom_item(&self, raw_item: &[u8]) -> Bytes {
        if self.custom_value_encoded() {
            // `raw_item` is canonical RLP we produced, so `data()` can't fail.
            Rlp::new(raw_item)
                .data()
                .map(|d| d.to_vec())
                .unwrap_or_default()
        } else {
            raw_item.to_vec()
        }
    }

    /// Get the nonce field of the header.
    pub fn nonce(&self) -> U256 { self.nonce }

    /// Get the PoS reference.
    pub fn pos_reference(&self) -> &Option<PosBlockId> { &self.pos_reference }

    pub fn base_price(&self) -> Option<SpaceMap<U256>> {
        self.base_price.map(
            |BasePrice {
                 core_base_price,
                 espace_base_price,
             }| SpaceMap::new(core_base_price, espace_base_price),
        )
    }

    // Get the base price for the given space after 1559 hardfork.
    pub fn space_base_price(&self, space: Space) -> Option<U256> {
        self.base_price.map(|x| match space {
            Space::Native => x.core_base_price,
            Space::Ethereum => x.espace_base_price,
        })
    }

    /// Set the nonce field of the header.
    pub fn set_nonce(&mut self, nonce: U256) { self.nonce = nonce; }

    /// Set the timestamp filed of the header.
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
    }

    /// Set the custom filed of the header.
    pub fn set_custom(&mut self, custom: Vec<Bytes>) {
        let height = self.height;
        self.rlp_part.custom = CustomData::from_items(&custom, height);
    }

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
        stream.out().to_vec()
    }

    /// Get the RLP representation of this header.
    pub fn rlp(&self) -> Bytes {
        let mut stream = RlpStream::new();
        self.stream_rlp(&mut stream);
        stream.out().to_vec()
    }

    /// Place this header(except nonce) into an RLP stream `stream`.
    fn stream_rlp_without_nonce(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1_u8 } else { 0_u8 };
        let list_len = HEADER_LIST_MIN_LEN
            + self.pos_reference.is_some() as usize
            + self.base_price.is_some() as usize
            + self.custom.count;
        stream
            .begin_list(list_len)
            .append(&self.parent_hash)
            .append(&self.height)
            .append(&self.timestamp)
            .append(&self.author)
            .append(&self.transactions_root)
            .append(&self.deferred_state_root)
            .append(&self.deferred_receipts_root)
            .append(&self.deferred_logs_bloom_hash)
            .append(&self.blame)
            .append(&self.difficulty)
            .append(&adaptive_n)
            .append(&self.gas_limit)
            .append_list(&self.referee_hashes);
        if self.pos_reference.is_some() {
            stream.append(&self.pos_reference);
        }
        if self.base_price.is_some() {
            stream.append(&self.base_price);
        }

        stream.append_raw(&self.custom.raw, self.custom.count);
    }

    /// Place this header into an RLP stream `stream`.
    fn stream_rlp(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1_u8 } else { 0_u8 };
        let list_len = HEADER_LIST_MIN_LEN
            + 1
            + self.pos_reference.is_some() as usize
            + self.base_price.is_some() as usize
            + self.custom.count;
        stream
            .begin_list(list_len)
            .append(&self.parent_hash)
            .append(&self.height)
            .append(&self.timestamp)
            .append(&self.author)
            .append(&self.transactions_root)
            .append(&self.deferred_state_root)
            .append(&self.deferred_receipts_root)
            .append(&self.deferred_logs_bloom_hash)
            .append(&self.blame)
            .append(&self.difficulty)
            .append(&adaptive_n)
            .append(&self.gas_limit)
            .append_list(&self.referee_hashes)
            .append(&self.nonce);
        if self.pos_reference.is_some() {
            stream.append(&self.pos_reference);
        }
        if self.base_price.is_some() {
            stream.append(&self.base_price);
        }
        stream.append_raw(&self.custom.raw, self.custom.count);
    }

    /// Place this header and its `pow_hash` into an RLP stream `stream`.
    pub fn stream_rlp_with_pow_hash(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1_u8 } else { 0_u8 };
        let list_len = HEADER_LIST_MIN_LEN
            + 2
            + self.pos_reference.is_some() as usize
            + self.base_price.is_some() as usize
            + self.custom.count;
        stream
            .begin_list(list_len)
            .append(&self.parent_hash)
            .append(&self.height)
            .append(&self.timestamp)
            .append(&self.author)
            .append(&self.transactions_root)
            .append(&self.deferred_state_root)
            .append(&self.deferred_receipts_root)
            .append(&self.deferred_logs_bloom_hash)
            .append(&self.blame)
            .append(&self.difficulty)
            .append(&adaptive_n)
            .append(&self.gas_limit)
            .append_list(&self.referee_hashes)
            .append(&self.nonce)
            // Just encode the Option for future compatibility.
            // It should always be Some when it is being inserted to db.
            .append(&self.pow_hash);
        if self.pos_reference.is_some() {
            stream.append(&self.pos_reference);
        }
        if self.base_price.is_some() {
            stream.append(&self.base_price);
        }

        stream.append_raw(&self.custom.raw, self.custom.count);
    }

    pub fn decode_with_pow_hash(bytes: &[u8]) -> Result<Self, DecoderError> {
        let r = Rlp::new(bytes);
        let mut rlp_part = BlockHeaderRlpPart {
            parent_hash: r.val_at(0)?,
            height: r.val_at(1)?,
            timestamp: r.val_at(2)?,
            author: r.val_at(3)?,
            transactions_root: r.val_at(4)?,
            deferred_state_root: r.val_at(5)?,
            deferred_receipts_root: r.val_at(6)?,
            deferred_logs_bloom_hash: r.val_at(7)?,
            blame: r.val_at(8)?,
            difficulty: r.val_at(9)?,
            adaptive: r.val_at::<u8>(10)? == 1,
            gas_limit: r.val_at(11)?,
            referee_hashes: r.list_at(12)?,
            custom: CustomData::default(),
            nonce: r.val_at(13)?,
            pos_reference: r.val_at(15).unwrap_or(None),
            base_price: r.val_at(16).unwrap_or(None),
        };
        let pow_hash = r.val_at(14)?;

        let custom_start = 15
            + rlp_part.pos_reference.is_some() as usize
            + rlp_part.base_price.is_some() as usize;
        rlp_part.custom =
            CustomData::from_rlp(&r, custom_start, rlp_part.height)?;

        let mut header = BlockHeader {
            rlp_part,
            hash: None,
            pow_hash,
            approximated_rlp_size: bytes.len(),
        };
        header.compute_hash();
        Ok(header)
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
    deferred_state_root: H256,
    deferred_receipts_root: H256,
    deferred_logs_bloom_hash: H256,
    blame: u32,
    difficulty: U256,
    adaptive: bool,
    gas_limit: U256,
    referee_hashes: Vec<H256>,
    custom: Vec<Bytes>,
    nonce: U256,
    pos_reference: Option<PosBlockId>,
    base_price: Option<BasePrice>,
}

impl Default for BlockHeaderBuilder {
    fn default() -> Self { Self::new() }
}

impl BlockHeaderBuilder {
    pub fn new() -> Self {
        Self {
            parent_hash: NULL_EPOCH,
            height: 0,
            timestamp: 0,
            author: Address::default(),
            transactions_root: MERKLE_NULL_NODE,
            deferred_state_root: Default::default(),
            deferred_receipts_root: Default::default(),
            deferred_logs_bloom_hash: KECCAK_EMPTY_BLOOM,
            blame: 0,
            difficulty: U256::default(),
            adaptive: false,
            gas_limit: U256::zero(),
            referee_hashes: Vec::new(),
            custom: Vec::new(),
            nonce: U256::zero(),
            pos_reference: None,
            base_price: None,
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
        &mut self, deferred_state_root: H256,
    ) -> &mut Self {
        self.deferred_state_root = deferred_state_root;
        self
    }

    pub fn with_deferred_receipts_root(
        &mut self, deferred_receipts_root: H256,
    ) -> &mut Self {
        self.deferred_receipts_root = deferred_receipts_root;
        self
    }

    pub fn with_deferred_logs_bloom_hash(
        &mut self, deferred_logs_bloom_hash: H256,
    ) -> &mut Self {
        self.deferred_logs_bloom_hash = deferred_logs_bloom_hash;
        self
    }

    pub fn with_blame(&mut self, blame: u32) -> &mut Self {
        self.blame = blame;
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

    pub fn with_custom(&mut self, custom: Vec<Bytes>) -> &mut Self {
        self.custom = custom;
        self
    }

    pub fn with_nonce(&mut self, nonce: U256) -> &mut Self {
        self.nonce = nonce;
        self
    }

    pub fn with_pos_reference(
        &mut self, pos_reference: Option<PosBlockId>,
    ) -> &mut Self {
        self.pos_reference = pos_reference;
        self
    }

    pub fn with_base_price(
        &mut self, maybe_base_price: Option<SpaceMap<U256>>,
    ) -> &mut Self {
        self.base_price = maybe_base_price.map(|x| BasePrice {
            core_base_price: x[Space::Native],
            espace_base_price: x[Space::Ethereum],
        });
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
                deferred_state_root: self.deferred_state_root,
                deferred_receipts_root: self.deferred_receipts_root,
                deferred_logs_bloom_hash: self.deferred_logs_bloom_hash,
                blame: self.blame,
                difficulty: self.difficulty,
                adaptive: self.adaptive,
                gas_limit: self.gas_limit,
                referee_hashes: self.referee_hashes.clone(),
                custom: CustomData::from_items(&self.custom, self.height),
                nonce: self.nonce,
                pos_reference: self.pos_reference,
                base_price: self.base_price,
            },
            hash: None,
            pow_hash: None,
            approximated_rlp_size: 0,
        };

        block_header.approximated_rlp_size =
            mem::size_of::<BlockHeaderRlpPart>()
                + block_header
                    .referee_hashes
                    .size_of(&mut new_malloc_size_ops());

        block_header
    }

    pub fn compute_block_logs_bloom_hash(
        receipts: &[Arc<BlockReceipts>],
    ) -> H256 {
        let bloom = receipts.iter().flat_map(|x| &x.receipts).fold(
            Bloom::zero(),
            |mut b, r| {
                b.accrue_bloom(&r.log_bloom);
                b
            },
        );

        keccak(bloom)
    }

    pub fn compute_aggregated_bloom(blooms: Vec<Bloom>) -> Bloom {
        blooms.into_iter().fold(Bloom::zero(), |mut res, bloom| {
            res.accrue_bloom(&bloom);
            res
        })
    }

    pub fn compute_blame_state_root_vec_root(roots: Vec<H256>) -> H256 {
        let mut accumulated_root = *roots.last().unwrap();
        for i in (0..(roots.len() - 1)).rev() {
            accumulated_root =
                BlockHeaderBuilder::compute_blame_state_root_incremental(
                    roots[i],
                    accumulated_root,
                );
        }
        accumulated_root
    }

    pub fn compute_blame_state_root_incremental(
        first_root: H256, remaining_root: H256,
    ) -> H256 {
        let mut buffer = Vec::with_capacity(H256::len_bytes() * 2);
        buffer.extend_from_slice(first_root.as_bytes());
        buffer.extend_from_slice(remaining_root.as_bytes());
        keccak(&buffer)
    }
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, stream: &mut RlpStream) { self.stream_rlp(stream); }
}

impl Decodable for BlockHeader {
    fn decode(r: &Rlp) -> Result<Self, DecoderError> {
        let rlp_size = r.as_raw().len();
        let mut rlp_part = BlockHeaderRlpPart {
            parent_hash: r.val_at(0)?,
            height: r.val_at(1)?,
            timestamp: r.val_at(2)?,
            author: r.val_at(3)?,
            transactions_root: r.val_at(4)?,
            deferred_state_root: r.val_at(5)?,
            deferred_receipts_root: r.val_at(6)?,
            deferred_logs_bloom_hash: r.val_at(7)?,
            blame: r.val_at(8)?,
            difficulty: r.val_at(9)?,
            adaptive: r.val_at::<u8>(10)? == 1,
            gas_limit: r.val_at(11)?,
            referee_hashes: r.list_at(12)?,
            custom: CustomData::default(),
            nonce: r.val_at(13)?,
            pos_reference: r.val_at(14).unwrap_or(None),
            base_price: r.val_at(15).unwrap_or(None),
        };
        let custom_start = 14
            + rlp_part.pos_reference.is_some() as usize
            + rlp_part.base_price.is_some() as usize;
        rlp_part.custom =
            CustomData::from_rlp(r, custom_start, rlp_part.height)?;

        let mut header = BlockHeader {
            rlp_part,
            hash: None,
            pow_hash: None,
            approximated_rlp_size: rlp_size,
        };
        header.compute_hash();

        Ok(header)
    }
}

#[derive(Clone, Copy, Debug, Eq, RlpDecodable, RlpEncodable, PartialEq)]
pub struct BasePrice {
    pub core_base_price: U256,
    pub espace_base_price: U256,
}
#[cfg(test)]
mod tests {
    use super::BlockHeaderBuilder;
    use crate::{
        hash::keccak,
        receipt::{BlockReceipts, Receipt},
        TransactionStatus,
    };
    use cfx_types::{Bloom, KECCAK_EMPTY_BLOOM, U256};
    use std::{str::FromStr, sync::Arc};

    #[test]
    fn test_logs_bloom_hash_no_receipts() {
        let receipts = vec![]; // Vec<_>
        let hash = BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        assert_eq!(hash, KECCAK_EMPTY_BLOOM);

        let receipts: Vec<Arc<BlockReceipts>> = (1..11)
            .map(|_| {
                Arc::new(BlockReceipts {
                    receipts: vec![],
                    block_number: 0,
                    secondary_reward: U256::zero(),
                    tx_execution_error_messages: vec![],
                })
            })
            .collect();
        let hash = BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        assert_eq!(hash, KECCAK_EMPTY_BLOOM);
    }

    #[test]
    fn test_logs_bloom_hash_empty_receipts() {
        let receipt = Receipt {
            accumulated_gas_used: U256::zero(),
            gas_fee: U256::zero(),
            gas_sponsor_paid: false,
            logs: vec![],
            outcome_status: TransactionStatus::Success,
            log_bloom: Bloom::zero(),
            storage_sponsor_paid: false,
            storage_collateralized: vec![],
            storage_released: vec![],
            burnt_gas_fee: None,
        };

        // 10 blocks with 10 empty receipts each
        let receipts: Vec<Arc<BlockReceipts>> = (1..11)
            .map(|_| {
                Arc::new(BlockReceipts {
                    receipts: (1..11).map(|_| receipt.clone()).collect(),
                    block_number: 0,
                    secondary_reward: U256::zero(),
                    tx_execution_error_messages: vec!["".into(); 10],
                })
            })
            .collect();
        let hash = BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        assert_eq!(hash, KECCAK_EMPTY_BLOOM);
    }

    #[test]
    fn test_logs_bloom_hash() {
        let block1 = BlockReceipts {
            receipts: vec![
                Receipt {
                    accumulated_gas_used: 0.into(),
                    gas_fee: 0.into(),
                    gas_sponsor_paid: false,
                    logs: vec![],
                    outcome_status: TransactionStatus::Success,
                    log_bloom: Bloom::from_str(
                        "11111111111111111111111111111111\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000",
                    )
                    .unwrap(),
                    storage_sponsor_paid: false,
                    storage_collateralized: vec![],
                    storage_released: vec![],
                    burnt_gas_fee: None,
                },
                Receipt {
                    accumulated_gas_used: U256::zero(),
                    gas_fee: U256::zero(),
                    gas_sponsor_paid: false,
                    logs: vec![],
                    outcome_status: TransactionStatus::Success,
                    log_bloom: Bloom::from_str(
                        "00000000000000000000000000000000\
                         22222222222222222222222222222222\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000\
                         00000000000000000000000000000000",
                    )
                    .unwrap(),
                    storage_sponsor_paid: false,
                    storage_collateralized: vec![],
                    storage_released: vec![],
                    burnt_gas_fee: None,
                },
            ],
            block_number: 0,
            secondary_reward: U256::zero(),
            tx_execution_error_messages: vec!["".into(); 2],
        };

        let block2 = BlockReceipts {
            receipts: vec![Receipt {
                accumulated_gas_used: U256::zero(),
                gas_fee: U256::zero(),
                gas_sponsor_paid: false,
                logs: vec![],
                outcome_status: TransactionStatus::Success,
                log_bloom: Bloom::from_str(
                    "44444444444444440000000000000000\
                     44444444444444440000000000000000\
                     44444444444444440000000000000000\
                     44444444444444440000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000\
                     00000000000000000000000000000000",
                )
                .unwrap(),
                storage_sponsor_paid: false,
                storage_collateralized: vec![],
                storage_released: vec![],
                burnt_gas_fee: None,
            }],
            block_number: 0,
            secondary_reward: U256::zero(),
            tx_execution_error_messages: vec!["".into()],
        };

        let expected = keccak(
            "55555555555555551111111111111111\
             66666666666666662222222222222222\
             44444444444444440000000000000000\
             44444444444444440000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000\
             00000000000000000000000000000000"
                .parse::<Bloom>()
                .unwrap(),
        );

        let receipts = vec![Arc::new(block1), Arc::new(block2)];
        let hash = BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        assert_eq!(hash, expected);
    }

    use super::{BlockHeader, CIP112_TRANSITION_HEIGHT};
    use crate::bytes::Bytes;
    use rlp::{Decodable, Rlp};

    // CIP112_TRANSITION_HEIGHT is a process-global OnceCell, shared by all
    // tests.
    const CIP112: u64 = 1000;

    fn init_cip112() { CIP112_TRANSITION_HEIGHT.get_or_init(|| CIP112); }

    fn header_with_custom(height: u64, custom: Vec<Bytes>) -> BlockHeader {
        init_cip112();
        BlockHeaderBuilder::new()
            .with_height(height)
            .with_custom(custom)
            .build()
    }

    /// Decode→re-encode is byte-identical (hash preserved) and items
    /// round-trip.
    fn assert_roundtrip(height: u64, custom: Vec<Bytes>) {
        let header = header_with_custom(height, custom.clone());
        let encoded = header.rlp();

        let decoded = BlockHeader::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(decoded.rlp(), encoded, "re-encoding must be identical");
        assert_eq!(decoded.hash(), header.hash(), "hash must be preserved");

        assert_eq!(decoded.custom_count(), custom.len());
        assert_eq!(decoded.custom_items(), custom);
        assert_eq!(
            decoded.custom_data_len(),
            custom.iter().map(|x| x.len()).sum::<usize>()
        );
        for (i, item) in custom.iter().enumerate() {
            assert_eq!(decoded.custom_item(i).as_ref(), Some(item));
        }
        assert_eq!(decoded.custom_item(custom.len()), None);
    }

    #[test]
    fn custom_roundtrip_post_cip112() {
        assert_roundtrip(
            CIP112 + 5,
            vec![vec![1u8, 2, 3], vec![], vec![0xab; 40], vec![0x42]],
        );
    }

    #[test]
    fn custom_roundtrip_empty_post_cip112() {
        assert_roundtrip(CIP112 + 5, vec![]);
    }

    #[test]
    fn custom_roundtrip_pre_cip112() {
        // Pre-CIP112 items are raw RLP verbatim, so feed encoded byte strings.
        let items = vec![
            rlp::encode(&vec![1u8, 2, 3]).to_vec(),
            rlp::encode(&Vec::<u8>::new()).to_vec(),
            rlp::encode(&vec![0xcd_u8; 30]).to_vec(),
        ];
        assert_roundtrip(CIP112 - 5, items);
    }

    #[test]
    fn custom_many_empty_items_no_amplification() {
        let n = 5000usize;
        let header = header_with_custom(CIP112 + 5, vec![Vec::new(); n]);
        let encoded = header.rlp();

        let decoded = BlockHeader::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(decoded.custom_count(), n);
        assert_eq!(decoded.custom_data_len(), 0);
        // One byte (0x80) per empty item — no per-item Vec overhead.
        assert_eq!(decoded.custom.raw.len(), n);
        assert_eq!(decoded.rlp(), encoded);
        assert_eq!(decoded.hash(), header.hash());
    }

    #[test]
    fn custom_roundtrip_with_pow_hash() {
        init_cip112();
        let custom = vec![vec![9u8, 8, 7], vec![], vec![0x11; 33]];
        let mut header = BlockHeaderBuilder::new()
            .with_height(CIP112 + 5)
            .with_custom(custom.clone())
            .build();
        header.pow_hash = Some(crate::hash::keccak(b"pow"));

        let mut stream = rlp::RlpStream::new();
        header.stream_rlp_with_pow_hash(&mut stream);
        let encoded = stream.out().to_vec();

        let decoded = BlockHeader::decode_with_pow_hash(&encoded).unwrap();
        assert_eq!(decoded.custom_items(), custom);
        assert_eq!(decoded.pow_hash, header.pow_hash);

        let mut stream2 = rlp::RlpStream::new();
        decoded.stream_rlp_with_pow_hash(&mut stream2);
        assert_eq!(stream2.out().to_vec(), encoded);
    }
}
