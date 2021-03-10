// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block::BlockHeight, bytes::Bytes, hash::keccak, receipt::BlockReceipts,
    MERKLE_NULL_NODE, NULL_EPOCH,
};
use cfx_types::{Address, Bloom, H256, KECCAK_EMPTY_BLOOM, U256};
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf, MallocSizeOfOps};
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
    custom: Vec<Bytes>,
    /// Nonce of the block
    nonce: U256,
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

    fn deref(&self) -> &Self::Target {
        &self.rlp_part
    }
}

impl DerefMut for BlockHeader {
    fn deref_mut(&mut self) -> &mut BlockHeaderRlpPart {
        &mut self.rlp_part
    }
}

impl MallocSizeOf for BlockHeader {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.referee_hashes.size_of(ops) + self.custom.size_of(ops)
    }
}

impl PartialEq for BlockHeader {
    fn eq(&self, o: &BlockHeader) -> bool {
        self.rlp_part == o.rlp_part
    }
}

impl BlockHeader {
    /// Approximated rlp size of the block header.
    pub fn approximated_rlp_size(&self) -> usize {
        self.approximated_rlp_size
    }

    /// Get the parent_hash field of the header.
    pub fn parent_hash(&self) -> &H256 {
        &self.parent_hash
    }

    /// Get the block height
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Get the timestamp field of the header.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the author field of the header.
    pub fn author(&self) -> &Address {
        &self.author
    }

    /// Get the transactions root field of the header.
    pub fn transactions_root(&self) -> &H256 {
        &self.transactions_root
    }

    /// Get the deferred state root field of the header.
    pub fn deferred_state_root(&self) -> &H256 {
        &self.deferred_state_root
    }

    /// Get the deferred block receipts root field of the header.
    pub fn deferred_receipts_root(&self) -> &H256 {
        &self.deferred_receipts_root
    }

    /// Get the deferred block logs bloom hash field of the header.
    pub fn deferred_logs_bloom_hash(&self) -> &H256 {
        &self.deferred_logs_bloom_hash
    }

    /// Get the blame field of the header
    pub fn blame(&self) -> u32 {
        self.blame
    }

    /// Get the difficulty field of the header.
    pub fn difficulty(&self) -> &U256 {
        &self.difficulty
    }

    /// Get the adaptive field of the header
    pub fn adaptive(&self) -> bool {
        self.adaptive
    }

    /// Get the gas limit field of the header.
    pub fn gas_limit(&self) -> &U256 {
        &self.gas_limit
    }

    /// Get the referee hashes field of the header.
    pub fn referee_hashes(&self) -> &Vec<H256> {
        &self.referee_hashes
    }

    /// Get the custom data field of the header.
    pub fn custom(&self) -> &Vec<Bytes> {
        &self.custom
    }

    /// Get the nonce field of the header.
    pub fn nonce(&self) -> U256 {
        self.nonce
    }

    /// Set the nonce field of the header.
    pub fn set_nonce(&mut self, nonce: U256) {
        self.nonce = nonce;
    }

    /// Set the timestamp filed of the header.
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
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
    pub fn problem_hash(&self) -> H256 {
        keccak(self.rlp_without_nonce())
    }

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
        let list_len = if self.custom.is_empty() {
            13
        } else {
            13 + self.custom.len()
        };
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

        if list_len > 13 {
            for b in &self.custom {
                stream.append_raw(b, 1);
            }
        }
    }

    /// Place this header into an RLP stream `stream`.
    fn stream_rlp(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1 as u8 } else { 0 as u8 };
        let list_len = if self.custom.is_empty() {
            14
        } else {
            14 + self.custom.len()
        };
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

        if list_len > 14 {
            for b in &self.custom {
                stream.append_raw(b, 1);
            }
        }
    }

    /// Place this header and its `pow_hash` into an RLP stream `stream`.
    pub fn stream_rlp_with_pow_hash(&self, stream: &mut RlpStream) {
        let adaptive_n = if self.adaptive { 1 as u8 } else { 0 as u8 };
        let list_len = if self.custom.is_empty() {
            15
        } else {
            15 + self.custom.len()
        };
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

        if list_len > 15 {
            for b in &self.custom {
                stream.append_raw(b, 1);
            }
        }
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
            custom: vec![],
            nonce: r.val_at(13)?,
        };
        let pow_hash = r.val_at(14)?;
        for i in 15..r.item_count()? {
            rlp_part.custom.push(r.at(i)?.as_raw().to_vec())
        }

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
                custom: self.custom.clone(),
                nonce: self.nonce,
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
        receipts: &Vec<Arc<BlockReceipts>>,
    ) -> H256 {
        let bloom = receipts.iter().map(|x| &x.receipts).flatten().fold(
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
        let mut accumulated_root = roots.last().unwrap().clone();
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
    fn rlp_append(&self, stream: &mut RlpStream) {
        self.stream_rlp(stream);
    }
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
            custom: vec![],
            nonce: r.val_at(13)?,
        };
        for i in 14..r.item_count()? {
            rlp_part.custom.push(r.at(i)?.as_raw().to_vec())
        }

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

#[cfg(test)]
mod tests {
    use super::BlockHeaderBuilder;
    use crate::{
        hash::keccak,
        receipt::{BlockReceipts, Receipt},
    };
    use cfx_types::{Bloom, KECCAK_EMPTY_BLOOM, U256};
    use std::{str::FromStr, sync::Arc};

    #[test]
    fn test_logs_bloom_hash_no_receipts() {
        let receipts = vec![]; // Vec<_>
        let hash = BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        assert_eq!(hash, KECCAK_EMPTY_BLOOM);

        let receipts = (1..11)
            .map(|_| {
                Arc::new(BlockReceipts {
                    receipts: vec![],
                    block_number: 0,
                    secondary_reward: U256::zero(),
                    tx_execution_error_messages: vec![],
                })
            })
            .collect(); // Vec<Arc<Vec<_>>>
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
            outcome_status: 0,
            log_bloom: Bloom::zero(),
            storage_sponsor_paid: false,
            storage_collateralized: vec![],
            storage_released: vec![],
        };

        // 10 blocks with 10 empty receipts each
        let receipts = (1..11)
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
                    outcome_status: 0,
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
                },
                Receipt {
                    accumulated_gas_used: U256::zero(),
                    gas_fee: U256::zero(),
                    gas_sponsor_paid: false,
                    logs: vec![],
                    outcome_status: 0,
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
                outcome_status: 0,
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
}
