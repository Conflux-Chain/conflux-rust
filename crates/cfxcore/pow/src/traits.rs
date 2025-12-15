use cfx_types::H256;
use primitives::BlockHeader;
use std::sync::Arc;

pub trait ConsensusProvider {
    fn num_blocks_in_epoch(&self, hash: &H256) -> u64;

    fn block_header_by_hash(&self, hash: &H256) -> Option<Arc<BlockHeader>>;
}
