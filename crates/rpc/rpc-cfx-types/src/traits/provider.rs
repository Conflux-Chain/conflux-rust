use cfx_types::H256;
use primitives::EpochNumber;

pub trait BlockProvider {
    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64>;

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String>;
}
