use primitives::{block::BlockHeight, BlockNumber};
use sha3_macro::keccak;

const BLOCK_HASHES_START_SLOT: [u8; 32] = {
    let mut hash = keccak!("CIP_133_BLOCK_HASHES_START_SLOT");
    hash[30] = 0;
    hash[31] = 0;
    hash
};

const EPOCH_HASHES_START_SLOT: [u8; 32] = {
    let mut hash = keccak!("CIP_133_EPOCH_HASHES_START_SLOT");
    hash[30] = 0;
    hash[31] = 0;
    hash
};

pub const fn block_hash_slot(number: BlockNumber) -> [u8; 32] {
    let mut answer = BLOCK_HASHES_START_SLOT;
    let r = ((number & 0xffff) as u16).to_be_bytes();
    answer[30] = r[0];
    answer[31] = r[1];
    answer
}

pub const fn epoch_hash_slot(height: BlockHeight) -> [u8; 32] {
    let mut answer = EPOCH_HASHES_START_SLOT;
    let r = ((height & 0xffff) as u16).to_be_bytes();
    answer[30] = r[0];
    answer[31] = r[1];
    answer
}
