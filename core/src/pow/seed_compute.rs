use super::shared;
use super::keccak::{keccak_256, H256};

use std::cell::Cell;

#[derive(Default)]
pub struct SeedHashCompute {
	prev_epoch: Cell<u64>,
	prev_seedhash: Cell<H256>,
}

impl SeedHashCompute {
	#[inline]
	fn reset_cache(&self) {
		self.prev_epoch.set(0);
		self.prev_seedhash.set([0u8; 32]);
	}

	#[inline]
	pub fn hash_block_height(&self, block_height: u64) -> H256 {
		self.hash_epoch(shared::epoch(block_height))
	}

	#[inline]
	pub fn hash_epoch(&self, epoch: u64) -> H256 {
		if epoch < self.prev_epoch.get() {
			// can't build on previous hash if requesting an older block
			self.reset_cache();
		}
		if epoch > self.prev_epoch.get() {
			let seed_hash = SeedHashCompute::resume_compute_seedhash(
				self.prev_seedhash.get(),
				self.prev_epoch.get(),
				epoch,
			);
			self.prev_seedhash.set(seed_hash);
			self.prev_epoch.set(epoch);
		}
		self.prev_seedhash.get()
	}

	#[inline]
	pub fn resume_compute_seedhash(mut hash: H256, start_epoch: u64, end_epoch: u64) -> H256 {
		for _ in start_epoch..end_epoch {
            let mut out = H256::default();
            keccak_256::write(&hash, &mut out);
            hash = out;
		}
		hash
	}
}
