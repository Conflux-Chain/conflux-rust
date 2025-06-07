use super::{
    keccak::{keccak_256, H256},
    shared,
};

use std::cell::Cell;

#[derive(Default)]
pub struct SeedHashCompute {
    prev_stage: Cell<u64>,
    prev_seedhash: Cell<H256>,
}

impl SeedHashCompute {
    #[inline]
    fn reset_cache(&self) {
        self.prev_stage.set(0);
        self.prev_seedhash.set([0u8; 32]);
    }

    #[inline]
    pub fn hash_block_height(&self, block_height: u64) -> H256 {
        self.hash_stage(shared::stage(block_height))
    }

    #[inline]
    pub fn hash_stage(&self, stage: u64) -> H256 {
        if stage < self.prev_stage.get() {
            // can't build on previous hash if requesting an older block
            self.reset_cache();
        }
        if stage > self.prev_stage.get() {
            let seed_hash = SeedHashCompute::resume_compute_seedhash(
                self.prev_seedhash.get(),
                self.prev_stage.get(),
                stage,
            );
            self.prev_seedhash.set(seed_hash);
            self.prev_stage.set(stage);
        }
        self.prev_seedhash.get()
    }

    #[inline]
    pub fn resume_compute_seedhash(
        mut hash: H256, start_stage: u64, end_stage: u64,
    ) -> H256 {
        for _ in start_stage..end_stage {
            let mut out = H256::default();
            keccak_256::write(&hash, &mut out);
            hash = out;
        }
        hash
    }
}
