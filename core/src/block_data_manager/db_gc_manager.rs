use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use std::cmp::min;

#[derive(Default, DeriveMallocSizeOf)]
pub struct GCProgress {
    pub last_processed: usize,
    pub gc_end: usize,
    pub last_consensus_best_epoch: usize,
    pub expected_end_consensus_best_epoch: usize,
}

impl GCProgress {
    /// Return Some((start_epoch, end_epoch)) if there are epochs to GC.
    pub fn get_gc_range(&self, best_epoch: usize) -> Option<(usize, usize)> {
        if self.gc_end <= self.last_processed
            || best_epoch <= self.last_consensus_best_epoch
        {
            return None;
        }
        let best_epoch =
            min(best_epoch, self.expected_end_consensus_best_epoch);
        let batch_size = (self.gc_end - self.last_processed)
            * (best_epoch - self.last_consensus_best_epoch)
            / (self.expected_end_consensus_best_epoch
                - self.last_consensus_best_epoch);
        Some((self.last_processed + 1, self.last_processed + batch_size))
    }
}
