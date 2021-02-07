use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use std::cmp::min;

#[derive(Default, DeriveMallocSizeOf)]
pub struct GCProgress {
    pub next_to_process: u64,
    pub gc_end: u64,
    pub last_consensus_best_epoch: u64,
    pub expected_end_consensus_best_epoch: u64,
}

impl GCProgress {
    pub fn new(next_to_process: u64) -> Self {
        Self {
            next_to_process,
            ..Default::default()
        }
    }

    /// Return Some((start_epoch, end_epoch)) if there are epochs to GC.
    pub fn get_gc_range(&self, best_epoch: u64) -> Option<(u64, u64)> {
        if self.gc_end <= self.next_to_process
            || best_epoch <= self.last_consensus_best_epoch
        {
            return None;
        }
        let best_epoch =
            min(best_epoch, self.expected_end_consensus_best_epoch);
        let batch_size = (self.gc_end - self.next_to_process)
            * (best_epoch - self.last_consensus_best_epoch)
            / (self.expected_end_consensus_best_epoch
                - self.last_consensus_best_epoch);
        Some((self.next_to_process, self.next_to_process + batch_size))
    }
}
