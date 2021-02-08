use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use std::cmp::min;

/// Each time we make a new checkpoint, we will mark more data as garbage
/// depending on the parameters. To avoid the GC process affecting normal
/// transaction execution or RPC-handling, we GC data gradually, and expect to
/// finish removing the data in a previous era with less time than the period
/// that the consensus graph makes a new era (the default configuration is to
/// finish GC with half an era).
#[derive(Default, DeriveMallocSizeOf, Debug)]
pub struct GCProgress {
    // The earliest not-garbage-collected epoch.
    // This is the only field that we persist to disk as the GC progress.
    pub next_to_process: u64,

    // The last epoch that we are allowed to garbage collect.
    pub gc_end: u64,

    // The best epoch number of the last time we garbage collect data.
    // This is compared with the latest epoch number to decide how many epochs
    // to GC this time.
    pub last_consensus_best_epoch: u64,

    // The epoch number that we want to finish garbage collection of
    // `self.gc_end`.
    pub expected_end_consensus_best_epoch: u64,
}

impl GCProgress {
    pub fn new(next_to_process: u64) -> Self {
        Self {
            next_to_process,
            ..Default::default()
        }
    }

    /// Compute the GC base range to make sure the GC progress is proportional
    /// to the consensus progress.
    /// The actual GC range for each kind of data is the returned base range
    /// minus the corresponding `additional_maintained*` offset.
    ///
    /// Return `Some((start_epoch, end_epoch))` and the range `[start_epoch,
    /// end_epoch)` will be GCed. Return `None` if there is no work to be
    /// done.
    pub fn get_gc_base_range(&self, best_epoch: u64) -> Option<(u64, u64)> {
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
