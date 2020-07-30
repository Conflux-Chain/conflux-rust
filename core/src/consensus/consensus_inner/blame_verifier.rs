// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockDataManager,
    channel::Channel,
    consensus::consensus_inner::ConsensusGraphInner,
    parameters::{consensus::*, light::BLAME_CHECK_OFFSET},
    Notifications,
};
use parking_lot::Mutex;
use primitives::BlockHeader;
use std::sync::Arc;

pub struct BlameVerifier {
    /// Block data manager.
    data_man: Arc<BlockDataManager>,

    /// Channel used to send verified headers to the light sync layer.
    /// Each element is <height, maybe_witness>
    blame_sender: Arc<Channel<(u64, Option<u64>)>>,

    /// Last epoch received from ConsensusNewBlockHandler.
    // We use Mutex to allow for interior mutability.
    last_epoch_received: Mutex<u64>,

    /// Next epoch we plan to process.
    // We use Mutex to allow for interior mutability.
    next_epoch_to_process: Mutex<u64>,
}

impl BlameVerifier {
    pub fn new(
        data_man: Arc<BlockDataManager>, notifications: Arc<Notifications>,
    ) -> Self {
        let blame_sender = notifications.blame_verification_results.clone();
        let last_epoch_received = Mutex::new(0);
        let next_epoch_to_process = Mutex::new(0);

        Self {
            data_man,
            blame_sender,
            last_epoch_received,
            next_epoch_to_process,
        }
    }

    fn header_from_height(
        &self, inner: &ConsensusGraphInner, height: u64,
    ) -> Option<BlockHeader> {
        let pivot_index = inner.height_to_pivot_index(height);
        let pivot_arena_index = inner.pivot_chain[pivot_index];
        let pivot_hash = inner.arena[pivot_arena_index].hash;

        self.data_man
            .block_header_by_hash(&pivot_hash)
            .map(|h| (*h).clone())
    }

    fn first_trusted_header_starting_from(
        &self, inner: &ConsensusGraphInner, height: u64,
        blame_bound: Option<u32>,
    ) -> Option<u64>
    {
        // check if `height` is available in memory
        let pivot_index = match height {
            h if h < inner.get_cur_era_genesis_height() => return None,
            h => inner.height_to_pivot_index(h),
        };

        inner
            .find_first_trusted_starting_from(pivot_index, blame_bound)
            .map(|index| inner.pivot_index_to_height(index))
    }

    /// Check the blame corresponding to `epoch` and send the verification
    /// results to the light node sync layer.
    #[rustfmt::skip]
    pub fn check(&self, inner: &ConsensusGraphInner, epoch: u64) {
        // TODO(thegaram): is there a better way to achieve interior mutability?
        let mut last_epoch_received = self.last_epoch_received.lock();
        let mut next_epoch_to_process = self.next_epoch_to_process.lock();

        // we need to keep an offset so that we have
        // enough headers to calculate the blame ratio
        // TODO(thegaram): choose better value for `BLAME_CHECK_OFFSET`
        let epoch = match epoch {
            e if e < BLAME_CHECK_OFFSET => return,
            e => e - BLAME_CHECK_OFFSET,
        };

        trace!(
            "Blame verification received epoch {:?} (last_epoch_received = {}, next_epoch_to_process = {})",
            epoch, *last_epoch_received, *next_epoch_to_process
        );

        match epoch {
            // special case
            e if e == 0 => {
                // EMPTY
            }

            // pivot chain reorg (BLAME_CHECK_OFFSET = 2):
            //
            //                                   ---        ---        ---
            //                               .- | D | <--- | E | <--- | F | <--- ...
            //  ---        ---        ---    |   ---        ---        ---
            // | A | <--- | B | <--- | C | <-*
            //  ---        ---        ---    |   ---
            //                               .- | G | <--- ...
            //                                   ---
            //
            // example 1: depth <= BLAME_CHECK_OFFSET
            //    check is called with    C, D, E, C, G
            //    we will process epochs  A, B, C, A, B
            //    --> A, B, C can be skipped the second time
            //
            // example 2: depth > BLAME_CHECK_OFFSET
            //    check is called with    C, D, E, F, C, G
            //    we will process epochs  A, B, C, D, A, B
            //    --> we have to re-execute from C
            //
            // TODO(thegaram): can a fork change the blame status of a header?

            e if e <= *last_epoch_received => {
                let depth = *last_epoch_received - e;

                if depth <= BLAME_CHECK_OFFSET {
                    // epoch has been processed previously, safe to skip
                    // (we skip by not resetting `next_epoch_to_process`)
                    debug!("Chain reorg ({} --> {}), skipping", *last_epoch_received, e);
                    *last_epoch_received = e;
                    return;
                }

                // re-process from fork point
                debug!("Chain reorg ({} --> {}), re-executing", *last_epoch_received, e);
                *last_epoch_received = e;
                *next_epoch_to_process = e;
            }

            // sanity check: epochs are sent in order, one-by-one
            e if e > *last_epoch_received + 1 => {
                error!(
                    "Unexpected epoch number: e = {}, last_epoch_received = {}",
                    e, *last_epoch_received
                );

                // FIXME(thegaram): double-check assumption
                //   --> this is failing in ghast_consensus_test.py
                assert!(false);
            }

            // epoch already handled through witness
            //
            //                 blames
            //              ............
            //              v          |
            //  ---        ---        ---        ---
            // | A | <--- | B | <--- | C | <--- | D | <--- ...
            //  ---        ---        ---        ---
            //
            // we receive B and proceed to request all blamed headers (B, C);
            // set last-epoch-received to B and next-epoch-to-process to D;
            // we will skip C in the next iteration (it is covered already).

            e if e < *next_epoch_to_process => {
                debug!("Epoch already covered, skipping (e = {}, next_epoch_to_process = {})", e, *next_epoch_to_process);
                *last_epoch_received = e;
                return;
            }

            // sanity check: no epochs are skipped
            e if e > *next_epoch_to_process => {
                error!("Unexpected epoch number: e = {}, next_epoch_to_process = {}", e, *next_epoch_to_process);
                assert!(false);
            }

            // in most cases, we will iterate over the pivot chain sequentially;
            // at each step, the epoch we receive (e) will be the same as the
            // next-epoch-to-process (nep)
            //
            //                         e
            //  ---        ---        ---        ---
            // |   | <--- |   | <--- |   | <--- |   | <--- ...
            //  ---        ---        ---        ---
            //             ler        nep

            // e == last_epoch_received + 1
            // e == next_epoch_to_process
            e => {
                *last_epoch_received = e;
            }
        }

        // convert epoch number into pivot height
        let height = epoch + DEFERRED_STATE_EPOCH_COUNT;

        // check blame
        debug!("Finding witness for header at height {} (epoch {})...", height, epoch);

        match self.first_trusted_header_starting_from(
            inner,
            height,
            Some(1000), /* blame_bound */
        ) {
            // no witness found
            None => {
                error!(
                    "No witness found for epoch {} (height {});
                    best_epoch_number = {}",
                    epoch,
                    height,
                    inner.best_epoch_number(),
                );

                // this can happen in two cases:
                // (1) we are lagging behind so much that `height`
                //     is no longer maintained in memory.
                //       --> this will not happen.
                // (2) there are too many blamed blocks on the
                //     `BLAME_CHECK_OFFSET` suffix of the pivot
                //     chain so we cannot reliably determine the
                //     witness.
                //       --> this is also unlikely but can in theory happen.
                // TODO(thegaram): add retry logic for (2)
                assert!(false);
            }

            // header is not blamed (i.e. it is its own witness)
            Some(w) if w == height => {
                trace!("Epoch {} (height {}) is NOT blamed", epoch, height);

                let header = self
                    .header_from_height(inner, height)
                    .expect("Pivot header exists");

                // normal case: blaming block have been covered previously,
                // so this block must be non-blaming
                if header.blame() == 0 {
                    // send non-blaming header
                    self.blame_sender.send((height, None));
                }

                // special case
                //
                //      blame
                //   ...........                                ---        ---        ---
                //   v          |                           .- | E | <--- | F | <--- | G | <--- ...
                //  ---        ---        ---        ---    |   ---        ---        ---
                // | A | <--- | B | <--- | C | <--- | D | <-*
                //  ---        ---        ---        ---    |   ---
                //                                          .- | H | <--- ...
                //                                              ---
                //
                // example (BLAME_CHECK_OFFSET = 2)
                //    check is called with    C, D, E, F, G, D, H
                //    we will process epochs  A, B, C, D, E, B, C
                //
                // after the chain reorg, we will start re-executing from B
                // B was already covered in A's iteration but it is blaming
                //   --> we do nothing, skip it
                else {
                    // EMPTY
                }

                // continue from the next header on the pivot chain
                *next_epoch_to_process = epoch + 1;
            }

            // header is blamed
            Some(w) => {
                debug!("Epoch {} (height {}) is blamed, requesting witness {}", epoch, height, w);

                // this request covers all blamed headers:
                // [height, height + 1, ..., w]
                self.blame_sender.send((height, Some(w)));

                // skip all subsequent headers requested
                assert!(w > DEFERRED_STATE_EPOCH_COUNT);
                let witness_epoch = w - DEFERRED_STATE_EPOCH_COUNT;
                *next_epoch_to_process = witness_epoch + 1;
            }
        }
    }
}
