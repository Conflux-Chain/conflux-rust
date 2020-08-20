// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockDataManager, channel::Channel,
    consensus::consensus_inner::ConsensusGraphInner, Notifications,
};
use cfx_parameters::{consensus::*, light::BLAME_CHECK_OFFSET};
use primitives::BlockHeader;
use std::{collections::VecDeque, sync::Arc};

pub struct BlameVerifier {
    /// Channel used to send verified headers to the light sync layer.
    /// Each element is <height, maybe_witness>
    blame_sender: Arc<Channel<(u64, Option<u64>)>>,

    /// Block data manager.
    data_man: Arc<BlockDataManager>,

    /// Last epoch received from ConsensusNewBlockHandler.
    last_epoch_received: u64,

    /// Next epoch we plan to process.
    next_epoch_to_process: u64,

    /// Queue of epochs that need to be re-processed.
    queue: VecDeque<u64>,
}

impl BlameVerifier {
    pub fn new(
        data_man: Arc<BlockDataManager>, notifications: Arc<Notifications>,
    ) -> Self {
        let blame_sender = notifications.blame_verification_results.clone();

        let stable_hash = data_man.get_cur_consensus_era_stable_hash();

        let stable_height = data_man
            .block_header_by_hash(&stable_hash)
            .expect("Current era stable header should exist")
            .height();

        let start_height = stable_height.saturating_sub(BLAME_CHECK_OFFSET);

        debug!("Starting Blame Verifier from height {}", start_height);

        let last_epoch_received = start_height;
        let next_epoch_to_process = start_height + 1;
        let queue = VecDeque::new();

        Self {
            blame_sender,
            data_man,
            last_epoch_received,
            next_epoch_to_process,
            queue,
        }
    }

    fn header_from_height(
        &self, inner: &ConsensusGraphInner, height: u64,
    ) -> Option<Arc<BlockHeader>> {
        let pivot_index = inner.height_to_pivot_index(height);
        let pivot_arena_index = inner.pivot_chain[pivot_index];
        let pivot_hash = inner.arena[pivot_arena_index].hash;
        self.data_man.block_header_by_hash(&pivot_hash)
    }

    fn first_trusted_header_starting_from(
        &self, inner: &ConsensusGraphInner, height: u64,
    ) -> Option<u64> {
        // check if `height` is available in memory
        let pivot_index = match height {
            h if h < inner.get_cur_era_genesis_height() => return None,
            h => inner.height_to_pivot_index(h),
        };

        inner
            .find_first_trusted_starting_from(
                pivot_index,
                Some(1000), /* blame_bound */
                10,         /* min_vote_count */
            )
            .map(|index| inner.pivot_index_to_height(index))
    }

    /// Add `epoch` to the queue and start processing it.
    pub fn process(&mut self, inner: &ConsensusGraphInner, epoch: u64) {
        // we need to keep an offset so that we have
        // enough headers to calculate the blame ratio
        // TODO(thegaram): choose better value for `BLAME_CHECK_OFFSET`
        let epoch = match epoch {
            e if e < BLAME_CHECK_OFFSET => return,
            e => e - BLAME_CHECK_OFFSET,
        };

        trace!("Blame verification received epoch {:?}", epoch);
        self.queue.push_back(epoch);

        loop {
            // process while there are unprocessed epochs
            let epoch = match self.queue.pop_front() {
                Some(e) => e,
                None => break,
            };

            // process until we encounter an epoch for which
            // there is no blame information available
            if !self.check(inner, epoch) {
                break;
            }
        }
    }

    /// Check the blame corresponding to `epoch` and send the verification
    /// results to the light node sync layer.
    /// Returns false if the epoch cannot be processed, true otherwise.
    #[rustfmt::skip]
    pub fn check(&mut self, inner: &ConsensusGraphInner, epoch: u64) -> bool {
        trace!(
            "Blame verification is processing epoch {:?} (last_epoch_received = {}, next_epoch_to_process = {})",
            epoch, self.last_epoch_received, self.next_epoch_to_process
        );

        match epoch {
            // pivot chain reorg
            //
            //                                   ---        ---
            //                               .- | D | <--- | E | <--- ...
            //  ---        ---        ---    |   ---        ---
            // | A | <--- | B | <--- | C | <-*
            //  ---        ---        ---    |   ---
            //                               .- | F | <--- ...
            //                                   ---
            //
            // example (BLAME_CHECK_OFFSET = 2):
            //    check is called with    C, D, E, C, F
            //    we will process epochs  A, B, C, A, B
            //
            // TODO(thegaram): can a fork change the blame status of a header?

            e if e <= self.last_epoch_received => {
                // re-process from fork point
                debug!("Chain reorg ({} --> {}), re-executing", self.last_epoch_received, e);
                self.last_epoch_received = e;
                self.next_epoch_to_process = e;
            }

            // sanity check: epochs are sent in order, one-by-one
            e if e > self.last_epoch_received + 1 => {
                error!(
                    "Unexpected epoch number: e = {}, last_epoch_received = {}",
                    e, self.last_epoch_received
                );

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

            e if e < self.next_epoch_to_process => {
                debug!("Epoch already covered, skipping (e = {}, next_epoch_to_process = {})", e, self.next_epoch_to_process);
                self.last_epoch_received = e;
                return true;
            }

            // sanity check: no epochs are skipped
            e if e > self.next_epoch_to_process => {
                error!("Unexpected epoch number: e = {}, next_epoch_to_process = {}", e, self.next_epoch_to_process);
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
                self.last_epoch_received = e;
            }
        }

        // convert epoch number into pivot height
        let height = epoch + DEFERRED_STATE_EPOCH_COUNT;

        // check blame
        debug!(
            "Finding witness for header at height {} (epoch {})...",
            height, epoch
        );

        match self.first_trusted_header_starting_from(inner, height) {
            // no witness found
            None => {
                warn!(
                    "No witness found for epoch {} (height {});
                    best_epoch_number = {}",
                    epoch,
                    height,
                    inner.best_epoch_number(),
                );

                // this can happen in two cases:
                //
                // (1) we are lagging behind so much that `height`
                //     is no longer maintained in memory.
                //       --> consensus and blame verification are
                //           in sync so this should not happen.
                //
                // (2) there are too many blamed blocks on the
                //     `BLAME_CHECK_OFFSET` suffix of the pivot
                //     chain so we cannot reliably determine the
                //     witness.
                //       --> we will retry during the next invocation of `check`
                //
                // example for (2):
                //
                //       blame     blame     blame
                //       ......    ......    ......
                //      /     |   /     |   /     |
                //  ---       ---       ---       ---
                // | A | <-- | B | <-- | C | <-- | D | <--- ...
                //  ---       ---       ---       ---
                //
                // if we have such a section of the pivot chain of length
                // `BLAME_CHECK_OFFSET` or more, then at the point of
                // receiving A we might not be able to find the corresponding
                // witness. in this case, we store this epoch for processing
                // later. we assume here that the pivot chain will eventually
                // normalize and we will be able to find the witness later.

                // save for further processing and terminate
                self.queue.push_front(epoch);
                return false;
            }

            // header is not blamed (i.e. it is its own witness)
            Some(w) if w == height => {
                trace!("Epoch {} (height {}) is NOT blamed", epoch, height);

                let header = self
                    .header_from_height(inner, height)
                    .expect("Pivot header exists");

                // normal case: blaming blocks have been covered previously,
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
                self.next_epoch_to_process = epoch + 1;
            }

            // header is blamed
            Some(w) => {
                debug!(
                    "Epoch {} (height {}) is blamed, requesting witness {}",
                    epoch, height, w
                );

                // this request covers all blamed headers:
                // [height, height + 1, ..., w]
                self.blame_sender.send((height, Some(w)));

                // skip all subsequent headers requested
                assert!(w > DEFERRED_STATE_EPOCH_COUNT);
                let witness_epoch = w - DEFERRED_STATE_EPOCH_COUNT;
                self.next_epoch_to_process = witness_epoch + 1;
            }
        }

        true
    }
}
