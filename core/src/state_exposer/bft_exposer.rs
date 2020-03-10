// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::mem;

#[derive(Clone, Debug)]
pub struct BFTCommitEvent {
    pub epoch: u64,
    pub commit: String,
    pub round: u64,
    pub parent: String,
    pub timestamp: u64,
}

#[derive(Default)]
/// This struct maintains some inner state of BFT.
pub struct BFTStates {
    pub bft_events: Vec<BFTCommitEvent>,
}

impl BFTStates {
    pub fn retrieve(&mut self) -> Self {
        let mut bft_events = Vec::new();
        mem::swap(&mut bft_events, &mut self.bft_events);
        Self { bft_events }
    }
}
