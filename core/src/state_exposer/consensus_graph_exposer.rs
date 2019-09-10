// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;

#[derive(Default)]
/// This struct maintains some inner state of consensus graph.
pub struct ConsensusGraphExposer {
    pub best_block_hash: H256,
}
