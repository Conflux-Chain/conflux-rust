// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::state::storage::{Chunk, ChunkKey};
use primitives::{MerkleHash, StateRoot};

#[derive(Default)]
pub struct Restorer {}

#[allow(unused)]
impl Restorer {
    /// Append a chunk for restoration.
    pub fn append(&self, _chunk_key: &ChunkKey, _chunk: Chunk) {
        unimplemented!()
    }

    /// Start to restore chunks asynchronously.
    pub fn start_to_restore(&self) { unimplemented!() }

    /// Check if the restored snapshot match with the specified snapshot root.
    pub fn is_valid(&self, _snapshot_root: &MerkleHash) -> bool {
        unimplemented!()
    }

    pub fn progress(&self) -> RestoreProgress { unimplemented!() }

    pub fn restored_state_root(&self) -> StateRoot { unimplemented!() }
}

#[derive(Default, Debug)]
pub struct RestoreProgress {}

impl RestoreProgress {
    pub fn is_completed(&self) -> bool { unimplemented!() }
}
