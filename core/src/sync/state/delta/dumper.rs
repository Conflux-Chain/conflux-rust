// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{
        state_manager::{StateManager, StateManagerTrait},
        Error as StorageError, KVInserter, SnapshotAndEpochIdRef,
    },
    sync::{state::delta::chunk::Chunk, Error},
};
use cfx_types::H256;
use std::{env::current_dir, fs::remove_dir_all, path::PathBuf};

pub struct StateDumper {
    epoch: H256,
    epoch_dir: PathBuf,
    max_chunk_size: usize,
    dumping_chunk: Chunk,
}

impl StateDumper {
    pub fn default_root_dir() -> String {
        current_dir()
            .unwrap_or(PathBuf::from("./"))
            .join("state_checkpoints")
            .to_str()
            .expect("state chunk directory should not be empty")
            .to_string()
    }

    pub fn epoch_dir(root_dir: String, epoch: &H256) -> PathBuf {
        PathBuf::from(root_dir).join(format!("epoch_{:?}", epoch))
    }

    pub fn new(root_dir: String, epoch: H256, max_chunk_size: usize) -> Self {
        let epoch_dir = Self::epoch_dir(root_dir, &epoch);

        Self {
            epoch,
            epoch_dir,
            max_chunk_size,
            dumping_chunk: Chunk::default(),
        }
    }

    pub fn dump(
        &mut self, state_manager: &StateManager,
    ) -> Result<bool, Error> {
        let epoch_id =
            SnapshotAndEpochIdRef::new_for_test_only_delta_mpt(&self.epoch);
        let state = match state_manager.get_state_no_commit(epoch_id)? {
            Some(state) => state,
            None => return Ok(false),
        };

        state.dump(self)?;

        // dump last chunk
        self.dumping_chunk.dump(self.epoch_dir.as_path())?;

        Ok(true)
    }

    pub fn remove(root_dir: String, epoch: Option<H256>) -> Result<(), Error> {
        let epoch = match epoch {
            Some(epoch) => epoch,
            None => {
                remove_dir_all(root_dir)?;
                return Ok(());
            }
        };

        let epoch_dir = Self::epoch_dir(root_dir, &epoch);
        remove_dir_all(epoch_dir)?;

        Ok(())
    }
}

impl KVInserter<(Vec<u8>, Box<[u8]>)> for StateDumper {
    fn push(&mut self, v: (Vec<u8>, Box<[u8]>)) -> Result<(), StorageError> {
        self.dumping_chunk.insert(&v.0, &v.1);

        if self.dumping_chunk.estimate_size() > self.max_chunk_size {
            self.dumping_chunk.dump(self.epoch_dir.as_path())?;
            self.dumping_chunk = Chunk::default();
        }

        Ok(())
    }
}
