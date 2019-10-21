// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    state::delta::{compress::read_single_zip_file, Chunk, StateDumper},
    Error,
};
use cfx_types::H256;
use std::{fs::read_dir, path::PathBuf};

pub struct ChunkReader {
    epoch_dir: PathBuf,
}

impl ChunkReader {
    pub fn new(root_dir: String, epoch: &H256) -> Option<ChunkReader> {
        let epoch_dir = StateDumper::epoch_dir(root_dir, epoch);
        Self::new_with_epoch_dir(epoch_dir)
    }

    pub fn new_with_epoch_dir(epoch_dir: PathBuf) -> Option<ChunkReader> {
        if !epoch_dir.is_dir() {
            return None;
        }

        Some(ChunkReader { epoch_dir })
    }

    pub fn chunks(&self) -> Result<Vec<H256>, Error> {
        let mut hashes = Vec::new();

        for entry in read_dir(&self.epoch_dir)? {
            if let Some(hash) = Chunk::parse_hash(entry?.path().as_path()) {
                hashes.push(hash);
            }
        }

        Ok(hashes)
    }

    pub fn chunk_raw(&self, hash: &H256) -> Result<Option<Vec<u8>>, Error> {
        let path = Chunk::chunk_file_path(self.epoch_dir.as_path(), hash);

        if !path.is_file() {
            return Ok(None);
        }

        Ok(Some(read_single_zip_file(path.as_path())?))
    }
}
