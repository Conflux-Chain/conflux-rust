// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    state::delta::{ChunkReader, StateDumper},
    Error, ErrorKind,
};
use cfx_types::H256;
use primitives::MerkleHash;
use rlp_derive::{RlpDecodableWrapper, RlpEncodableWrapper};

pub type ChunkKey = H256;

#[derive(Default, RlpDecodableWrapper, RlpEncodableWrapper)]
pub struct Manifest {
    chunks: Vec<ChunkKey>,
}

impl Manifest {
    pub fn validate(
        &self, _snapshot_root: &MerkleHash, _start_chunk: &Option<ChunkKey>,
    ) -> Result<(), Error> {
        if self.chunks.is_empty() {
            return Err(ErrorKind::InvalidSnapshotManifest(
                "empty chunks".into(),
            )
            .into());
        }

        Ok(())
    }

    pub fn next_chunk(&self) -> Option<ChunkKey> { None }

    pub fn into_chunks(self) -> Vec<ChunkKey> { self.chunks }

    pub fn load(
        checkpoint: &H256, _start_key: Option<ChunkKey>,
    ) -> Result<Option<Manifest>, Error> {
        let root_dir = StateDumper::default_root_dir();

        let reader = match ChunkReader::new(root_dir, checkpoint) {
            Some(reader) => reader,
            None => return Ok(None),
        };

        Ok(Some(Manifest {
            chunks: reader.chunks()?,
        }))
    }
}
