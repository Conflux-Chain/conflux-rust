// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::state_manager::StateManager,
    sync::{
        state::delta::{CheckpointDumpManager, ChunkReader, StateDumper},
        Error, ErrorKind,
    },
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
    // FIXME: implement
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
        state_manager: &StateManager,
    ) -> Result<Option<Manifest>, Error>
    {
        let root_dir = StateDumper::default_root_dir();

        // dump state of new checkpoint
        let mut dumper = StateDumper::new(
            root_dir.clone(),
            *checkpoint,
            CheckpointDumpManager::MAX_CHUNK_SIZE,
        );
        match dumper.dump(state_manager) {
            Ok(true) =>
                debug!("CheckpointDumpManager: succeed to dump checkpoint state")
            ,
            Ok(false) => error!(
                "CheckpointDumpManager: failed to dump checkpoint state: state missed"
            ),
            Err(e) => {
                error!("CheckpointDumpManager: failed to dump checkpoint state: {:?}", e)
            }
        }

        let reader = match ChunkReader::new(root_dir, checkpoint) {
            Some(reader) => reader,
            None => return Ok(None),
        };

        Ok(Some(Manifest {
            chunks: reader.chunks()?,
        }))
    }
}
