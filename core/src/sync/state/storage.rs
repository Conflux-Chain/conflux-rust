// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{
        storage_db::{
            key_value_db::KeyValueDbIterableTrait, OpenSnapshotMptTrait,
        },
        MptSlicer, StorageManager, TrieProof,
    },
    sync::{Error, ErrorKind},
};
use cfx_types::H256;
use fallible_iterator::FallibleIterator;
use primitives::{EpochId, MerkleHash};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Hash, Ord, PartialOrd, PartialEq, Eq, Debug)]
pub enum SnapshotSyncCandidate {
    OneStepSync {
        height: u64,
        snapshot_epoch_id: EpochId,
    },
    FullSync {
        height: u64,
        snapshot_epoch_id: EpochId,
    },
    IncSync {
        height: u64,
        base_snapshot_epoch_id: EpochId,
        snapshot_epoch_id: EpochId,
    },
}

impl SnapshotSyncCandidate {
    fn to_type_id(&self) -> u8 {
        match &self {
            SnapshotSyncCandidate::OneStepSync { .. } => 0,
            SnapshotSyncCandidate::FullSync { .. } => 1,
            SnapshotSyncCandidate::IncSync { .. } => 2,
        }
    }
}

impl Encodable for SnapshotSyncCandidate {
    fn rlp_append(&self, s: &mut RlpStream) {
        match &self {
            SnapshotSyncCandidate::OneStepSync {
                height,
                snapshot_epoch_id,
            } => {
                s.begin_list(3)
                    .append(&self.to_type_id())
                    .append(height)
                    .append(snapshot_epoch_id);
            }
            SnapshotSyncCandidate::FullSync {
                height,
                snapshot_epoch_id,
            } => {
                s.begin_list(3)
                    .append(&self.to_type_id())
                    .append(height)
                    .append(snapshot_epoch_id);
            }
            SnapshotSyncCandidate::IncSync {
                height,
                base_snapshot_epoch_id,
                snapshot_epoch_id,
            } => {
                s.begin_list(4)
                    .append(&self.to_type_id())
                    .append(height)
                    .append(base_snapshot_epoch_id)
                    .append(snapshot_epoch_id);
            }
        }
    }
}

impl Decodable for SnapshotSyncCandidate {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let type_id: u8 = rlp.val_at(0)?;
        let parsed = match type_id {
            0 => SnapshotSyncCandidate::OneStepSync {
                height: rlp.val_at(1)?,
                snapshot_epoch_id: rlp.val_at(2)?,
            },
            1 => SnapshotSyncCandidate::FullSync {
                height: rlp.val_at(1)?,
                snapshot_epoch_id: rlp.val_at(2)?,
            },
            2 => SnapshotSyncCandidate::IncSync {
                height: rlp.val_at(1)?,
                base_snapshot_epoch_id: rlp.val_at(2)?,
                snapshot_epoch_id: rlp.val_at(3)?,
            },
            _ => {
                return Err(DecoderError::Custom(
                    "Unknown SnapshotSyncCandidate type id",
                ))
            }
        };
        debug_assert_eq!(parsed.to_type_id(), type_id);
        Ok(parsed)
    }
}

#[derive(
    Clone,
    RlpEncodable,
    RlpDecodable,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Hash,
)]
pub struct ChunkKey {
    lower_bound_incl: Option<Vec<u8>>,
    pub upper_bound_excl: Option<Vec<u8>>,
}

/// FIXME Handle the case `next.is_some()`
#[derive(Default, Clone)]
pub struct RangedManifest {
    pub chunk_boundaries: Vec<Vec<u8>>,
    pub chunk_boundary_proofs: Vec<TrieProof>,
    next: Option<Vec<u8>>,
}

impl Encodable for RangedManifest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append_list::<Vec<u8>, Vec<u8>>(&self.chunk_boundaries)
            .append_list(&self.chunk_boundary_proofs)
            .append(&self.next);
    }
}

impl Decodable for RangedManifest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(RangedManifest {
            chunk_boundaries: rlp.list_at(0)?,
            chunk_boundary_proofs: rlp.list_at(1)?,
            next: rlp.val_at(2)?,
        })
    }
}

impl RangedManifest {
    /// Validate the manifest with specified snapshot merkle root and the
    /// requested start chunk key. Basically, the retrieved chunks should
    /// not be empty, and the proofs of all chunk keys are valid.
    pub fn validate(
        &self, snapshot_root: &MerkleHash, start_chunk: &Option<Vec<u8>>,
    ) -> Result<(), Error> {
        if self.chunk_boundaries.len() != self.chunk_boundary_proofs.len() {
            return Err(ErrorKind::InvalidSnapshotManifest(
                "chunk and proof number do not match".into(),
            )
            .into());
        }
        if let Some(start_key) = start_chunk {
            // chunks in manifest should not be empty
            if self.chunk_boundaries.is_empty() {
                return Err(ErrorKind::InvalidSnapshotManifest(
                    "empty chunks".into(),
                )
                .into());
            }
            if start_key != self.chunk_boundaries.first().expect("Not empty") {
                return Err(ErrorKind::InvalidSnapshotManifest(
                    "chunk start key do not match".into(),
                )
                .into());
            }
        }

        // validate the trie proof for all chunks
        for (chunk_index, proof) in
            self.chunk_boundary_proofs.iter().enumerate()
        {
            if proof.get_merkle_root() != snapshot_root {
                warn!(
                    "Manifest merkle root should be {:?}, get {:?}",
                    snapshot_root,
                    proof.get_merkle_root()
                );
                return Err(ErrorKind::InvalidSnapshotManifest(
                    "invalid proof merkle root".into(),
                )
                .into());
            }
            if !proof.if_proves_key(&self.chunk_boundaries[chunk_index]).0 {
                return Err(ErrorKind::InvalidSnapshotManifest(
                    "invalid proof".into(),
                )
                .into());
            }
        }
        Ok(())
    }

    pub fn into_chunks(self) -> Vec<ChunkKey> {
        let mut chunks = Vec::with_capacity(self.chunk_boundaries.len());
        let mut lower = None;
        for key in self.chunk_boundaries {
            chunks.push(ChunkKey {
                lower_bound_incl: lower,
                upper_bound_excl: Some(key.clone()),
            });
            lower = Some(key);
        }
        chunks.push(ChunkKey {
            lower_bound_incl: lower,
            upper_bound_excl: None,
        });
        chunks
    }

    pub fn load(
        snapshot_epoch_id: &EpochId, start_key: Option<Vec<u8>>,
        storage_manager: &StorageManager, chunk_size: u64,
    ) -> Result<Option<(RangedManifest, MerkleHash)>, Error>
    {
        debug!(
            "begin to load manifest, snapshot_epoch_id = {:?}, start_key = {:?}",
            snapshot_epoch_id, start_key
        );

        let snapshot_db_manager =
            storage_manager.get_storage_manager().get_snapshot_manager();

        let mut snapshot_db = match snapshot_db_manager
            .get_snapshot_by_epoch_id(snapshot_epoch_id)?
        {
            Some(db) => db,
            None => {
                debug!(
                    "failed to load manifest, cannot find snapshot {:?}",
                    snapshot_epoch_id
                );
                return Ok(None);
            }
        };
        let mut snapshot_mpt = snapshot_db.open_snapshot_mpt_owned()?;
        let merkle_root = snapshot_mpt.merkle_root;
        let mut slicer = match start_key {
            Some(ref key) => MptSlicer::new_from_key(&mut snapshot_mpt, key)?,
            None => MptSlicer::new(&mut snapshot_mpt)?,
        };

        let mut manifest = RangedManifest::default();
        let mut has_next = true;

        // todo determine the maximum chunks in a ranged manifest
        let max_chunks = i32::max_value();
        for i in 0..max_chunks {
            trace!("cut chunks for manifest, loop = {}", i);
            slicer.advance(chunk_size)?;
            match slicer.get_range_end_key() {
                None => {
                    has_next = false;
                    break;
                }
                Some(key) => {
                    manifest.chunk_boundaries.push(key.to_vec());
                    manifest.chunk_boundary_proofs.push(slicer.to_proof());
                }
            }
        }

        if has_next {
            manifest.next = Some(
                manifest
                    .chunk_boundaries
                    .last()
                    .expect("boundaries not empty if has next")
                    .clone(),
            );
        }

        debug!(
            "succeed to load manifest, chunks = {}, next_chunk_key = {:?}",
            manifest.chunk_boundaries.len(),
            manifest.next
        );

        Ok(Some((manifest, merkle_root)))
    }
}

#[derive(Default)]
pub struct Chunk {
    pub keys: Vec<Vec<u8>>,
    pub values: Vec<Vec<u8>>,
}

impl Encodable for Chunk {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append_list::<Vec<u8>, Vec<u8>>(&self.keys)
            .append_list::<Vec<u8>, Vec<u8>>(&self.values);
    }
}

impl Decodable for Chunk {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Chunk {
            keys: rlp.list_at(0)?,
            values: rlp.list_at(1)?,
        })
    }
}

impl Chunk {
    /// Validate the chunk with specified key.
    pub fn validate(&self, key: &ChunkKey) -> Result<(), Error> {
        // chunk should not be empty
        if self.keys.is_empty() {
            return Err(
                ErrorKind::InvalidSnapshotChunk("empty chunk".into()).into()
            );
        }
        if self.keys.len() != self.values.len() {
            return Err(ErrorKind::InvalidSnapshotChunk(
                "keys and values do not match".into(),
            )
            .into());
        }
        // the key of first item in chunk should match with the requested key
        if let Some(ref start_key) = key.lower_bound_incl {
            if start_key != &self.keys[0] {
                return Err(ErrorKind::InvalidSnapshotChunk(
                    "key mismatch".into(),
                )
                .into());
            }
        }

        Ok(())
    }

    pub fn load(
        snapshot_epoch_id: &H256, chunk_key: &ChunkKey,
        storage_manager: &StorageManager,
    ) -> Result<Option<Chunk>, Error>
    {
        debug!(
            "begin to load chunk, snapshot_epoch_id = {:?}, key = {:?}",
            snapshot_epoch_id, chunk_key
        );

        let snapshot_db_manager =
            storage_manager.get_storage_manager().get_snapshot_manager();

        let mut snapshot_db = match snapshot_db_manager
            .get_snapshot_by_epoch_id(snapshot_epoch_id)?
        {
            Some(db) => db,
            None => {
                debug!(
                    "failed to load chunk, cannot find snapshot by checkpoint"
                );
                return Ok(None);
            }
        };

        let mut kv_iterator = snapshot_db.snapshot_kv_iterator();
        let lower_bound_incl =
            chunk_key.lower_bound_incl.clone().unwrap_or_default();
        let upper_bound_excl =
            chunk_key.upper_bound_excl.as_ref().map(|k| k.as_slice());
        let mut kvs = kv_iterator
            .iter_range(lower_bound_incl.as_slice(), upper_bound_excl)?;

        let mut keys = Vec::new();
        let mut values = Vec::new();
        while let Some((key, value)) = kvs.next()? {
            keys.push(key);
            values.push(value.into());
        }

        debug!(
            "complete to load chunk, items = {}, chunk_key = {:?}",
            keys.len(),
            chunk_key
        );

        Ok(Some(Chunk { keys, values }))
    }
}

// todo add necessary unit tests when code is stable
