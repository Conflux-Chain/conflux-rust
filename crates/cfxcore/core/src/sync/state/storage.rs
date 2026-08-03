// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::Error;
use cfx_storage::{
    rlp_key_value_len,
    storage_db::{
        key_value_db::KeyValueDbIterableTrait, snapshot_db::SnapshotDbTrait,
        OpenSnapshotMptTrait,
    },
    MptSlicer, StorageManager, TrieProof,
};
use cfx_types::H256;
use fallible_iterator::FallibleIterator;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::{EpochId, MerkleHash};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(
    Clone, Hash, Ord, PartialOrd, PartialEq, Eq, Debug, DeriveMallocSizeOf,
)]
pub enum SnapshotSyncCandidate {
    // Wire type_id 0 (OneStepSync) and 2 (IncSync) were never implemented and
    // have been deprecated and removed; `Decodable` rejects those ids. Do not
    // reuse them for a new variant.
    FullSync {
        height: u64,
        snapshot_epoch_id: EpochId,
    },
}

impl SnapshotSyncCandidate {
    fn to_type_id(&self) -> u8 {
        match self {
            SnapshotSyncCandidate::FullSync { .. } => 1,
        }
    }

    pub fn get_snapshot_epoch_id(&self) -> &EpochId {
        match self {
            SnapshotSyncCandidate::FullSync {
                snapshot_epoch_id, ..
            } => snapshot_epoch_id,
        }
    }
}

impl Encodable for SnapshotSyncCandidate {
    fn rlp_append(&self, s: &mut RlpStream) {
        match &self {
            SnapshotSyncCandidate::FullSync {
                height,
                snapshot_epoch_id,
            } => {
                s.begin_list(3)
                    .append(&self.to_type_id())
                    .append(height)
                    .append(snapshot_epoch_id);
            }
        }
    }
}

impl Decodable for SnapshotSyncCandidate {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let type_id: u8 = rlp.val_at(0)?;
        match type_id {
            1 => Ok(SnapshotSyncCandidate::FullSync {
                height: rlp.val_at(1)?,
                snapshot_epoch_id: rlp.val_at(2)?,
            }),
            // type_id 0 (OneStepSync) and 2 (IncSync) were never implemented
            // and are deprecated: reject them so they can never
            // reach a handler. A peer that sends one is treated
            // like any unknown/malformed type. Do not reuse these
            // ids.
            _ => Err(DecoderError::Custom(
                "Unsupported SnapshotSyncCandidate type id",
            )),
        }
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
    DeriveMallocSizeOf,
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
    pub next: Option<Vec<u8>>,
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
    /// `lower_bound_excl` is the previous page's last boundary (the
    /// continuation `start_chunk`), or `None` for the initial page.
    pub fn validate(
        &self, snapshot_root: &MerkleHash, lower_bound_excl: Option<&[u8]>,
    ) -> Result<(), Error> {
        if self.chunk_boundaries.len() != self.chunk_boundary_proofs.len() {
            bail!(Error::InvalidSnapshotManifest(
                "chunk and proof number do not match".into(),
            ));
        }
        if let Some(next) = &self.next {
            match self.chunk_boundaries.last() {
                Some(last) if next == last => (),
                _ => bail!(Error::InvalidSnapshotManifest(
                    "next does not match last boundary".into(),
                )),
            }
        }

        // The per-key proofs below are order-independent, so this is what
        // rejects a permuted/duplicated boundary list (which would otherwise
        // become impossible empty download ranges).
        let mut prev_excl = lower_bound_excl;
        for boundary in &self.chunk_boundaries {
            let boundary = boundary.as_slice();
            if let Some(prev) = prev_excl {
                if boundary <= prev {
                    bail!(Error::InvalidSnapshotManifest(
                        "chunk boundaries are not strictly increasing".into(),
                    ));
                }
            }
            prev_excl = Some(boundary);
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
                bail!(Error::InvalidSnapshotManifest(
                    "invalid proof merkle root".into(),
                ));
            }
            if !proof.if_proves_key(&self.chunk_boundaries[chunk_index]).0 {
                bail!(Error::InvalidSnapshotManifest("invalid proof".into(),));
            }
        }
        Ok(())
    }

    pub fn convert_boundaries_to_chunks(
        chunk_boundaries: Vec<Vec<u8>>,
    ) -> Vec<ChunkKey> {
        let mut chunks = Vec::with_capacity(chunk_boundaries.len());
        let mut lower = None;
        for key in chunk_boundaries {
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
        snapshot_to_sync: &SnapshotSyncCandidate, start_key: Option<Vec<u8>>,
        storage_manager: &StorageManager, chunk_size: u64, max_chunks: usize,
    ) -> Result<Option<(RangedManifest, MerkleHash)>, Error> {
        let snapshot_epoch_id = match snapshot_to_sync {
            SnapshotSyncCandidate::FullSync {
                snapshot_epoch_id, ..
            } => snapshot_epoch_id,
        };
        debug!(
            "begin to load manifest, snapshot_epoch_id = {:?}, start_key = {:?}",
            snapshot_epoch_id, start_key
        );

        let snapshot_db_manager =
            storage_manager.get_storage_manager().get_snapshot_manager();

        let snapshot_db = match snapshot_db_manager.get_snapshot_by_epoch_id(
            snapshot_epoch_id,
            /* try_open = */ true,
            true,
        )? {
            Some(db) => db,
            None => {
                debug!(
                    "failed to load manifest, cannot find snapshot {:?}",
                    snapshot_epoch_id
                );
                return Ok(None);
            }
        };
        let mut snapshot_mpt = snapshot_db.open_snapshot_mpt_shared()?;
        let merkle_root = snapshot_mpt.merkle_root;
        let mut slicer = match start_key {
            Some(ref key) => MptSlicer::new_from_key(&mut snapshot_mpt, key)?,
            None => MptSlicer::new(&mut snapshot_mpt)?,
        };

        let mut manifest = RangedManifest::default();
        let mut has_next = true;

        // The slicer advances monotonically through the trie, so the boundaries
        // come out strictly increasing -- the invariant the receiver enforces
        // in `validate`.
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
            // TODO: Now this may happen if the requested peer has opened
            // maximal number of snapshots and cannot give a
            // response temporarily, we should differentiate this
            // from dishonest behaviors.
            return Err(Error::EmptySnapshotChunk.into());
        }
        if self.keys.len() != self.values.len() {
            return Err(Error::InvalidSnapshotChunk(
                "keys and values do not match".into(),
            )
            .into());
        }
        // the key of first item in chunk should match with the requested key
        if let Some(ref start_key) = key.lower_bound_incl {
            if start_key != &self.keys[0] {
                return Err(
                    Error::InvalidSnapshotChunk("key mismatch".into()).into()
                );
            }
        }

        Ok(())
    }

    pub fn load(
        snapshot_epoch_id: &H256, chunk_key: &ChunkKey,
        storage_manager: &StorageManager, max_chunk_size: u64,
    ) -> Result<Option<Chunk>, Error> {
        debug!(
            "begin to load chunk, snapshot_epoch_id = {:?}, key = {:?}",
            snapshot_epoch_id, chunk_key
        );

        let snapshot_db_manager =
            storage_manager.get_storage_manager().get_snapshot_manager();

        let snapshot_db = match snapshot_db_manager.get_snapshot_by_epoch_id(
            snapshot_epoch_id,
            /* try_open = */ true,
            false,
        )? {
            Some(db) => db,
            None => {
                debug!("failed to load chunk, cannot find snapshot by checkpoint {:?}",
                       snapshot_epoch_id);
                return Ok(None);
            }
        };

        let mut kv_iterator = snapshot_db.snapshot_kv_iterator()?.take();
        let lower_bound_incl =
            chunk_key.lower_bound_incl.clone().unwrap_or_default();
        let upper_bound_excl =
            chunk_key.upper_bound_excl.as_ref().map(|k| k.as_slice());
        let mut kvs = kv_iterator
            .iter_range(lower_bound_incl.as_slice(), upper_bound_excl)?
            .take();

        let mut keys = Vec::new();
        let mut values = Vec::new();
        let mut chunk_size = 0;
        while let Some((key, value)) = kvs.next()? {
            chunk_size += rlp_key_value_len(key.len() as u16, value.len());
            if chunk_size > max_chunk_size {
                let msg =
                    format!("Exceed max allowed chunk size {}", max_chunk_size);
                error!("{}", msg);
                return Err(Error::InvalidSnapshotChunk(msg).into());
            }

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

#[cfg(test)]
mod tests {
    use super::RangedManifest;
    use cfx_storage::TrieProof;
    use cfx_types::H256;

    fn manifest(boundaries: Vec<Vec<u8>>) -> RangedManifest {
        let chunk_boundary_proofs =
            boundaries.iter().map(|_| TrieProof::default()).collect();
        RangedManifest {
            chunk_boundaries: boundaries,
            chunk_boundary_proofs,
            next: None,
        }
    }

    // Non-null so the default proofs fail their root check, letting tests tell
    // the ordering error apart from the proof error.
    fn non_null_root() -> H256 { H256::from_low_u64_be(1) }

    #[test]
    fn reversed_boundaries_are_rejected() {
        let err = manifest(vec![vec![2], vec![1]])
            .validate(&non_null_root(), None)
            .expect_err("reversed boundaries must be rejected");
        assert!(
            err.to_string().contains("strictly increasing"),
            "expected ordering error, got: {}",
            err
        );
    }

    #[test]
    fn duplicate_boundaries_are_rejected() {
        let err = manifest(vec![vec![1], vec![1]])
            .validate(&non_null_root(), None)
            .expect_err("duplicate boundaries must be rejected");
        assert!(
            err.to_string().contains("strictly increasing"),
            "expected ordering error, got: {}",
            err
        );
    }

    #[test]
    fn boundary_not_greater_than_lower_bound_is_rejected() {
        let err = manifest(vec![vec![5]])
            .validate(&non_null_root(), Some(&[5]))
            .expect_err("boundary equal to lower bound must be rejected");
        assert!(
            err.to_string().contains("strictly increasing"),
            "expected ordering error, got: {}",
            err
        );

        let err = manifest(vec![vec![4]])
            .validate(&non_null_root(), Some(&[5]))
            .expect_err("boundary below lower bound must be rejected");
        assert!(
            err.to_string().contains("strictly increasing"),
            "expected ordering error, got: {}",
            err
        );
    }

    #[test]
    fn in_order_boundaries_pass_ordering_check() {
        let err = manifest(vec![vec![1], vec![2]])
            .validate(&non_null_root(), Some(&[0]))
            .expect_err("dummy proofs must fail the proof check");
        assert!(
            !err.to_string().contains("strictly increasing"),
            "in-order boundaries must pass the ordering check, got: {}",
            err
        );
    }
}
