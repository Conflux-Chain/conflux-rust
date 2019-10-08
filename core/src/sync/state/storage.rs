// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{
        storage_db::{
            key_value_db::KeyValueDbIterableTrait, SnapshotDbManagerTrait,
        },
        MptSlicer, SnapshotDbManagerSqlite, TrieProof,
    },
    sync::{Error, ErrorKind},
};
use cfx_types::H256;
use fallible_iterator::FallibleIterator;
use keccak_hash::keccak;
use primitives::MerkleHash;
use rlp_derive::{
    RlpDecodable, RlpDecodableWrapper, RlpEncodable, RlpEncodableWrapper,
};

const DEFAULT_CHUNK_SIZE: i64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Hash, RlpEncodable, RlpDecodable)]
pub struct ChunkKey {
    lower_bound_incl: Option<Vec<u8>>, // `None` for the first key
    upper_bound_excl: Option<Vec<u8>>, // `None` for the last key
}

#[derive(RlpEncodable, RlpDecodable)]
struct ChunkKeyWithProof {
    key: ChunkKey,
    proof: TrieProof,
}

#[derive(Default, RlpEncodable, RlpDecodable)]
pub struct RangedManifest {
    chunks: Vec<ChunkKeyWithProof>,
    next: Option<Vec<u8>>,
}

impl RangedManifest {
    /// Validate the manifest with specified snapshot merkle root and the
    /// requested start chunk key. Basically, the retrieved chunks should
    /// not be empty, and the proofs of all chunk keys are valid.
    pub fn validate(
        &self, snapshot_root: &MerkleHash, start_chunk: &Option<ChunkKey>,
    ) -> Result<(), Error> {
        // chunks in manifest should not be empty
        if self.chunks.is_empty() {
            return Err(ErrorKind::InvalidSnapshotManifest(
                "empty chunks".into(),
            )
            .into());
        }

        // the first chunk should match with the requested start chunk key
        let expected_start_key = start_chunk
            .as_ref()
            .and_then(|chunk| chunk.lower_bound_incl.as_ref());
        let actual_start_key = self.chunks[0].key.lower_bound_incl.as_ref();
        if actual_start_key != expected_start_key {
            return Err(ErrorKind::InvalidSnapshotManifest(
                "start chunk key mismatch".into(),
            )
            .into());
        }

        // ensure the chunks are all in sequence:
        // current_chunk.upper_bound == next_chunk.lower_bound
        for i in 0..self.chunks.len() - 1 {
            let cur_upper_bound = self.chunks[i].key.upper_bound_excl.as_ref();
            let next_lower_bound =
                self.chunks[i + 1].key.lower_bound_incl.as_ref();
            if cur_upper_bound != next_lower_bound {
                return Err(ErrorKind::InvalidSnapshotManifest(format!(
                    "chunks are not continuous at {}",
                    i
                ))
                .into());
            }
        }

        // the upper bound of last chunk key should match with the next chunk
        // key of manifest
        let last_chunk_upper_bound = self.chunks[self.chunks.len() - 1]
            .key
            .upper_bound_excl
            .as_ref();
        if last_chunk_upper_bound != self.next.as_ref() {
            return Err(ErrorKind::InvalidSnapshotManifest(
                "end chunk key mismatch".into(),
            )
            .into());
        }

        // validate the trie proof for all chunks
        for chunk in self.chunks.iter() {
            if let Some(ref key) = chunk.key.upper_bound_excl {
                if !chunk.proof.is_valid_key(key, snapshot_root) {
                    return Err(ErrorKind::InvalidSnapshotManifest(
                        "invalid proof".into(),
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    pub fn next_chunk(&self) -> Option<ChunkKey> {
        let next_chunk_key = self.next.as_ref()?;

        if next_chunk_key.is_empty() {
            return None;
        }

        Some(ChunkKey {
            lower_bound_incl: Some(next_chunk_key.to_vec()),
            upper_bound_excl: None,
        })
    }

    pub fn into_chunks(self) -> Vec<ChunkKey> {
        self.chunks.into_iter().map(|chunk| chunk.key).collect()
    }

    pub fn load(
        checkpoint: &H256, start_key: Option<ChunkKey>,
    ) -> Result<Option<RangedManifest>, Error> {
        debug!(
            "begin to load manifest, checkpoint = {:?}, start_key = {:?}",
            checkpoint, start_key
        );

        let snapshot_db_manager = SnapshotDbManagerSqlite::default();
        let mut snapshot_db = match snapshot_db_manager
            .get_snapshot_by_epoch_id(checkpoint)?
        {
            Some(db) => db,
            None => {
                debug!("failed to load manifest, cannot find snapshot by checkpoint");
                return Ok(None);
            }
        };
        let mut snapshot_mpt = snapshot_db.open_snapshot_mpt_read_only()?;
        let start_key = start_key.and_then(|key| key.lower_bound_incl);
        let mut slicer = match start_key {
            Some(ref key) => MptSlicer::new_from_key(&mut snapshot_mpt, key)?,
            None => MptSlicer::new(&mut snapshot_mpt)?,
        };

        let mut manifest = RangedManifest::default();
        let mut end_key = start_key;

        // todo determine the maximum chunks in a ranged manifest
        let max_chunks = 100;
        for i in 0..max_chunks {
            trace!("cut chunks for manifest, loop = {}", i);
            slicer.advance(DEFAULT_CHUNK_SIZE)?;
            let proof = slicer.to_proof();
            let lower_bound_incl = end_key.take();
            end_key = slicer.get_range_end_key().map(|key| key.to_vec());

            manifest.chunks.push(ChunkKeyWithProof {
                key: ChunkKey {
                    lower_bound_incl,
                    upper_bound_excl: end_key.clone(),
                },
                proof,
            });

            if end_key.is_none() {
                break;
            }
        }

        manifest.next = end_key;

        debug!(
            "succeed to load manifest, chunks = {}, next_chunk_key = {:?}",
            manifest.chunks.len(),
            manifest.next
        );

        Ok(Some(manifest))
    }
}

#[derive(RlpEncodable, RlpDecodable)]
struct ChunkItem {
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Default, RlpEncodableWrapper, RlpDecodableWrapper)]
pub struct Chunk {
    items: Vec<ChunkItem>,
}

impl Chunk {
    /// Validate the chunk with specified key.
    pub fn validate(&self, key: &ChunkKey) -> Result<(), Error> {
        // chunk should not be empty
        if self.items.is_empty() {
            return Err(
                ErrorKind::InvalidSnapshotChunk("empty chunk".into()).into()
            );
        }

        // the key of first item in chunk should match with the requested key
        if let Some(ref start_key) = key.lower_bound_incl {
            if start_key != &self.items[0].key {
                return Err(ErrorKind::InvalidSnapshotChunk(
                    "key mismatch".into(),
                )
                .into());
            }
        }

        // keccak(value) == key
        for item in self.items.iter() {
            if keccak(&item.value).as_ref() != item.key.as_slice() {
                return Err(ErrorKind::InvalidSnapshotChunk(
                    "value hash mismatch with key".into(),
                )
                .into());
            }
        }

        Ok(())
    }

    pub fn load(
        checkpoint: &H256, chunk_key: &ChunkKey,
    ) -> Result<Option<Chunk>, Error> {
        debug!(
            "begin to load chunk, checkpoint = {:?}, key = {:?}",
            checkpoint, chunk_key
        );

        let snapshot_db_manager = SnapshotDbManagerSqlite::default();
        let mut snapshot_db =
            match snapshot_db_manager.get_snapshot_by_epoch_id(checkpoint)? {
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

        let mut items = Vec::new();
        while let Some((key, value)) = kvs.next()? {
            items.push(ChunkItem { key, value });
        }

        debug!(
            "complete to load chunk, items = {}, chunk_key = {:?}",
            items.len(),
            chunk_key
        );

        Ok(Some(Chunk { items }))
    }
}

// todo add necessary unit tests when code is stable
