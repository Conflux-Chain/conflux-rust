// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{
        state::{State, StateTrait},
        storage_db::{
            key_value_db::KeyValueDbIterableTrait, OpenSnapshotMptTrait,
            SnapshotDbManagerTrait,
        },
        MptSlicer, SnapshotDbManagerSqlite, StateRootWithAuxInfo,
        StorageManager, TrieProof,
    },
    sync::{Error, ErrorKind},
};
use cfx_types::{Address, H256};
use fallible_iterator::FallibleIterator;
use keccak_hash::keccak;
use primitives::{MerkleHash, StorageKey};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    fs::{create_dir_all, File},
    io::{Error as IoError, Read, Write},
    path::{Path, PathBuf},
};
use zip::{write::FileOptions, ZipArchive, ZipWriter};

const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Hash, RlpEncodable, RlpDecodable)]
pub struct ChunkKey {
    pub lower_bound_incl: Option<Vec<u8>>, // `None` for the first key
    pub upper_bound_excl: Option<Vec<u8>>, // `None` for the last key
}

impl ChunkKey {
    pub fn to_chunk_file_name(&self, dir: &Path) -> Box<Path> {
        let hash = keccak(&rlp::encode(self));
        dir.to_path_buf()
            .join(format!("chunk_{:?}", hash))
            .into_boxed_path()
    }
}
#[derive(Clone, RlpEncodable, RlpDecodable)]
pub struct ChunkKeyWithProof {
    pub key: ChunkKey,
    pub proof: TrieProof,
}

/// FIXME Handle the case `next.is_some()`
#[derive(Default, Clone, RlpEncodable, RlpDecodable)]
pub struct RangedManifest {
    pub chunks: Vec<ChunkKeyWithProof>,
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
            if chunk.proof.get_merkle_root() != snapshot_root {
                warn!(
                    "Manifest merkle root should be {:?}, get {:?}",
                    snapshot_root,
                    chunk.proof.get_merkle_root()
                );
                return Err(ErrorKind::InvalidSnapshotManifest(
                    "invalid proof merkle root".into(),
                )
                .into());
            }
            if let Some(ref key) = chunk.key.upper_bound_excl {
                if !chunk.proof.if_proves_key(key).0 {
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
        storage_manager: &StorageManager,
    ) -> Result<Option<RangedManifest>, Error>
    {
        debug!(
            "begin to load manifest, checkpoint = {:?}, start_key = {:?}",
            checkpoint, start_key
        );

        let snapshot_db_manager =
            storage_manager.get_storage_manager().get_snapshot_manager();

        // FIXME: The snapshot logic in sync not completely implemented.
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
pub struct ChunkItem {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Default, RlpEncodable, RlpDecodable)]
pub struct Chunk {
    pub items: Vec<ChunkItem>,
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

    pub fn dump(&self, dir: &Path, key: &ChunkKey) -> Result<(), IoError> {
        create_dir_all(dir)?;

        let content = rlp::encode(self);

        let file_path = key.to_chunk_file_name(dir);
        write_single_zip_file(&file_path, &content)?;

        Ok(())
    }

    pub fn restore(
        &self, state: &mut State, commit_epoch: Option<H256>,
    ) -> Result<Option<StateRootWithAuxInfo>, Error> {
        for item in &self.items {
            let key = &item.key;
            let value = &item.value;
            let mut address = Address::default();
            state.set(
                StorageKey::from_delta_mpt_key(key, address.as_mut()),
                value.to_vec().into_boxed_slice(),
            )?;
        }

        let epoch = match commit_epoch {
            Some(epoch) => epoch,
            None => return Ok(None),
        };

        let root = state.compute_state_root()?;
        state.commit(epoch)?;
        Ok(Some(root))
    }

    pub fn epoch_dir(root_dir: String, epoch: &H256) -> PathBuf {
        PathBuf::from(root_dir).join(format!("epoch_{:?}", epoch))
    }
}

pub struct ChunkReader {
    epoch_dir: PathBuf,
}

impl ChunkReader {
    pub fn new_with_epoch_dir(epoch_dir: PathBuf) -> Option<ChunkReader> {
        if !epoch_dir.is_dir() {
            return None;
        }

        Some(ChunkReader { epoch_dir })
    }

    pub fn chunk_raw(&self, key: &ChunkKey) -> Result<Option<Vec<u8>>, Error> {
        let path = key.to_chunk_file_name(self.epoch_dir.as_path());

        if !path.is_file() {
            return Ok(None);
        }

        Ok(Some(read_single_zip_file(&path)?))
    }
}

pub fn write_single_zip_file(
    path: &Path, content: &[u8],
) -> Result<(), IoError> {
    let file = File::create(path)?;
    let mut zip = ZipWriter::new(file);
    zip.start_file("0", FileOptions::default())?;
    zip.write_all(content)?;
    zip.finish()?;
    Ok(())
}

pub fn read_single_zip_file(path: &Path) -> Result<Vec<u8>, IoError> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file)?;
    let mut zip_file = zip.by_index(0)?;
    let mut content = Vec::new();
    zip_file.read_to_end(&mut content)?;
    Ok(content)
}

// todo add necessary unit tests when code is stable
