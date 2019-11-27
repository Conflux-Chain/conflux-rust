// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{
        state::{State, StateTrait},
        StateRootWithAuxInfo,
    },
    sync::{
        state::delta::{
            compress::write_single_zip_file, ChunkKey, ChunkReader, StateDumper,
        },
        Error, ErrorKind,
    },
};
use cfx_types::{Address, H256};
use keccak_hash::keccak;
use primitives::StorageKey;
use rlp::{Encodable, Rlp};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    fs::create_dir_all,
    io::Error as IoError,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Default, RlpDecodable, RlpEncodable)]
pub struct Chunk {
    metadata: Vec<usize>,
    data: Vec<u8>,
}

impl Chunk {
    pub fn estimate_size(&self) -> usize {
        self.data.len() + self.metadata.len() * 8
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.data.extend_from_slice(key);
        self.data.extend_from_slice(value);
        self.metadata.push(key.len());
        self.metadata.push(value.len());
    }

    pub fn chunk_file_path(dir: &Path, hash: &H256) -> PathBuf {
        dir.join(format!("chunk_{:?}", hash)).to_path_buf()
    }

    pub fn parse_hash(path: &Path) -> Option<H256> {
        if !path.is_file() {
            return None;
        }

        let filename = path.file_name()?.to_str()?;
        if !filename.starts_with("chunk_0x") {
            return None;
        }

        H256::from_str(&filename["chunk_0x".len()..]).ok()
    }

    pub fn dump(&self, dir: &Path) -> Result<Option<H256>, IoError> {
        if self.metadata.is_empty() {
            return Ok(None);
        }

        create_dir_all(dir)?;

        let content = self.rlp_bytes();
        let hash = keccak(&content);

        let file_path = Self::chunk_file_path(dir, &hash);
        write_single_zip_file(file_path.as_path(), &content)?;

        Ok(Some(hash))
    }

    pub fn validate(&self, _key: &ChunkKey) -> Result<(), Error> {
        self.validate_internal()
    }

    fn validate_internal(&self) -> Result<(), Error> {
        if self.metadata.is_empty() {
            return Err(ErrorKind::InvalidSnapshotChunk(
                "chunk metadata is empty".into(),
            )
            .into());
        }

        if self.metadata.len() % 2 == 1 {
            return Err(ErrorKind::InvalidSnapshotChunk(
                "chunk metadata len is odd".into(),
            )
            .into());
        }

        if self.data.len() != self.metadata.iter().sum::<usize>() {
            return Err(ErrorKind::InvalidSnapshotChunk(
                "chunk data len mismatch with metadata".into(),
            )
            .into());
        }

        for size in self.metadata.iter() {
            if *size == 0 {
                return Err(ErrorKind::InvalidSnapshotChunk(
                    "chunk key or value is empty".into(),
                )
                .into());
            }
        }

        Ok(())
    }

    pub fn load(
        checkpoint: &H256, chunk_key: &ChunkKey,
    ) -> Result<Option<Chunk>, Error> {
        let root_dir = StateDumper::default_root_dir();

        let reader = match ChunkReader::new(root_dir, checkpoint) {
            Some(reader) => reader,
            None => return Ok(None),
        };

        let chunk_raw = match reader.chunk_raw(chunk_key)? {
            Some(raw) => raw,
            None => return Ok(None),
        };

        Ok(Some(Rlp::new(&chunk_raw).as_val()?))
    }

    pub fn restore(
        &self, state: &mut State, commit_epoch: Option<H256>,
    ) -> Result<Option<StateRootWithAuxInfo>, Error> {
        self.validate_internal()?;

        let mut index = 0;
        let mut data_pos = 0;

        while index < self.metadata.len() {
            let key = &self.data[data_pos..data_pos + self.metadata[index]];
            data_pos += self.metadata[index];
            let value =
                &self.data[data_pos..data_pos + self.metadata[index + 1]];
            data_pos += self.metadata[index + 1];
            index += 2;

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
}
