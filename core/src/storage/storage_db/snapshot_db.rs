// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Debug, Default)]
pub struct SnapshotInfo {
    // FIXME: update serve_one_step_sync at maintenance.
    pub serve_one_step_sync: bool,

    pub merkle_root: MerkleHash,
    pub parent_snapshot_height: u64,
    pub height: u64,
    pub parent_snapshot_epoch_id: EpochId,
    // the last element of pivot_chain_parts is the epoch id of the snapshot
    // itself.
    pub pivot_chain_parts: Vec<EpochId>,
}

impl SnapshotInfo {
    pub fn genesis_snapshot_info() -> Self {
        Self {
            serve_one_step_sync: false,
            merkle_root: MERKLE_NULL_NODE,
            parent_snapshot_height: 0,
            height: 0,
            parent_snapshot_epoch_id: NULL_EPOCH,
            pivot_chain_parts: vec![NULL_EPOCH],
        }
    }

    pub fn get_snapshot_epoch_id(&self) -> &EpochId {
        self.pivot_chain_parts.last().unwrap()
    }

    pub fn get_epoch_id_at_height(&self, height: u64) -> Option<&EpochId> {
        if height < self.parent_snapshot_height {
            None
        } else if height == self.parent_snapshot_height {
            Some(&self.parent_snapshot_epoch_id)
        } else if height > self.height {
            None
        } else {
            unsafe {
                Some(self.pivot_chain_parts.get_unchecked(
                    (height - self.parent_snapshot_height - 1) as usize,
                ))
            }
        }
    }
}

pub trait OpenSnapshotMptTrait<'db> {
    type SnapshotMptReadType: 'db + SnapshotMptTraitReadOnly;
    type SnapshotMptWriteType: 'db + SnapshotMptTraitSingleWriter;

    fn open_snapshot_mpt_for_write(
        &'db mut self,
    ) -> Result<Self::SnapshotMptWriteType>;

    fn open_snapshot_mpt_read_only(
        &'db mut self,
    ) -> Result<Self::SnapshotMptReadType>;
}

pub trait SnapshotDbTrait:
    KeyValueDbTraitOwnedRead
    + KeyValueDbToOwnedReadTrait
    + KeyValueDbTraitSingleWriter
    + for<'db> OpenSnapshotMptTrait<'db>
    + Sized
{
    fn get_null_snapshot() -> Self;

    // FIXME: upon opening we should load something..
    fn open(snapshot_path: &str, read_only: bool) -> Result<Option<Self>>;

    // FIXME: what should be stored after a snapshot is created?
    fn create(snapshot_path: &str) -> Result<Self>;

    fn direct_merge(&mut self) -> Result<MerkleHash>;

    fn copy_and_merge(
        &mut self, old_snapshot_db: &mut Self,
    ) -> Result<MerkleHash>;
}

impl Encodable for SnapshotInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(6)
            .append(&self.merkle_root)
            .append(&self.height)
            .append(&self.serve_one_step_sync)
            .append(&self.parent_snapshot_epoch_id)
            .append(&self.parent_snapshot_height)
            .append_list(&self.pivot_chain_parts);
    }
}

impl Decodable for SnapshotInfo {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self {
            merkle_root: rlp.val_at(0)?,
            height: rlp.val_at(1)?,
            serve_one_step_sync: rlp.val_at(2)?,
            parent_snapshot_epoch_id: rlp.val_at(3)?,
            parent_snapshot_height: rlp.val_at(4)?,
            pivot_chain_parts: rlp.list_at(5)?,
        })
    }
}

use super::{
    super::impls::errors::*,
    key_value_db::{
        KeyValueDbToOwnedReadTrait, KeyValueDbTraitOwnedRead,
        KeyValueDbTraitSingleWriter,
    },
};
use crate::storage::storage_db::{
    SnapshotMptTraitReadOnly, SnapshotMptTraitSingleWriter,
};
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE, NULL_EPOCH};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
