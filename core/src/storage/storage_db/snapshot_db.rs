// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Debug)]
pub struct SnapshotInfo {
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

pub trait SnapshotDbTrait:
    KeyValueDbTraitOwnedRead
    + KeyValueDbToOwnedReadTrait
    + KeyValueDbTraitSingleWriter
    + Sized
{
    fn get_null_snapshot() -> Self;

    // FIXME: upon opening we should load something..
    fn open(snapshot_path: &str) -> Result<Option<Self>>;

    // FIXME: we store the snapshot info once in the snapshot and also
    // FIXME: aggregated info in another db. At startup we do a maintenance.
    // FIXME: we may need console input to ask for operations.
    fn get_snapshot_info(&self) -> &SnapshotInfo;
    fn set_snapshot_info(&mut self, snapshot_info: SnapshotInfo);

    // FIXME: what should be stored after a snapshot is created?
    fn create(snapshot_path: &str) -> Result<Self>;

    fn direct_merge(
        &mut self, delta_mpt: &DeltaMptIterator,
    ) -> Result<MerkleHash>;

    // FIXME: the type of old_snapshot_db is not Self, but
    // FIXME: a Box<dyn 'a + KeyValueDbTraitOwnedRead>
    fn copy_and_merge(
        &mut self, old_snapshot_db: &mut Self, delta_mpt: &DeltaMptIterator,
    ) -> Result<MerkleHash>;
}

use super::{
    super::impls::{errors::*, storage_manager::DeltaMptIterator},
    key_value_db::{
        KeyValueDbToOwnedReadTrait, KeyValueDbTraitOwnedRead,
        KeyValueDbTraitSingleWriter,
    },
};
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE, NULL_EPOCH};
