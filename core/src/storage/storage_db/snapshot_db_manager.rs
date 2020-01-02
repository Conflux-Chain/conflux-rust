// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// The trait for database manager of Snapshot.
pub trait SnapshotDbManagerTrait {
    type SnapshotDb: SnapshotDbTrait<ValueType = Box<[u8]>>;

    // Scan snapshot dir, remove extra files and return the list of missing
    // snapshots.
    fn scan_persist_state(
        &self, snapshot_info_map: &mut HashMap<EpochId, SnapshotInfo>,
    ) -> Result<Vec<EpochId>>;

    fn new_snapshot_by_merging(
        &self, old_snapshot_epoch_id: &EpochId, snapshot_epoch_id: EpochId,
        delta_mpt: DeltaMptIterator, in_progress_snapshot_info: SnapshotInfo,
    ) -> Result<SnapshotInfo>;
    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Self::SnapshotDb>>;
    fn destroy_snapshot(&self, snapshot_epoch_id: &EpochId) -> Result<()>;

    fn new_temp_snapshot_for_full_sync(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> Result<Self::SnapshotDb>;

    fn finalize_full_sync_snapshot(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> Result<()>;
}

use super::{
    super::impls::{delta_mpt::DeltaMptIterator, errors::*},
    snapshot_db::*,
};
use primitives::{EpochId, MerkleHash};
use std::collections::HashMap;
