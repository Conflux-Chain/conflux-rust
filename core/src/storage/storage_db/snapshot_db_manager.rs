// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// FIXME: Even for full node it should keep corresponding db
// FIXME: to do verifiable proof for light client.
// FIXME: And archive node may store all wire-formats and
// FIXME: some other dbs to answer verifiable proofs.
/// The trait for database manager of Snapshot.
pub trait SnapshotDbManagerTrait {
    type SnapshotDb: SnapshotDbTrait;

    fn new_snapshot_by_merging(
        &self, old_snapshot_root: &MerkleHash, snapshot_epoch_id: EpochId,
        height: u64, delta_mpt: DeltaMptInserter,
    ) -> Result<Arc<Self::SnapshotDb>>;
    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Arc<Self::SnapshotDb>>>;
    fn get_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<Option<Arc<Self::SnapshotDb>>>;
    fn destroy_snapshot(&self, snapshot_root: &MerkleHash) -> Result<()>;
}

use super::{
    super::impls::{
        errors::*, storage_manager::storage_manager::DeltaMptInserter,
    },
    snapshot_db::*,
};
use primitives::{EpochId, MerkleHash};
use std::sync::Arc;
