// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Default, Derivative, DeriveMallocSizeOf)]
#[derivative(Debug)]
pub struct SnapshotInfo {
    // FIXME: update serve_one_step_sync at maintenance.
    pub serve_one_step_sync: bool,

    pub merkle_root: MerkleHash,
    pub parent_snapshot_height: u64,
    pub height: u64,
    pub parent_snapshot_epoch_id: EpochId,
    // the last element of pivot_chain_parts is the epoch id of the snapshot
    // itself.
    #[derivative(Debug = "ignore")]
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
    type SnapshotDbBorrowSharedType: 'db + SnapshotMptTraitRead;
    type SnapshotDbBorrowMutType: 'db + SnapshotMptTraitRw;
    type SnapshotDbAsOwnedType: 'db + SnapshotMptTraitRw;

    fn open_snapshot_mpt_owned(
        &'db mut self,
    ) -> Result<Self::SnapshotDbBorrowMutType>;

    fn open_snapshot_mpt_as_owned(
        &'db self,
    ) -> Result<Self::SnapshotDbAsOwnedType>;

    fn open_snapshot_mpt_shared(
        &'db self,
    ) -> Result<Self::SnapshotDbBorrowSharedType>;
}

pub trait SnapshotDbTrait:
    KeyValueDbTraitOwnedRead
    + KeyValueDbTraitRead
    + KeyValueDbTraitSingleWriter
    + for<'db> OpenSnapshotMptTrait<'db>
    + Sized
{
    fn get_null_snapshot() -> Self;

    /// Store already_open_snapshots and open_semaphore to update
    /// SnapshotDbManager on destructor. SnapshotDb itself does not take
    /// care of the update on these data.
    fn open(
        snapshot_path: &Path, readonly: bool,
        already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        open_semaphore: &Arc<Semaphore>,
    ) -> Result<Self>;

    /// Store already_open_snapshots and open_semaphore to update
    /// SnapshotDbManager on destructor. SnapshotDb itself does not take
    /// care of the update on these data.
    fn create(
        snapshot_path: &Path,
        already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        open_semaphore: &Arc<Semaphore>,
    ) -> Result<Self>;

    fn direct_merge(&mut self) -> Result<MerkleHash>;

    fn copy_and_merge(&mut self, old_snapshot_db: &Self) -> Result<MerkleHash>;

    fn start_transaction(&mut self) -> Result<()>;

    fn commit_transaction(&mut self) -> Result<()>;
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

use crate::{
    impls::{
        errors::*, storage_db::snapshot_db_manager_sqlite::AlreadyOpenSnapshots,
    },
    storage_db::{
        key_value_db::{KeyValueDbTraitOwnedRead, KeyValueDbTraitSingleWriter},
        KeyValueDbTraitRead, SnapshotMptTraitRead, SnapshotMptTraitRw,
    },
};
use derivative::Derivative;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE, NULL_EPOCH};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{path::Path, sync::Arc};
use tokio::sync::Semaphore;
