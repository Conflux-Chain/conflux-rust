// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait SnapshotDbTrait:
    KeyValueDbTraitOwnedRead
    + KeyValueDbToOwnedReadTrait
    + KeyValueDbTraitSingleWriter
    + Sized
{
    fn get_null_snapshot() -> Self;

    fn open(snapshot_path: &str) -> Result<Option<Self>>;

    fn create(snapshot_path: &str, height: i64) -> Result<Self>;

    fn direct_merge(
        &mut self, delta_mpt: &DeltaMptInserter,
    ) -> Result<MerkleHash>;

    // FIXME: the type of old_snapshot_db is not Self, but
    // FIXME: a Box<dyn 'a + KeyValueDbTraitOwnedRead>
    fn copy_and_merge(
        &mut self, old_snapshot_db: &mut Self, delta_mpt: &DeltaMptInserter,
    ) -> Result<MerkleHash>;
}

use super::{
    super::impls::{errors::*, storage_manager::DeltaMptInserter},
    key_value_db::{
        KeyValueDbToOwnedReadTrait, KeyValueDbTraitOwnedRead,
        KeyValueDbTraitSingleWriter,
    },
};
use primitives::MerkleHash;
