// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod mpt_slicer;
pub use self::mpt_slicer::MptSlicer;

// FIXME: remove the allow unused line.
#[allow(unused)]
impl<
        DbType: KeyValueDbTraitOwnedRead<ValueType = SnapshotMptDbValue> + ?Sized,
        BorrowType: BorrowMut<DbType>,
    > SnapshotMpt<DbType, BorrowType>
where DbType:
        for<'db> KeyValueDbIterableTrait<'db, SnapshotMptValue, Error, [u8]>
{
    fn compute_sync_manifest(
        &mut self, key: &[u8],
    ) -> Result<Option<RangedManifest>> {
        let mut slicer = MptSlicer::new_from_key(self, key)?;
        // FIXME: there is no chunk size passed, use a hardcoded number as demo.
        slicer.advance(1048576)?;
        let _proof = slicer.to_proof();
        unimplemented!()
    }
}

use super::{
    super::storage_db::*, errors::*, storage_db::snapshot_mpt::SnapshotMpt,
};
use crate::sync::RangedManifest;
use std::borrow::BorrowMut;
