// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[cfg(test)]
pub fn open_snapshot_db_for_testing(
    snapshot_path: &Path, readonly: bool, mpt_snapshot_path: &Path,
) -> Result<SnapshotDbSqlite> {
    use crate::impls::storage_db::snapshot_mpt_db_sqlite::SnapshotMptDbSqlite;

    use super::SnapshotKvDbSqlite;

    let mpt_snapshot = Arc::new(SnapshotMptDbSqlite::open(
        mpt_snapshot_path,
        readonly,
        &Default::default(),
        &Arc::new(Semaphore::new(DEFAULT_MAX_OPEN_SNAPSHOTS as usize)),
        None,
    )?);

    let kv_snapshot = SnapshotKvDbSqlite::open(
        snapshot_path,
        readonly,
        &Default::default(),
        &Arc::new(Semaphore::new(DEFAULT_MAX_OPEN_SNAPSHOTS as usize)),
    )?;

    Ok(SnapshotDbSqlite {
        snapshot_db: Arc::new(kv_snapshot),
        mpt_snapshot_db: Some(mpt_snapshot),
    })
}

pub trait MptValueKind: Debug {
    fn value_eq(&self, maybe_value: Option<&[u8]>) -> bool;
}

impl MptValueKind for () {
    fn value_eq(&self, maybe_value: Option<&[u8]>) -> bool {
        maybe_value.is_none()
    }
}

impl MptValueKind for Box<[u8]> {
    fn value_eq(&self, maybe_value: Option<&[u8]>) -> bool {
        maybe_value.map_or(false, |v| v.eq(&**self))
    }
}

pub fn check_key_value_load<Value: MptValueKind>(
    snapshot_db: &SnapshotDbSqlite,
    mut kv_iter: impl FallibleIterator<Item = (Vec<u8>, Value), Error = Error>,
    check_value: bool,
) -> Result<u64> {
    let mut checker_count = 0;
    let mut mpt = snapshot_db.open_snapshot_mpt_shared()?;

    let mut cursor = MptCursor::<
        &mut dyn SnapshotMptTraitRead,
        BasicPathNode<&mut dyn SnapshotMptTraitRead>,
    >::new(&mut mpt);
    cursor.load_root()?;
    while let Some((access_key, expected_value)) = kv_iter.next()? {
        let terminal =
            cursor.open_path_for_key::<access_mode::Read>(&access_key)?;
        if check_value {
            let mpt_value = match terminal {
                CursorOpenPathTerminal::Arrived => {
                    cursor.current_node_mut().value_as_slice().into_option()
                }
                CursorOpenPathTerminal::ChildNotFound { .. } => None,
                CursorOpenPathTerminal::PathDiverted(_) => None,
            };
            if !expected_value.value_eq(mpt_value) {
                error!(
                    "mpt value doesn't match snapshot kv. Expected {:?}, got {:?}",
                    expected_value, mpt_value,
                );
            }
        }
        checker_count += 1;
    }
    cursor.finish()?;

    Ok(checker_count)
}

use crate::{
    impls::{
        errors::*,
        merkle_patricia_trie::{
            mpt_cursor::{BasicPathNode, CursorOpenPathTerminal, MptCursor},
            TrieNodeTrait,
        },
        storage_db::snapshot_db_sqlite::SnapshotDbSqlite,
    },
    storage_db::{snapshot_db::OpenSnapshotMptTrait, SnapshotMptTraitRead},
    utils::access_mode,
};
use fallible_iterator::FallibleIterator;
use std::fmt::Debug;

#[cfg(test)]
use crate::impls::{
    defaults::DEFAULT_MAX_OPEN_SNAPSHOTS,
    storage_db::snapshot_kv_db_sqlite::SnapshotDbTrait,
};
#[cfg(test)]
use std::{path::Path, sync::Arc};
#[cfg(test)]
use tokio02::sync::Semaphore;
