// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[cfg(test)]
mod state;

use super::state_manager::StateManager;
use crate::{ext_db::SystemDB, storage::state_manager::StorageConfiguration};
use elastic_array::ElasticArray128;
use kvdb::{DBTransaction, KeyValueDB};
use std::{io::Result, sync::Arc};

#[derive(Default)]
pub struct FakeDbForStateTest {}

impl KeyValueDB for FakeDbForStateTest {
    fn get(
        &self, _col: Option<u32>, _key: &[u8],
    ) -> Result<Option<ElasticArray128<u8>>> {
        Ok(None)
    }

    fn get_by_prefix(
        &self, _col: Option<u32>, _prefix: &[u8],
    ) -> Option<Box<[u8]>> {
        unreachable!()
    }

    /// No-op
    fn write_buffered(&self, _transaction: DBTransaction) {}

    /// No-op
    fn flush(&self) -> Result<()> { Ok(()) }

    fn iter<'a>(
        &'a self, _col: Option<u32>,
    ) -> Box<Iterator<Item = (Box<[u8]>, Box<[u8]>)>> {
        unreachable!()
    }

    fn iter_from_prefix<'a>(
        &'a self, _col: Option<u32>, _prefix: &'a [u8],
    ) -> Box<Iterator<Item = (Box<[u8]>, Box<[u8]>)>> {
        unreachable!()
    }

    fn restore(&self, _new_db: &str) -> Result<()> { unreachable!() }
}

pub fn new_state_manager_for_testing() -> StateManager {
    StateManager::new(
        Arc::new(SystemDB::new(Arc::new(FakeDbForStateTest::default()))),
        StorageConfiguration {
            cache_start_size: 1_000_000,
            cache_size: 20_000_000,
            idle_size: 200_000,
            node_map_size: 20_000_000,
            recent_lfu_factor: 4.0,
        },
    )
}
