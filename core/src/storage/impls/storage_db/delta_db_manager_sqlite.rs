// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// TODO(yz): Status: WIP.
// TODO(yz): Evaluate whether Sqlite is suitable for DeltaMpt and check if there
// TODO(yz): are good B-Tree based alternatives. The read write locking
// TODO(yz): mechanism of Sqlite may lead to complicated code for us.
#[allow(unused)]
pub struct DeltaDbManagerSqlite {}

impl DeltaDbManagerTrait for DeltaDbManagerSqlite {
    type DeltaDb = KvdbSqlite;

    fn new_empty_delta_db(
        &self, _delta_db_name: &String,
    ) -> Result<Self::DeltaDb> {
        unimplemented!()
    }

    fn get_delta_db(
        &self, _delta_db_name: &String,
    ) -> Result<Option<Self::DeltaDb>> {
        unimplemented!()
    }

    fn destroy_delta_db(&self, _delta_db_name: &String) -> Result<()> {
        unimplemented!()
    }
}

use super::{
    super::{
        super::storage_db::delta_db_manager::DeltaDbManagerTrait, errors::*,
    },
    kvdb_sqlite::KvdbSqlite,
};
