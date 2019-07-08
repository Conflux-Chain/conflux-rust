// FIXME: WIP.
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
