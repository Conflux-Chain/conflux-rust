// The trait for database manager of Delta MPT.
pub trait DeltaDbManagerTrait {
    type DeltaDb: DeltaDbTrait;

    // TODO: Should we add epoch number to db name?
    fn delta_db_name(snapshot_root: &MerkleHash) -> String {
        String::from(snapshot_root.hex())
    }

    fn new_empty_delta_db(
        &self, delta_db_name: &String,
    ) -> Result<Self::DeltaDb>;
    fn get_delta_db(
        &self, delta_db_name: &String,
    ) -> Result<Option<Self::DeltaDb>>;
    /// Destroy a Delta DB. Keep in mind that this method is irrecoverable.
    /// Ref-counting is necessary for Delta1 MPT in Snapshot.
    fn destroy_delta_db(&self, delta_db_name: &String) -> Result<()>;
}

use super::{super::impls::errors::*, delta_db::DeltaDbTrait};
use primitives::MerkleHash;
