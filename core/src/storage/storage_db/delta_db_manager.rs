// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// The trait for database manager of Delta MPT.
pub trait DeltaDbTrait:
    KeyValueDbTraitRead
    + KeyValueDbToOwnedReadTrait
    + KeyValueDbTraitTransactionalDyn
{
}

pub trait DeltaDbManagerTrait {
    type DeltaDb: DeltaDbTrait;

    // TODO: Should we add epoch number to db name?
    fn delta_db_name(snapshot_root: &MerkleHash) -> String {
        String::from(snapshot_root.hex())
    }

    fn new_empty_delta_db(&self, delta_db_name: &str) -> Result<Self::DeltaDb>;

    fn get_delta_db(
        &self, delta_db_name: &str,
    ) -> Result<Option<Self::DeltaDb>>;

    /// Destroy a Delta DB. Keep in mind that this method is irrecoverable.
    /// Ref-counting is necessary for Delta1 MPT in Snapshot.
    fn destroy_delta_db(&self, delta_db_name: &str) -> Result<()>;
}

use super::{super::impls::errors::*, key_value_db::*};
use primitives::MerkleHash;
