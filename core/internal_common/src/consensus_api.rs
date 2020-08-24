// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::epoch_execution_commitment::EpochExecutionCommitment;
use primitives::EpochId;

pub trait StateMaintenanceTrait {
    fn get_pivot_hash_from_epoch_number(
        &self, epoch_number: u64,
    ) -> Result<EpochId, String>;

    fn get_epoch_execution_commitment_with_db(
        &self, block_hash: &EpochId,
    ) -> Option<EpochExecutionCommitment>;

    fn remove_epoch_execution_commitment_from_db(&self, block_hash: &EpochId);
}
