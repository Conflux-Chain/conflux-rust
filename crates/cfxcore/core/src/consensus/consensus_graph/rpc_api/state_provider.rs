use crate::errors::{invalid_params_check, Result as CoreResult};

use cfx_statedb::StateDb;
use cfx_storage::{
    state::StateTrait, state_manager::StateManagerTrait, StorageState,
};
use cfx_types::{Space, H256};

use primitives::EpochNumber;

use super::super::ConsensusGraph;

impl ConsensusGraph {
    pub fn get_storage_state_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StorageState> {
        invalid_params_check(
            rpc_param_name,
            self.validate_stated_epoch(&epoch_number),
        )?;
        let height = invalid_params_check(
            rpc_param_name,
            self.get_height_from_epoch_number(epoch_number),
        )?;
        let hash =
            self.inner.read().get_pivot_hash_from_epoch_number(height)?;
        self.get_storage_state_by_height_and_hash(height, &hash)
    }

    pub fn get_eth_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb> {
        self.get_state_db_by_epoch_number_with_space(
            epoch_number,
            rpc_param_name,
            Some(Space::Ethereum),
        )
    }

    pub fn get_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb> {
        self.get_state_db_by_epoch_number_with_space(
            epoch_number,
            rpc_param_name,
            None,
        )
    }

    fn get_state_db_by_epoch_number_with_space(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
        space: Option<Space>,
    ) -> CoreResult<StateDb> {
        invalid_params_check(
            rpc_param_name,
            self.validate_stated_epoch(&epoch_number),
        )?;
        let height = invalid_params_check(
            rpc_param_name,
            self.get_height_from_epoch_number(epoch_number),
        )?;
        let hash =
            self.inner.read().get_pivot_hash_from_epoch_number(height)?;
        Ok(StateDb::new(
            self.get_state_by_height_and_hash(height, &hash, space)?,
        ))
    }

    fn get_storage_state_by_height_and_hash(
        &self, height: u64, hash: &H256,
    ) -> CoreResult<StorageState> {
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary.check_availability(height, &hash) {
            debug!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            );
            bail!(format!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            ));
        }
        let maybe_state_readonly_index =
            self.data_man.get_state_readonly_index(&hash).into();
        let maybe_state = match maybe_state_readonly_index {
            Some(state_readonly_index) => self
                .data_man
                .storage_manager
                .get_state_no_commit_inner(
                    state_readonly_index,
                    /* try_open = */ true,
                    true,
                )
                .map_err(|e| format!("Error to get state, err={:?}", e))?,
            None => None,
        };

        let state = match maybe_state {
            Some(state) => state,
            None => {
                bail!(format!(
                    "State for epoch (number={:?} hash={:?}) does not exist",
                    height, hash
                ));
            }
        };

        Ok(state)
    }

    fn get_state_by_height_and_hash(
        &self, height: u64, hash: &H256, space: Option<Space>,
    ) -> CoreResult<Box<dyn StateTrait>> {
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary
            .check_read_availability(height, &hash, space)
        {
            debug!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            );
            bail!(format!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            ));
        }
        let maybe_state_readonly_index =
            self.data_man.get_state_readonly_index(&hash).into();
        let maybe_state = match maybe_state_readonly_index {
            Some(state_readonly_index) => self
                .data_man
                .storage_manager
                .get_state_no_commit(
                    state_readonly_index,
                    /* try_open = */ true,
                    space,
                )
                .map_err(|e| format!("Error to get state, err={:?}", e))?,
            None => None,
        };

        let state = match maybe_state {
            Some(state) => state,
            None => {
                bail!(format!(
                    "State for epoch (number={:?} hash={:?}) does not exist",
                    height, hash
                ));
            }
        };

        Ok(state)
    }
}
