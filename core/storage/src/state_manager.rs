// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::impls as state_impls;

pub use state_impls::{
    errors::*, state::State, state_index::StateIndex,
    state_manager::StateManager,
};

use std::sync::Arc;

// StateManager is the single entry-point to access State for any epoch.
// StateManager manages internal mutability and is thread-safe.

// The trait is created to separate the implementation to another file, and the
// concrete struct is put into inner mod, because the implementation is
// anticipated to be too complex to present in the same file of the API.
pub trait StateManagerTrait {
    /// At the boundary of snapshot, getting a state for new epoch will switch
    /// to new Delta MPT, but it's unnecessary getting a no-commit state.
    ///
    /// With try_open == true, the call fails immediately when the max number of
    /// snapshot open is reached.
    fn get_state_no_commit(
        self: &Arc<Self>, epoch_id: StateIndex, try_open: bool,
    ) -> Result<Option<State>>;
    fn get_state_for_next_epoch(
        self: &Arc<Self>, parent_epoch_id: StateIndex,
    ) -> Result<Option<State>>;
    fn get_state_for_genesis_write(self: &Arc<Self>) -> State;
}
