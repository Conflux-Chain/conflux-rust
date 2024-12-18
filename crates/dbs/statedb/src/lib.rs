// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[macro_use]
extern crate cfx_util_macros;
#[macro_use]
extern crate log;

pub mod global_params;
#[cfg(feature = "testonly_code")]
mod in_memory_storage;
mod statedb;
mod statedb_ext;

use cfx_db_errors::statedb as error;

#[cfg(test)]
mod tests;

pub use self::{
    error::{Error, Result},
    statedb::StateDb as StateDbGeneric,
    statedb_ext::StateDbExt,
};
pub use cfx_storage::utils::access_mode;
pub type StateDb = StateDbGeneric;
