// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// extern crate cfx_primitives;

pub mod delta_mpt;
pub mod dummy;
mod key_value;

#[cfg(not(feature = "storage-dev"))]
pub use delta_mpt::*;
#[cfg(feature = "storage-dev")]
pub use dummy::*;
pub use key_value::MptValue;
