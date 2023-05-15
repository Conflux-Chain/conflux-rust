// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
#[macro_use]
extern crate log;

pub mod amt;
pub mod delta_mpt;
mod key_value;
pub mod mpt;
pub mod raw;

pub use key_value::MptValue;

#[cfg(feature = "lvmt-storage")]
pub use amt::*;
#[cfg(not(any(
    feature = "lvmt-storage",
    feature = "mpt-storage",
    feature = "raw-storage",
    feature = "rain-storage"
)))]
pub use delta_mpt::*;
#[cfg(feature = "mpt-storage")]
pub use mpt::*;
#[cfg(feature = "rain-storage")]
pub use mpt::{self as rain, *};
#[cfg(feature = "raw-storage")]
pub use raw::*;
