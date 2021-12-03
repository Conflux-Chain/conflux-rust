// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// extern crate cfx_primitives;

pub mod key_value;
pub mod storage_root_aux;
pub use key_value::StateRoot;
pub use storage_root_aux::{StateRootAuxInfo, StateRootWithAuxInfo};
