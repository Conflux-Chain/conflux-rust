// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod single_mpt_storage_manager;
mod snapshot_manager;
/// Storage manager manages the lifecycle of SnapshotMPTS and DeltaMPTs.
pub mod storage_manager;

// FIXME: pub scope?
pub use self::storage_manager::*;
