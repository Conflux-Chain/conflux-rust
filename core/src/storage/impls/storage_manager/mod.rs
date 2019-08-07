// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod storage_manager;
mod storage_manager_archive_node;
mod storage_manager_full_node;

// FIXME: pub scope?
pub use self::storage_manager::*;
#[allow(unused)]
pub(self) use self::storage_manager_archive_node::StorageManagerArchiveNode;
pub(self) use self::storage_manager_full_node::StorageManagerFullNode;
