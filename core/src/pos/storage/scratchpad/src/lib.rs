// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This crate provides in-memory representation of Diem core data structures
//! used by the executor.

mod sparse_merkle;

pub use crate::sparse_merkle::{AccountStatus, ProofRead, SparseMerkleTree};
