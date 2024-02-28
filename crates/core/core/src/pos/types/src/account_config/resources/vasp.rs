// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::account_address::AccountAddress;
use move_core_types::move_resource::MoveResource;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ParentVASP {
    num_children: u64,
}

impl ParentVASP {
    pub fn num_children(&self) -> u64 { self.num_children }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ChildVASP {
    parent_vasp_addr: AccountAddress,
}

impl ChildVASP {
    pub fn parent_vasp_addr(&self) -> AccountAddress { self.parent_vasp_addr }
}

impl MoveResource for ParentVASP {
    const MODULE_NAME: &'static str = "VASP";
    const STRUCT_NAME: &'static str = "ParentVASP";
}

impl MoveResource for ChildVASP {
    const MODULE_NAME: &'static str = "VASP";
    const STRUCT_NAME: &'static str = "ChildVASP";
}
