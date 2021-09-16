// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::chain_id::ChainId;
use move_core_types::move_resource::MoveResource;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ChainIdResource {
    chain_id: u64,
}

impl ChainIdResource {
    pub fn chain_id(&self) -> ChainId { ChainId::new(self.chain_id) }
}

impl MoveResource for ChainIdResource {
    const MODULE_NAME: &'static str = "ChainId";
    const STRUCT_NAME: &'static str = "ChainId";
}
