// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::on_chain_config::OnChainConfig;
use serde::{Deserialize, Serialize};

/// Defines the version of Diem Validator software.
#[derive(
    Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize,
)]
pub struct DiemVersion {
    pub major: u64,
}

impl OnChainConfig for DiemVersion {
    const IDENTIFIER: &'static str = "DiemVersion";
}

// NOTE: version number for the next release of Diem (as of Mar-05, 2021)
// Items gated by this version number include:
//  - the ScriptFunction payload type
// TODO: expand the list if more features are gated
pub const DIEM_VERSION_2: DiemVersion = DiemVersion { major: 2 };

// Maximum current known version
pub const DIEM_MAX_KNOWN_VERSION: DiemVersion = DIEM_VERSION_2;
