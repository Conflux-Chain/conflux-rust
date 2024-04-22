// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::account_config::resources::{
    ChildVASP, Credential, DesignatedDealer, DesignatedDealerPreburns,
    ParentVASP,
};
use serde::{Deserialize, Serialize};

/// A enum that captures the collection of role-specific resources stored under
/// each account type
#[derive(Debug, Serialize, Deserialize)]
pub enum AccountRole {
    ParentVASP {
        vasp: ParentVASP,
        credential: Credential,
    },
    ChildVASP(ChildVASP),
    DesignatedDealer {
        dd_credential: Credential,
        preburn_balances: DesignatedDealerPreburns,
        designated_dealer: DesignatedDealer,
    },
    Unknown,
    // TODO: add other roles
}
