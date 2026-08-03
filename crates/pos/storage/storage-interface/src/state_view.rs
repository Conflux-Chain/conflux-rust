// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_state_view::{StateView, StateViewId};
use diem_types::term_state::PosState;

/// `VerifiedStateView` is a snapshot of the global state for PoS execution.
///
/// In Conflux PoS, the VM (`PosVM`) reads state exclusively through
/// `pos_state()`.
pub struct VerifiedStateView {
    id: StateViewId,
    pos_state: PosState,
}

impl VerifiedStateView {
    pub fn new(id: StateViewId, pos_state: PosState) -> Self {
        Self { id, pos_state }
    }
}

impl StateView for VerifiedStateView {
    fn id(&self) -> StateViewId { self.id }

    fn pos_state(&self) -> &PosState { &self.pos_state }
}
