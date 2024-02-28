// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_logger::error as diem_error;
use std::fmt::{Debug, Display};

pub(crate) trait ErrorNotes<T, E: Display, N: Debug> {
    fn err_notes(self, notes: N) -> Result<T, E>;
}

impl<T, E: Display, N: Debug> ErrorNotes<T, E, N> for Result<T, E> {
    fn err_notes(self, notes: N) -> Result<T, E> {
        if let Err(e) = &self {
            diem_error!(error = %e, notes = ?notes, "Error raised, see notes.");
        }
        self
    }
}
