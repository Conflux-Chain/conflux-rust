// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct DbError {
    #[from]
    inner: anyhow::Error,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct MempoolError {
    #[from]
    inner: anyhow::Error,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct VerifyError {
    #[from]
    inner: anyhow::Error,
}

pub fn error_kind(e: &anyhow::Error) -> &'static str {
    if e.downcast_ref::<executor_types::Error>().is_some() {
        return "Execution";
    }
    if e.downcast_ref::<MempoolError>().is_some() {
        return "Mempool";
    }
    if e.downcast_ref::<DbError>().is_some() {
        return "ConsensusDb";
    }
    if e.downcast_ref::<safety_rules::Error>().is_some() {
        return "SafetyRules";
    }
    if e.downcast_ref::<VerifyError>().is_some() {
        return "VerifyError";
    }
    "InternalError"
}
