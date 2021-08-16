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
pub struct StateSyncError {
    #[from]
    inner: anyhow::Error,
}

impl From<executor_types::Error> for StateSyncError {
    fn from(e: executor_types::Error) -> Self {
        StateSyncError { inner: e.into() }
    }
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
    if let Some(e) = e.downcast_ref::<StateSyncError>() {
        if e.inner.downcast_ref::<executor_types::Error>().is_some() {
            return "Execution";
        }
        return "StateSync";
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

#[cfg(test)]
mod tests {
    use super::super::error::{error_kind, StateSyncError};
    use anyhow::Context;

    #[test]
    fn conversion_and_downcast() {
        let error = executor_types::Error::InternalError {
            error: "lalala".to_string(),
        };
        let typed_error: StateSyncError = error.into();
        let upper: anyhow::Result<()> = Err(typed_error).context("Context!");
        assert_eq!(error_kind(&upper.unwrap_err()), "Execution");
    }
}
