// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_logger::Schema;
use diem_types::{
    contract_event::ContractEvent, ledger_info::LedgerInfoWithSignatures,
};
use serde::Serialize;

#[derive(Clone, Schema)]
pub struct LogSchema {
    name: LogEntry,
    event: Option<LogEvent>,
    subscription_name: Option<String>,
    count: Option<usize>,
    reconfig_events: Option<Vec<ContractEvent>>,
    version: Option<u64>,
    local_li_version: Option<u64>,
    local_synced_version: Option<u64>,
    local_epoch: Option<u64>,
    #[schema(display)]
    ledger_info: Option<LedgerInfoWithSignatures>,
    old_epoch: Option<u64>,
    new_epoch: Option<u64>,
    target_version: Option<u64>,
}

impl LogSchema {
    pub fn new(name: LogEntry) -> Self { Self::new_event(name, None) }

    pub fn event_log(name: LogEntry, event: LogEvent) -> Self {
        Self::new_event(name, Some(event))
    }

    fn new_event(name: LogEntry, event: Option<LogEvent>) -> Self {
        Self {
            name,
            event,
            version: None,
            subscription_name: None,
            reconfig_events: None,
            count: None,
            local_li_version: None,
            local_synced_version: None,
            local_epoch: None,
            ledger_info: None,
            new_epoch: None,
            old_epoch: None,
            target_version: None,
        }
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEntry {
    Reconfig,
    RuntimeStart,
    ConsensusCommit,
    SyncRequest,
    EpochChange,
    CommitFlow,
    ProgressCheck,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEvent {
    CallbackFail,
    Complete,
    Fail,
    Timeout,
    PublishError,
    Success,
    PostCommitFail,
}
