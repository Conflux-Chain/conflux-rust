// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Helper type with all filter state data.

use cfx_types::H256;

use parking_lot::Mutex;
use primitives::filter::LogFilter;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};

use crate::rpc::types::eth::Log;

pub type BlockNumber = u64;

/// Thread-safe filter state.
#[derive(Clone)]
pub struct SyncPollFilter(Arc<Mutex<PollFilter>>);

impl SyncPollFilter {
    /// New `SyncPollFilter`
    pub fn new(f: PollFilter) -> Self {
        SyncPollFilter(Arc::new(Mutex::new(f)))
    }

    /// Modify underlying filter
    pub fn modify<F, R>(&self, f: F) -> R
    where F: FnOnce(&mut PollFilter) -> R {
        f(&mut self.0.lock())
    }
}

/// Filter state.
#[derive(Clone)]
pub enum PollFilter {
    /// Number of last block which client was notified about.
    Block {
        last_block_number: BlockNumber,
        #[doc(hidden)]
        recent_reported_epochs: VecDeque<(BlockNumber, Vec<H256>)>,
    },
    /// Hashes of all pending transactions the client knows about.
    PendingTransaction(BTreeSet<H256>),
    /// Number of From block number, last seen block hash, pending logs and log
    /// filter itself.
    Logs {
        last_block_number: BlockNumber,
        recent_reported_epochs: VecDeque<(BlockNumber, Vec<H256>)>,
        previous_logs: VecDeque<Vec<Log>>,
        filter: LogFilter,
        include_pending: bool,
    },
}

impl PollFilter {
    pub const MAX_BLOCK_HISTORY_SIZE: usize = 200;
}

/// Returns only last `n` logs
pub fn limit_logs(mut logs: Vec<Log>, limit: Option<usize>) -> Vec<Log> {
    let len = logs.len();
    match limit {
        Some(limit) if len >= limit => logs.split_off(len - limit),
        _ => logs,
    }
}
