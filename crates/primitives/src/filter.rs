// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Blockchain filter

use crate::{epoch::EpochNumber, log_entry::LogEntry};
use cfx_types::{Address, Bloom, BloomInput, Space, H256};
use std::{
    error, fmt,
    ops::{Deref, DerefMut},
};

#[derive(Debug, PartialEq, Clone)]
/// Errors concerning log filtering.
pub enum FilterError {
    /// Filter has wrong epoch numbers set.
    InvalidEpochNumber {
        from_epoch: u64,
        to_epoch: u64,
    },

    /// Filter has wrong block numbers set.
    InvalidBlockNumber {
        from_block: u64,
        to_block: u64,
    },

    OutOfBoundEpochNumber {
        to_epoch: u64,
        max_epoch: u64,
    },

    EpochNumberGapTooLarge {
        from_epoch: u64,
        to_epoch: u64,
        max_gap: u64,
    },

    BlockNumberGapTooLarge {
        from_block: u64,
        to_block: u64,
        max_gap: u64,
    },

    /// Roots for verifying the requested epochs are unavailable.
    UnableToVerify {
        epoch: u64,
        latest_verifiable: u64,
    },

    /// The block requested does not exist
    UnknownBlock {
        hash: H256,
    },

    /// Epoch cannot be served as it was already pruned from db on a full node
    EpochAlreadyPruned {
        epoch: u64,
        min: u64,
    },

    /// Block cannot be served as it was already pruned from db on a full node
    // Use this when the corresponding epoch is not known.
    BlockAlreadyPruned {
        block_hash: H256,
    },

    /// Block has not been executed yet
    BlockNotExecutedYet {
        block_hash: H256,
    },

    /// There was a pivot chain reorganization during log filtering
    PivotChainReorg {
        epoch: u64,
        from: H256,
        to: H256,
    },

    /// Filter error with custom error message (e.g. timeout)
    Custom(String),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::FilterError::*;
        let msg = match *self {
            InvalidEpochNumber {
                from_epoch,
                to_epoch,
            } => format! {
                "Filter has wrong epoch numbers set (from: {}, to: {})",
                from_epoch, to_epoch
            },
            InvalidBlockNumber {
                from_block,
                to_block,
            } => format! {
                "Filter has wrong block numbers set (from: {}, to: {})",
                from_block, to_block
            },
            OutOfBoundEpochNumber {
                to_epoch,
                max_epoch,
            } => format! {
                "Filter to_epoch is larger than the current best_epoch (to: {}, max: {})",
                to_epoch, max_epoch,
            },
            EpochNumberGapTooLarge {
                from_epoch,
                to_epoch,
                max_gap,
            } => {
                format! {
                    "The gap between from_epoch and to_epoch is larger than max_gap \
                    (from: {}, to: {}, max_gap: {})",
                    from_epoch, to_epoch, max_gap
                }
            }
            BlockNumberGapTooLarge {
                from_block,
                to_block,
                max_gap,
            } => {
                format! {
                    "The gap between from_block and to_block is larger than max_gap \
                    (from: {}, to: {}, max_gap: {})",
                    from_block, to_block, max_gap
                }
            }
            UnableToVerify {
                epoch,
                latest_verifiable,
            } => format! {
                "Unable to verify epoch {} (latest verifiable epoch is {})",
                epoch, latest_verifiable
            },
            UnknownBlock { hash } => format! {
                "Unable to identify block {:?}", hash
            },
            EpochAlreadyPruned { epoch, min } => format! {
                "Epoch is smaller than the earliest epoch stored (epoch: {}, min: {})",
                epoch, min,
            },
            BlockAlreadyPruned { block_hash } => format! {
                "Block {:?} has been pruned from db", block_hash,
            },
            BlockNotExecutedYet { block_hash } => format! {
                "Block {:?} is not executed yet", block_hash,
            },
            PivotChainReorg { epoch, from, to } => format! {
                "Pivot chain at epoch {} has been reorganized during log filtering: {:?} -> {:?}. Operation terminated to avoid inconsistent results.",
                epoch, from, to,
            },
            Custom(ref s) => s.clone(),
        };

        f.write_fmt(format_args!("Filter error: {}", msg))
    }
}

impl error::Error for FilterError {
    fn description(&self) -> &str { "Filter error" }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LogFilter {
    EpochLogFilter {
        from_epoch: EpochNumber,
        to_epoch: EpochNumber,
        params: LogFilterParams,
    },
    BlockHashLogFilter {
        block_hashes: Vec<H256>,
        params: LogFilterParams,
    },
    BlockNumberLogFilter {
        from_block: u64,
        to_block: u64,
        params: LogFilterParams,
    },
}

/// Log event Filter.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LogFilterParams {
    /// Search addresses.
    ///
    /// If None, match all.
    /// If specified, log must be produced by one of these addresses.
    pub address: Option<Vec<Address>>,

    /// Search topics.
    ///
    /// If None, match all.
    /// If specified, log must contain one of these topics.
    pub topics: Vec<Option<Vec<H256>>>,

    /// Indicate if the log filter can be trusted, so we do not need to check
    /// other fields.
    ///
    /// It is `false` if the Filter is constructed from RPCs,
    /// and `true` if it is generated within the process with trusted logics.
    pub trusted: bool,

    /// Space: Conflux or Ethereum.
    ///
    /// Log must be produced in this space.
    pub space: Space,
}

impl Default for LogFilterParams {
    fn default() -> Self {
        LogFilterParams {
            address: None,
            topics: vec![None, None, None, None],
            trusted: false,
            space: Space::Native,
        }
    }
}

impl Default for LogFilter {
    fn default() -> Self {
        LogFilter::EpochLogFilter {
            from_epoch: EpochNumber::LatestCheckpoint,
            to_epoch: EpochNumber::LatestState,
            params: Default::default(),
        }
    }
}

impl Deref for LogFilter {
    type Target = LogFilterParams;

    fn deref(&self) -> &Self::Target {
        match &self {
            &LogFilter::EpochLogFilter { params, .. } => params,
            &LogFilter::BlockHashLogFilter { params, .. } => params,
            &LogFilter::BlockNumberLogFilter { params, .. } => params,
        }
    }
}

impl DerefMut for LogFilter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            LogFilter::EpochLogFilter { params, .. } => params,
            LogFilter::BlockHashLogFilter { params, .. } => params,
            LogFilter::BlockNumberLogFilter { params, .. } => params,
        }
    }
}

impl LogFilterParams {
    /// Returns combinations of each address and topic.
    pub fn bloom_possibilities(&self) -> Vec<Bloom> {
        let blooms = match self.address {
            Some(ref addresses) if !addresses.is_empty() => addresses
                .iter()
                .map(|ref address| {
                    Bloom::from(BloomInput::Raw(address.as_bytes()))
                })
                .collect(),
            _ => vec![Bloom::default()],
        };

        self.topics.iter().fold(blooms, |bs, topic| match *topic {
            None => bs,
            Some(ref topics) => bs
                .into_iter()
                .flat_map(|bloom| {
                    topics
                        .iter()
                        .map(|topic| {
                            let mut b = bloom.clone();
                            b.accrue(BloomInput::Raw(topic.as_bytes()));
                            b
                        })
                        .collect::<Vec<Bloom>>()
                })
                .collect(),
        })
    }

    /// Returns true if given log entry matches filter.
    pub fn matches(&self, log: &LogEntry) -> bool {
        if log.space != self.space {
            return false;
        }

        let matches = match self.address {
            Some(ref addresses) if !addresses.is_empty() => {
                addresses.iter().any(|address| &log.address == address)
            }
            _ => true,
        };

        matches
            && self
                .topics
                .iter()
                .enumerate()
                .all(|(i, topic)| match *topic {
                    Some(ref topics) if !topics.is_empty() => topics
                        .iter()
                        .any(|topic| log.topics.get(i) == Some(topic)),
                    _ => true,
                })
    }
}

impl From<String> for FilterError {
    fn from(s: String) -> Self { FilterError::Custom(s) }
}
