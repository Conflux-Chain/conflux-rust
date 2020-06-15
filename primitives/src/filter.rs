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
use cfx_types::{Address, Bloom, BloomInput, H256};
use std::{error, fmt};

#[derive(Debug, PartialEq, Clone)]
/// Errors concerning log filtering.
pub enum FilterError {
    /// Filter has wrong epoch numbers set.
    InvalidEpochNumber {
        from_epoch: u64,
        to_epoch: u64,
    },

    OutOfBoundEpochNumber {
        to_epoch: u64,
        max_epoch: u64,
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
            OutOfBoundEpochNumber {
                to_epoch,
                max_epoch,
            } => format! {
                "Filter to_epoch is larger than the current best_epoch (to: {}, max: {})",
                to_epoch, max_epoch,
            },
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

/// Log event Filter.
#[derive(Debug, PartialEq)]
pub struct Filter {
    /// Search will be applied from this epoch number.
    pub from_epoch: EpochNumber,

    /// Till this epoch number.
    pub to_epoch: EpochNumber,

    /// Search will be applied in these blocks if given.
    /// This will override from/to_epoch fields.
    pub block_hashes: Option<Vec<H256>>,

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

    /// Logs limit
    ///
    /// If None, return all logs
    /// If specified, should only return *last* `n` logs.
    pub limit: Option<usize>,
}

impl Clone for Filter {
    fn clone(&self) -> Self {
        let mut topics = [None, None, None, None];
        for i in 0..4 {
            topics[i] = self.topics[i].clone();
        }

        Filter {
            from_epoch: self.from_epoch.clone(),
            to_epoch: self.to_epoch.clone(),
            block_hashes: self.block_hashes.clone(),
            address: self.address.clone(),
            topics: topics[..].to_vec(),
            limit: self.limit,
        }
    }
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            from_epoch: EpochNumber::Earliest,
            to_epoch: EpochNumber::LatestMined,
            block_hashes: None,
            address: None,
            topics: vec![None, None, None, None],
            limit: None,
        }
    }
}

impl Filter {
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
