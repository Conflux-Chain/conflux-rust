// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Log entry type definition.

use crate::{block::BlockNumber, bytes::Bytes};
use cfx_types::{Address, Bloom, BloomInput, H256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use std::ops::Deref;

/// A record of execution for a `LOG` operation.
#[derive(Default, Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct LogEntry {
    /// The address of the contract executing at the point of the `LOG`
    /// operation.
    pub address: Address,
    /// The topics associated with the `LOG` operation.
    pub topics: Vec<H256>,
    /// The data associated with the `LOG` operation.
    pub data: Bytes,
}

impl MallocSizeOf for LogEntry {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.topics.size_of(ops) + self.data.size_of(ops)
    }
}

impl LogEntry {
    /// Calculates the bloom of this log entry.
    pub fn bloom(&self) -> Bloom {
        self.topics.iter().fold(
            Bloom::from(BloomInput::Raw(&self.address)),
            |mut b, t| {
                b.accrue(BloomInput::Raw(t));
                b
            },
        )
    }
}

/// Log localized in a blockchain.
#[derive(Default, Debug, PartialEq, Clone)]
pub struct LocalizedLogEntry {
    /// Plain log entry.
    pub entry: LogEntry,
    /// Block in which this log was created.
    pub block_hash: H256,
    /// Block number.
    pub block_number: BlockNumber,
    /// Hash of transaction in which this log was created.
    pub transaction_hash: H256,
    /// Index of transaction within block.
    pub transaction_index: usize,
    /// Log position in the block.
    pub log_index: usize,
    /// Log position in the transaction.
    pub transaction_log_index: usize,
}

impl Deref for LocalizedLogEntry {
    type Target = LogEntry;

    fn deref(&self) -> &Self::Target { &self.entry }
}

#[cfg(test)]
mod tests {
    use super::LogEntry;
    use cfx_types::{Address, Bloom};

    #[test]
    fn test_empty_log_bloom() {
        let bloom = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse::<Bloom>().unwrap();
        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();
        let log = LogEntry {
            address,
            topics: vec![],
            data: vec![],
        };
        assert_eq!(log.bloom(), bloom);
    }
}
