// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Log entry type definition.

use crate::{block::BlockNumber, bytes::Bytes};
use cfx_types::{Address, Bloom, BloomInput, Space, H256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rlp::RlpStream;
use serde_derive::{Deserialize, Serialize};
use std::ops::Deref;

/// A record of execution for a `LOG` operation.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// The address of the contract executing at the point of the `LOG`
    /// operation.
    pub address: Address,
    /// The topics associated with the `LOG` operation.
    pub topics: Vec<H256>,
    /// The data associated with the `LOG` operation.
    pub data: Bytes,
    /// The space associated with `address`.
    pub space: Space,
}

impl rlp::Encodable for LogEntry {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.space {
            Space::Native => {
                s.begin_list(3);
                s.append(&self.address);
                s.append_list(&self.topics);
                s.append(&self.data);
            }
            Space::Ethereum => {
                s.begin_list(4);
                s.append(&self.address);
                s.append_list(&self.topics);
                s.append(&self.data);
                s.append(&self.space);
            }
        }
    }
}

// We want to remain backward-compatible with pre-CIP90 entries in the DB.
// However, rlp_derive::RlpDecodable is not backward-compatible when adding new
// fields, so we implement backward-compatible decoding manually.
impl rlp::Decodable for LogEntry {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        match rlp.item_count()? {
            3 => Ok(LogEntry {
                address: rlp.val_at(0)?,
                topics: rlp.list_at(1)?,
                data: rlp.val_at(2)?,
                space: Space::Native,
            }),
            4 => Ok(LogEntry {
                address: rlp.val_at(0)?,
                topics: rlp.list_at(1)?,
                data: rlp.val_at(2)?,
                space: rlp.val_at(3)?,
            }),
            _ => Err(rlp::DecoderError::RlpInvalidLength),
        }
    }
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
            Bloom::from(BloomInput::Raw(self.address.as_bytes())),
            |mut b, t| {
                b.accrue(BloomInput::Raw(t.as_bytes()));
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
    /// Epoch number.
    pub epoch_number: BlockNumber,
    /// Hash of transaction in which this log was created.
    pub transaction_hash: H256,
    /// Index of transaction within block.
    pub transaction_index: usize,
    /// Log position in the epoch.
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
    use crate::bytes::Bytes;
    use cfx_types::{Address, Bloom, Space, H256};
    use rlp_derive::RlpEncodable;

    #[derive(PartialEq, Eq, RlpEncodable)]
    pub struct LogEntryOld {
        pub address: Address,
        pub topics: Vec<H256>,
        pub data: Bytes,
    }

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
            space: Space::Native,
        };
        assert_eq!(log.bloom(), bloom);
    }

    #[test]
    fn test_rlp() {
        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        // check RLP for new version
        let log = LogEntry {
            address,
            topics: vec![],
            data: vec![],
            space: Space::Ethereum,
        };

        assert_eq!(log, rlp::decode(&rlp::encode(&log)).unwrap());

        // check RLP for old version
        let log_old = LogEntryOld {
            address,
            topics: vec![],
            data: vec![],
        };

        let log_new: LogEntry = rlp::decode(&rlp::encode(&log_old)).unwrap();

        assert_eq!(
            log_new,
            LogEntry {
                address,
                topics: vec![],
                data: vec![],
                space: Space::Native,
            }
        );
    }
}
