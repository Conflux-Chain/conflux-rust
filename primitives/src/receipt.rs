// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{bytes::Bytes, log_entry::LogEntry};
use cfx_types::{Address, Bloom, U256};
use heapsize::HeapSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

pub const TRANSACTION_OUTCOME_SUCCESS: u8 = 0;
pub const TRANSACTION_OUTCOME_EXCEPTION: u8 = 1;

/// Information describing execution of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The total gas used in the block following execution of the transaction.
    pub gas_used: U256,
    /// The OR-wide combination of all logs' blooms for this transaction.
    pub log_bloom: Bloom,
    /// The logs stemming from this transaction.
    pub logs: Vec<LogEntry>,
    /// Transaction outcome.
    pub outcome_status: u8,
    /// Addresses of contracts created during execution of transaction.
    /// Ordered from earliest creation.
    ///
    /// eg. sender creates contract A and A in constructor creates contract B
    ///
    /// B creation ends first, and it will be the first element of the vector.
    pub contracts_created: Vec<Address>,
    /// Transaction output.
    pub output: Bytes,
}

impl Receipt {
    pub fn new(
        outcome: u8, gas_used: U256, logs: Vec<LogEntry>,
        contracts_created: Vec<Address>, output: Bytes,
    ) -> Self
    {
        Self {
            gas_used,
            log_bloom: logs.iter().fold(Bloom::default(), |mut b, l| {
                b.accrue_bloom(&l.bloom());
                b
            }),
            logs,
            outcome_status: outcome,
            contracts_created,
            output,
        }
    }
}

impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(6);
        s.append(&self.gas_used);
        s.append(&self.outcome_status);
        s.append(&self.log_bloom);
        s.append_list(&self.logs);
        s.append_list(&self.contracts_created);
        s.append(&self.output);
    }
}

impl Decodable for Receipt {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 6 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(Receipt {
            gas_used: rlp.val_at(0)?,
            outcome_status: rlp.val_at(1)?,
            log_bloom: rlp.val_at(2)?,
            logs: rlp.list_at(3)?,
            contracts_created: rlp.list_at(4)?,
            output: rlp.val_at(5)?,
        })
    }
}

impl HeapSizeOf for Receipt {
    fn heap_size_of_children(&self) -> usize {
        self.logs.heap_size_of_children()
    }
}
