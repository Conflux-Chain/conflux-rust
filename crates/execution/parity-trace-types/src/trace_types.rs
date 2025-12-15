// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{action_types::Action, filter::TraceFilter};
use cfx_bytes::Bytes;
use cfx_internal_common::{DatabaseDecodable, DatabaseEncodable};
use cfx_types::{Bloom, Space, H256, U256, U64};
use malloc_size_of_derive::MallocSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

/// Trace localized in vector of traces produced by a single transaction.
///
/// Parent and children indexes refer to positions in this vector.
#[derive(Debug, PartialEq, Clone, MallocSizeOf)]
pub struct ExecTrace {
    #[ignore_malloc_size_of = "ignored for performance reason"]
    /// Type of action performed by a transaction.
    pub action: Action,
    pub valid: bool,
}

impl ExecTrace {
    /// Returns bloom of the trace.
    pub fn bloom(&self) -> Bloom { self.action.bloom() }
}

impl Encodable for ExecTrace {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.action);
        s.append(&self.valid);
    }
}

impl Decodable for ExecTrace {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        match d.item_count()? {
            1 => Ok(ExecTrace {
                action: d.val_at(0)?,
                valid: true,
            }),
            2 => Ok(ExecTrace {
                action: d.val_at(0)?,
                valid: d.val_at(1)?,
            }),
            _ => Err(DecoderError::RlpInvalidLength),
        }
    }
}

pub struct LocalizedTrace {
    pub action: Action,
    pub valid: bool,
    /// Epoch hash.
    pub epoch_hash: H256,
    /// Epoch number.
    pub epoch_number: U256,
    /// Block hash.
    pub block_hash: H256,
    /// Transaction position.
    pub transaction_position: U64,
    /// Signed transaction hash.
    pub transaction_hash: H256,
}

/// Represents all traces produced by a single transaction.
#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable, MallocSizeOf)]
pub struct TransactionExecTraces(pub Vec<ExecTrace>);

impl From<Vec<ExecTrace>> for TransactionExecTraces {
    fn from(v: Vec<ExecTrace>) -> Self { TransactionExecTraces(v) }
}

impl TransactionExecTraces {
    /// Returns bloom of all traces in the collection.
    pub fn bloom(&self) -> Bloom {
        self.0
            .iter()
            .fold(Default::default(), |bloom, trace| bloom | trace.bloom())
    }

    pub fn filter_space(self, space: Space) -> Self {
        // `unwrap` here should always succeed.
        // `vec![]` is just added in case.
        Self(
            TraceFilter::space_filter(space)
                .filter_traces(self)
                .unwrap_or(vec![]),
        )
    }
}

impl Into<Vec<ExecTrace>> for TransactionExecTraces {
    fn into(self) -> Vec<ExecTrace> { self.0 }
}

/// Represents all traces produced by transactions in a single block.
#[derive(
    Debug, PartialEq, Clone, Default, RlpEncodable, RlpDecodable, MallocSizeOf,
)]
pub struct BlockExecTraces(pub Vec<TransactionExecTraces>);

impl From<Vec<TransactionExecTraces>> for BlockExecTraces {
    fn from(v: Vec<TransactionExecTraces>) -> Self { BlockExecTraces(v) }
}

impl BlockExecTraces {
    /// Returns bloom of all traces in the block.
    pub fn bloom(&self) -> Bloom {
        self.0.iter().fold(Default::default(), |bloom, tx_traces| {
            bloom | tx_traces.bloom()
        })
    }

    pub fn filter_space(self, space: Space) -> Self {
        Self(
            self.0
                .into_iter()
                .map(|tx_trace| tx_trace.filter_space(space))
                .collect(),
        )
    }
}

impl Into<Vec<TransactionExecTraces>> for BlockExecTraces {
    fn into(self) -> Vec<TransactionExecTraces> { self.0 }
}

impl DatabaseDecodable for BlockExecTraces {
    fn db_decode(bytes: &[u8]) -> Result<Self, DecoderError> {
        rlp::decode(bytes)
    }
}

impl DatabaseEncodable for BlockExecTraces {
    fn db_encode(&self) -> Bytes { rlp::encode(self) }
}
