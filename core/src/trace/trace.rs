// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::Bytes,
    vm::{ActionParams, CallType},
};
use cfx_internal_common::{DatabaseDecodable, DatabaseEncodable};
use cfx_types::{Address, Bloom, BloomInput, U256};
use malloc_size_of_derive::MallocSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

/// Description of a _call_ action, either a `CALL` operation or a message
/// transaction.
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable)]
pub struct Call {
    /// The sending account.
    pub from: Address,
    /// The destination account.
    pub to: Address,
    /// The value transferred to the destination account.
    pub value: U256,
    /// The gas available for executing the call.
    pub gas: U256,
    /// The input data provided to the call.
    pub input: Bytes,
    /// The type of the call.
    pub call_type: CallType,
}

impl From<ActionParams> for Call {
    fn from(p: ActionParams) -> Self {
        match p.call_type {
            CallType::DelegateCall | CallType::CallCode => Call {
                from: p.address,
                to: p.code_address,
                value: p.value.value(),
                gas: p.gas,
                input: p.data.unwrap_or_else(Vec::new),
                call_type: p.call_type,
            },
            _ => Call {
                from: p.sender,
                to: p.address,
                value: p.value.value(),
                gas: p.gas,
                input: p.data.unwrap_or_else(Vec::new),
                call_type: p.call_type,
            },
        }
    }
}

impl Call {
    /// Returns call action bloom.
    /// The bloom contains from and to addresses.
    pub fn bloom(&self) -> Bloom {
        let mut bloom = Bloom::default();
        bloom.accrue(BloomInput::Raw(self.from.as_bytes()));
        bloom.accrue(BloomInput::Raw(self.to.as_bytes()));
        bloom
    }
}

/// Description of a _create_ action, either a `CREATE` operation or a create
/// transaction.
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable)]
pub struct Create {
    /// The address of the creator.
    pub from: Address,
    /// The value with which the new account is endowed.
    pub value: U256,
    /// The gas available for the creation init code.
    pub gas: U256,
    /// The init code.
    pub init: Bytes,
}

impl From<ActionParams> for Create {
    fn from(p: ActionParams) -> Self {
        Create {
            from: p.sender,
            value: p.value.value(),
            gas: p.gas,
            init: p.code.map_or_else(Vec::new, |c| (*c).clone()),
        }
    }
}

impl Create {
    /// Returns bloom create action bloom.
    /// The bloom contains only from address.
    pub fn bloom(&self) -> Bloom {
        BloomInput::Raw(self.from.as_bytes()).into()
    }
}

/// Description of an action that we trace; will be either a call or a create.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// It's a call action.
    Call(Call),
    /// It's a create action.
    Create(Create),
}

impl Encodable for Action {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        match *self {
            Action::Call(ref call) => {
                s.append(&0u8);
                s.append(call);
            }
            Action::Create(ref create) => {
                s.append(&1u8);
                s.append(create);
            }
        }
    }
}

impl Decodable for Action {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let action_type: u8 = rlp.val_at(0)?;
        match action_type {
            0 => rlp.val_at(1).map(Action::Call),
            1 => rlp.val_at(1).map(Action::Create),
            _ => Err(DecoderError::Custom("Invalid action type.")),
        }
    }
}

impl Action {
    /// Returns action bloom.
    pub fn bloom(&self) -> Bloom {
        match *self {
            Action::Call(ref call) => call.bloom(),
            Action::Create(ref create) => create.bloom(),
        }
    }
}

/// Trace localized in vector of traces produced by a single transaction.
///
/// Parent and children indexes refer to positions in this vector.
#[derive(Debug, PartialEq, Clone, MallocSizeOf)]
pub struct ExecTrace {
    #[ignore_malloc_size_of = "ignored for performance reason"]
    /// Type of action performed by a transaction.
    pub action: Action,
}

impl ExecTrace {
    /// Returns bloom of the trace.
    pub fn bloom(&self) -> Bloom { self.action.bloom() }
}

impl Encodable for ExecTrace {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(1);
        s.append(&self.action);
    }
}

impl Decodable for ExecTrace {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let res = ExecTrace {
            action: d.val_at(0)?,
        };
        Ok(res)
    }
}

/// Represents all traces produced by a single transaction.
#[derive(Debug, PartialEq, Clone, RlpEncodable, RlpDecodable, MallocSizeOf)]
pub struct TransactionExecTraces(pub(crate) Vec<ExecTrace>);

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
}

impl Into<Vec<ExecTrace>> for TransactionExecTraces {
    fn into(self) -> Vec<ExecTrace> { self.0 }
}

/// Represents all traces produced by transactions in a single block.
#[derive(
    Debug, PartialEq, Clone, Default, RlpEncodable, RlpDecodable, MallocSizeOf,
)]
pub struct BlockExecTraces(pub(crate) Vec<TransactionExecTraces>);

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

#[cfg(test)]
mod tests {
    use crate::{
        trace::trace::{
            Action, BlockExecTraces, Call, ExecTrace, TransactionExecTraces,
        },
        vm::CallType,
    };
    use rlp::*;

    #[test]
    fn encode_flat_transaction_traces() {
        let ftt = TransactionExecTraces::from(Vec::new());

        let mut s = RlpStream::new_list(2);
        s.append(&ftt);
        assert!(!s.is_finished(), "List shouldn't finished yet");
        s.append(&ftt);
        assert!(s.is_finished(), "List should be finished now");
        s.out();
    }

    #[test]
    fn encode_flat_block_traces() {
        let fbt = BlockExecTraces::from(Vec::new());

        let mut s = RlpStream::new_list(2);
        s.append(&fbt);
        assert!(!s.is_finished(), "List shouldn't finished yet");
        s.append(&fbt);
        assert!(s.is_finished(), "List should be finished now");
        s.out();
    }

    #[test]
    fn test_trace_serialization() {
        // block #51921

        let flat_trace = ExecTrace {
            action: Action::Call(Call {
                from: "8dda5e016e674683241bf671cced51e7239ea2bc"
                    .parse()
                    .unwrap(),
                to: "37a5e19cc2d49f244805d5c268c0e6f321965ab9".parse().unwrap(),
                value: "3627e8f712373c0000".parse().unwrap(),
                gas: 0x03e8.into(),
                input: vec![],
                call_type: CallType::Call,
            }),
        };

        let flat_trace1 = ExecTrace {
            action: Action::Call(Call {
                from: "3d0768da09ce77d25e2d998e6a7b6ed4b9116c2d"
                    .parse()
                    .unwrap(),
                to: "412fda7643b37d436cb40628f6dbbb80a07267ed".parse().unwrap(),
                value: 0.into(),
                gas: 0x010c78.into(),
                input: vec![0x41, 0xc0, 0xe1, 0xb5],
                call_type: CallType::Call,
            }),
        };

        let block_traces = BlockExecTraces(vec![
            TransactionExecTraces(vec![flat_trace]),
            TransactionExecTraces(vec![flat_trace1]),
        ]);

        let encoded = ::rlp::encode(&block_traces);
        let decoded =
            ::rlp::decode(&encoded).expect("error decoding block traces");
        assert_eq!(block_traces, decoded);
    }
}
