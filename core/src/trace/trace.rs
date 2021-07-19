// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::Bytes,
    executive::ExecutiveResult,
    vm::{ActionParams, CallType, Result as vmResult},
};
use cfx_internal_common::{DatabaseDecodable, DatabaseEncodable};
use cfx_types::{Address, Bloom, BloomInput, H256, U256, U64};
use malloc_size_of_derive::MallocSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::Serialize;
use strum_macros::EnumDiscriminants;

/// Description of a _call_ action, either a `CALL` operation or a message
/// transaction.
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable, Serialize)]
#[serde(rename_all = "camelCase")]
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

/// The outcome of the action result.
#[derive(Debug, PartialEq, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Reverted,
    Fail,
}

impl Encodable for Outcome {
    fn rlp_append(&self, s: &mut RlpStream) {
        let v = match *self {
            Outcome::Success => 0u32,
            Outcome::Reverted => 1,
            Outcome::Fail => 2,
        };
        Encodable::rlp_append(&v, s);
    }
}

impl Decodable for Outcome {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.as_val().and_then(|v| {
            Ok(match v {
                0u32 => Outcome::Success,
                1 => Outcome::Reverted,
                2 => Outcome::Fail,
                _ => {
                    return Err(DecoderError::Custom(
                        "Invalid value of CallType item",
                    ));
                }
            })
        })
    }
}

/// Description of the result of a _call_ action.
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallResult {
    /// The outcome of the result
    pub outcome: Outcome,
    /// The amount of gas left
    pub gas_left: U256,
    /// Output data
    pub return_data: Bytes,
}

impl From<&vmResult<ExecutiveResult>> for CallResult {
    fn from(r: &vmResult<ExecutiveResult>) -> Self {
        match r {
            Ok(ExecutiveResult {
                gas_left,
                return_data,
                apply_state: true,
                ..
            }) => CallResult {
                outcome: Outcome::Success,
                gas_left: gas_left.clone(),
                return_data: return_data.to_vec(),
            },
            Ok(ExecutiveResult {
                gas_left,
                return_data,
                apply_state: false,
                ..
            }) => CallResult {
                outcome: Outcome::Reverted,
                gas_left: gas_left.clone(),
                return_data: return_data.to_vec(),
            },
            Err(err) => CallResult {
                outcome: Outcome::Fail,
                gas_left: U256::zero(),
                return_data: format!("{:?}", err).into(),
            },
        }
    }
}

/// Description of a _create_ action, either a `CREATE` operation or a create
/// transaction.
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable, Serialize)]
#[serde(rename_all = "camelCase")]
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

/// Description of the result of a _create_ action.
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResult {
    /// The outcome of the create
    pub outcome: Outcome,
    /// The created contract address
    pub addr: Address,
    /// The amount of gas left
    pub gas_left: U256,
    /// Output data
    pub return_data: Bytes,
}

impl From<&vmResult<ExecutiveResult>> for CreateResult {
    fn from(r: &vmResult<ExecutiveResult>) -> Self {
        match r {
            Ok(ExecutiveResult {
                gas_left,
                return_data,
                apply_state: true,
                create_address,
            }) => CreateResult {
                outcome: Outcome::Success,
                addr: create_address.expect(
                    "Address should not be none in executive result of create",
                ),
                gas_left: gas_left.clone(),
                return_data: return_data.to_vec(),
            },
            Ok(ExecutiveResult {
                gas_left,
                return_data,
                apply_state: false,
                ..
            }) => CreateResult {
                outcome: Outcome::Reverted,
                addr: Address::zero(),
                gas_left: gas_left.clone(),
                return_data: return_data.to_vec(),
            },
            Err(err) => CreateResult {
                outcome: Outcome::Fail,
                addr: Address::zero(),
                gas_left: U256::zero(),
                return_data: format!("{:?}", err).into(),
            },
        }
    }
}

impl CreateResult {
    /// Returns create result bloom.
    /// The bloom contains only created contract address.
    pub fn bloom(&self) -> Bloom {
        if self.outcome == Outcome::Success {
            BloomInput::Raw(self.addr.as_bytes()).into()
        } else {
            Bloom::default()
        }
    }
}

/// Description of the result of an internal transfer action regarding about
/// CFX.
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalTransferAction {
    /// The source address. If it is zero, then it is an interest mint action.
    pub from: Address,
    /// The destination address. If it is zero, then it is a burnt action.
    pub to: Address,
    /// The amount of CFX
    pub value: U256,
}

impl InternalTransferAction {
    pub fn bloom(&self) -> Bloom {
        let mut bloom = Bloom::default();
        bloom.accrue(BloomInput::Raw(self.from.as_bytes()));
        bloom.accrue(BloomInput::Raw(self.to.as_bytes()));
        bloom
    }
}

/// Description of an action that we trace; will be either a call or a create.
#[derive(Debug, Clone, PartialEq, EnumDiscriminants)]
#[strum_discriminants(name(ActionType))]
pub enum Action {
    /// It's a call action.
    Call(Call),
    /// It's a create action.
    Create(Create),
    /// It's the result of a call action
    CallResult(CallResult),
    /// It's the result of a create action
    CreateResult(CreateResult),
    /// It's an internal transfer action
    InternalTransferAction(InternalTransferAction),
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
            Action::CallResult(ref call_result) => {
                s.append(&2u8);
                s.append(call_result);
            }
            Action::CreateResult(ref create_result) => {
                s.append(&3u8);
                s.append(create_result);
            }
            Action::InternalTransferAction(ref internal_action) => {
                s.append(&4u8);
                s.append(internal_action);
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
            2 => rlp.val_at(1).map(Action::CallResult),
            3 => rlp.val_at(1).map(Action::CreateResult),
            4 => rlp.val_at(1).map(Action::InternalTransferAction),
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
            Action::CallResult(_) => Bloom::default(),
            Action::CreateResult(ref create_result) => create_result.bloom(),
            Action::InternalTransferAction(ref internal_action) => {
                internal_action.bloom()
            }
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

pub struct LocalizedTrace {
    pub action: Action,
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
