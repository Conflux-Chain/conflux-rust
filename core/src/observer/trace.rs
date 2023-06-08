// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::AddressPocket;
use crate::{
    bytes::Bytes,
    executive::{
        internal_contract::{is_call_create_sig, is_withdraw_sig},
        ExecutiveResult,
    },
    observer::trace_filter::TraceFilter,
    vm::{ActionParams, CallType, CreateType, Result as vmResult},
};
use cfx_internal_common::{DatabaseDecodable, DatabaseEncodable};
use cfx_parameters::internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS;
use cfx_types::{
    Address, AddressWithSpace, Bloom, BloomInput, Space, H256, U256, U64,
};
use malloc_size_of_derive::MallocSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use solidity_abi::ABIEncodable;
use strum_macros::EnumDiscriminants;

/// Description of a _call_ action, either a `CALL` operation or a message
/// transaction.
#[derive(Debug, Clone, PartialEq, RlpEncodable, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    /// The space
    pub space: Space,
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

impl Decodable for Call {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.item_count()? {
            6 => Ok(Call {
                space: Space::Native,
                from: rlp.val_at(0)?,
                to: rlp.val_at(1)?,
                value: rlp.val_at(2)?,
                gas: rlp.val_at(3)?,
                input: rlp.val_at(4)?,
                call_type: rlp.val_at(5)?,
            }),
            7 => Ok(Call {
                space: rlp.val_at(0)?,
                from: rlp.val_at(1)?,
                to: rlp.val_at(2)?,
                value: rlp.val_at(3)?,
                gas: rlp.val_at(4)?,
                input: rlp.val_at(5)?,
                call_type: rlp.val_at(6)?,
            }),
            _ => Err(DecoderError::RlpInvalidLength),
        }
    }
}

impl From<ActionParams> for Call {
    fn from(p: ActionParams) -> Self {
        match p.call_type {
            CallType::DelegateCall | CallType::CallCode => Call {
                space: p.space,
                from: p.address,
                to: p.code_address,
                value: p.value.value(),
                gas: p.gas,
                input: p.data.unwrap_or_else(Vec::new),
                call_type: p.call_type,
            },
            _ => Call {
                space: p.space,
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
#[derive(Debug, Clone, PartialEq, RlpEncodable, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    /// Space
    pub space: Space,
    /// The address of the creator.
    pub from: Address,
    /// The value with which the new account is endowed.
    pub value: U256,
    /// The gas available for the creation init code.
    pub gas: U256,
    /// The init code.
    pub init: Bytes,
    /// The create type `CREATE` or `CREATE2`
    pub create_type: CreateType,
}

impl Decodable for Create {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.item_count()? {
            5 => Ok(Create {
                space: Space::Native,
                from: rlp.val_at(0)?,
                value: rlp.val_at(1)?,
                gas: rlp.val_at(2)?,
                init: rlp.val_at(3)?,
                create_type: rlp.val_at(4)?,
            }),
            6 => Ok(Create {
                space: rlp.val_at(0)?,
                from: rlp.val_at(1)?,
                value: rlp.val_at(2)?,
                gas: rlp.val_at(3)?,
                init: rlp.val_at(4)?,
                create_type: rlp.val_at(5)?,
            }),
            _ => Err(DecoderError::RlpInvalidLength),
        }
    }
}

impl From<ActionParams> for Create {
    fn from(p: ActionParams) -> Self {
        Create {
            space: p.space,
            from: p.sender,
            value: p.value.value(),
            gas: p.gas,
            init: p.code.map_or_else(Vec::new, |c| (*c).clone()),
            create_type: p.create_type,
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
                ..
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
#[derive(Debug, Clone, PartialEq, RlpEncodable, RlpDecodable)]
pub struct InternalTransferAction {
    /// The source address. If it is zero, then it is an interest mint action.
    pub from: AddressPocket,
    /// The destination address. If it is zero, then it is a burnt action.
    pub to: AddressPocket,
    /// The amount of CFX
    pub value: U256,
}

impl Serialize for InternalTransferAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut s = serializer.serialize_struct("InternalTransferAction", 5)?;
        s.serialize_field("from", &self.from.inner_address_or_default())?;
        s.serialize_field("fromPocket", &*self.from.pocket())?;
        s.serialize_field("fromSpace", &*self.from.space())?;
        s.serialize_field("to", &self.to.inner_address_or_default())?;
        s.serialize_field("toPocket", &*self.to.pocket())?;
        s.serialize_field("toSpace", &*self.to.space())?;
        s.serialize_field("value", &self.value)?;
        s.end()
    }
}

impl InternalTransferAction {
    pub fn bloom(&self) -> Bloom {
        let mut bloom = Bloom::default();
        bloom.accrue(BloomInput::Raw(
            self.from.inner_address_or_default().as_ref(),
        ));
        bloom.accrue(BloomInput::Raw(
            self.to.inner_address_or_default().as_ref(),
        ));
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

    /// Return pairs of (action, result, subtrace_len).
    /// Return `Err` if actions and results do not match.
    ///
    /// `from_address`, `to_address`, `action_types`, and `space` in `filter`
    /// are applied.
    pub fn filter_trace_pairs(
        self, filter: &TraceFilter,
    ) -> Result<Vec<(ExecTrace, ExecTrace, usize)>, String> {
        let mut trace_pairs: Vec<(ExecTrace, Option<ExecTrace>, usize)> =
            Vec::new();
        let mut stack_index = Vec::new();
        let mut sublen_stack = Vec::new();
        for trace in self.0 {
            match &trace.action {
                Action::Call(call) => {
                    if call.space == filter.space {
                        if let Some(parent_subtraces) = sublen_stack.last_mut()
                        {
                            *parent_subtraces += 1;
                        }
                    }
                    sublen_stack.push(0);
                    if call.space == filter.space
                        && filter.from_address.matches(&call.from)
                        && filter.to_address.matches(&call.to)
                        && filter.action_types.matches(&ActionType::Call)
                    {
                        stack_index.push(Some(trace_pairs.len()));
                        trace_pairs.push((trace, None, 0));
                    } else {
                        // The corresponding result should be ignored.
                        stack_index.push(None);
                    }
                }
                Action::Create(create) => {
                    if create.space == filter.space {
                        if let Some(parent_subtraces) = sublen_stack.last_mut()
                        {
                            *parent_subtraces += 1;
                        }
                    }
                    sublen_stack.push(0);
                    if create.space == filter.space
                        && filter.from_address.matches(&create.from)
                        // TODO(lpl): openethereum uses `to_address` to filter the contract address.
                        && filter.action_types.matches(&ActionType::Create)
                    {
                        stack_index.push(Some(trace_pairs.len()));
                        trace_pairs.push((trace, None, 0));
                    } else {
                        // The corresponding result should be ignored.
                        stack_index.push(None);
                    }
                }
                Action::CallResult(_) | Action::CreateResult(_) => {
                    if let Some(index) = stack_index
                        .pop()
                        .ok_or("result left unmatched!".to_string())?
                    {
                        // Since we know that traces should be paired correctly,
                        // we do not check if the type
                        // is correct here.
                        trace_pairs[index].1 = Some(trace);
                        let subtraces =
                            sublen_stack.pop().expect("stack_index matches");
                        trace_pairs[index].2 = subtraces;
                    } else {
                        sublen_stack.pop();
                    }
                }
                Action::InternalTransferAction(_) => {}
            }
        }
        if !stack_index.is_empty() {
            bail!("actions left unmatched!".to_string());
        }
        Ok(trace_pairs
            .into_iter()
            .map(|pair| (pair.0, pair.1.expect("all actions matched"), pair.2))
            .collect())
    }

    /// Return filtered Native actions with their orders kept.
    ///
    /// `from_address`, `to_address`, `action_types`, and `space` in `filter`
    /// are applied.
    pub fn filter_traces(
        self, filter: &TraceFilter,
    ) -> Result<Vec<ExecTrace>, String> {
        let mut traces = Vec::new();
        let mut stack = Vec::new();
        for trace in self.0 {
            match &trace.action {
                Action::Call(call) => {
                    if call.space == filter.space
                        && filter.from_address.matches(&call.from)
                        && filter.to_address.matches(&call.to)
                        && filter.action_types.matches(&ActionType::Call)
                    {
                        stack.push(true);
                        traces.push(trace);
                    } else {
                        // The corresponding result should be ignored.
                        stack.push(false);
                    }
                }
                Action::Create(create) => {
                    if create.space == filter.space
                        && filter.from_address.matches(&create.from)
                        // TODO(lpl): openethereum uses `to_address` to filter the contract address.
                        && filter.action_types.matches(&ActionType::Create)
                    {
                        stack.push(true);
                        traces.push(trace);
                    } else {
                        // The corresponding result should be ignored.
                        stack.push(false);
                    }
                }
                Action::CallResult(_) | Action::CreateResult(_) => {
                    if stack
                        .pop()
                        .ok_or("result left unmatched!".to_string())?
                    {
                        // Since we know that traces should be paired correctly,
                        // we do not check if the type
                        // is correct here.
                        traces.push(trace);
                    }
                }
                Action::InternalTransferAction(_) => {
                    traces.push(trace);
                }
            }
        }
        if !stack.is_empty() {
            bail!("actions left unmatched!".to_string());
        }
        Ok(traces)
    }

    pub fn filter_space(self, space: Space) -> Self {
        // `unwrap` here should always succeed.
        // `vec![]` is just added in case.
        Self(
            self.filter_traces(&TraceFilter::space_filter(space))
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

pub fn recover_phantom_trace_for_withdraw(
    mut tx_traces: impl Iterator<Item = ExecTrace>,
) -> Result<Vec<TransactionExecTraces>, String> {
    let trace = match tx_traces.next() {
        Some(t) => t,
        None => {
            error!("Unable to recover phantom trace: no more traces (expected withdraw)");
            return Err("Unable to recover phantom trace: no more traces (expected withdraw)".into());
        }
    };

    match trace.action {
        Action::InternalTransferAction(InternalTransferAction {
            from:
                AddressPocket::Balance(AddressWithSpace {
                    address: from,
                    space: Space::Ethereum,
                }),
            to:
                AddressPocket::Balance(AddressWithSpace {
                    address: _,
                    space: Space::Native,
                }),
            value,
        }) => {
            return Ok(vec![TransactionExecTraces(vec![
                ExecTrace {
                    action: Action::Call(Call {
                        space: Space::Ethereum,
                        from,
                        to: Address::zero(),
                        value,
                        gas: 0.into(),
                        input: Default::default(),
                        call_type: CallType::Call,
                    }),
                    valid: true,
                },
                ExecTrace {
                    action: Action::CallResult(CallResult {
                        outcome: Outcome::Success,
                        gas_left: 0.into(),
                        return_data: Default::default(),
                    }),
                    valid: true,
                },
            ])]);
        }

        _ => {
            error!("Unable to recover phantom trace: unexpected trace type while processing withdraw: {:?}", trace);
            return Err("Unable to recover phantom trace: unexpected trace type while processing withdraw".into());
        }
    }
}

pub fn recover_phantom_trace_for_call(
    tx_traces: &mut impl Iterator<Item = ExecTrace>, original_tx_hash: H256,
    cross_space_nonce: u32,
) -> Result<Vec<TransactionExecTraces>, String>
{
    let mut traces = vec![];

    let trace = match tx_traces.next() {
        Some(t) => t,
        None => {
            error!("Unable to recover phantom trace: no more traces (expected balance transfer) hash={:?}, nonce={:?}", original_tx_hash, cross_space_nonce);
            return Err("Unable to recover phantom trace: no more traces (expected balance transfer)".into());
        }
    };

    match trace.action {
        Action::InternalTransferAction(InternalTransferAction {
            from: _,
            to:
                AddressPocket::Balance(AddressWithSpace {
                    address,
                    space: Space::Ethereum,
                }),
            value,
        }) => {
            let input =
                (original_tx_hash, U256::from(cross_space_nonce)).abi_encode();

            traces.push(TransactionExecTraces(vec![
                ExecTrace {
                    action: Action::Call(Call {
                        space: Space::Ethereum,
                        from: Address::zero(),
                        to: address,
                        value,
                        gas: 0.into(),
                        input,
                        call_type: CallType::Call,
                    }),
                    valid: true,
                },
                ExecTrace {
                    action: Action::CallResult(CallResult {
                        outcome: Outcome::Success,
                        gas_left: 0.into(),
                        return_data: Default::default(),
                    }),
                    valid: true,
                },
            ]));
        }

        _ => {
            error!("Unable to recover phantom trace: unexpected trace type while processing call (hash={:?}, nonce={:?}): {:?}", original_tx_hash, cross_space_nonce, trace);
            return Err("Unable to recover phantom trace: unexpected trace type while processing call".into());
        }
    }

    let mut stack_depth = 0;
    let mut phantom_traces = vec![];

    loop {
        let mut trace = match tx_traces.next() {
            Some(t) => t,
            None => {
                error!("Unable to recover phantom trace: no more traces (expected eSpace trace entry) hash={:?}, nonce={:?}", original_tx_hash, cross_space_nonce);
                return Err("Unable to recover phantom trace: no more traces (expected eSpace trace entry)".into());
            }
        };

        // phantom traces have 0 gas
        match trace.action {
            Action::Call(Call { ref mut gas, .. }) => {
                *gas = 0.into();
            }
            Action::Create(Create { ref mut gas, .. }) => {
                *gas = 0.into();
            }
            Action::CallResult(CallResult {
                ref mut gas_left, ..
            }) => {
                *gas_left = 0.into();
            }
            Action::CreateResult(CreateResult {
                ref mut gas_left, ..
            }) => {
                *gas_left = 0.into();
            }
            Action::InternalTransferAction(InternalTransferAction {
                ..
            }) => {}
        }

        phantom_traces.push(trace);

        match phantom_traces.last().as_ref().unwrap().action {
            Action::Call(_) | Action::Create(_) => {
                stack_depth += 1;
            }
            Action::CallResult(_) | Action::CreateResult(_) => {
                stack_depth -= 1;

                if stack_depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }

    traces.push(TransactionExecTraces(phantom_traces));
    Ok(traces)
}

pub fn recover_phantom_traces(
    tx_traces: TransactionExecTraces, original_tx_hash: H256,
) -> Result<Vec<TransactionExecTraces>, String> {
    let mut traces: Vec<TransactionExecTraces> = vec![];
    let mut traces_iter = tx_traces.0.into_iter();
    let mut cross_space_nonce = 0u32;

    loop {
        let trace = match traces_iter.next() {
            Some(t) => t,
            None => break,
        };

        match trace.action {
            Action::Call(Call {
                space: Space::Native,
                to,
                call_type: CallType::Call,
                input,
                ..
            }) if to == CROSS_SPACE_CONTRACT_ADDRESS
                && trace.valid
                && is_call_create_sig(&input[0..4]) =>
            {
                let phantom_traces = recover_phantom_trace_for_call(
                    &mut traces_iter,
                    original_tx_hash,
                    cross_space_nonce,
                )?;

                traces.extend(phantom_traces);
                cross_space_nonce += 1;
            }
            Action::Call(Call {
                space: Space::Native,
                to,
                call_type: CallType::Call,
                input,
                ..
            }) if to == CROSS_SPACE_CONTRACT_ADDRESS
                && trace.valid
                && is_withdraw_sig(&input[0..4]) =>
            {
                let phantom_traces =
                    recover_phantom_trace_for_withdraw(&mut traces_iter)?;

                traces.extend(phantom_traces);
            }
            _ => {}
        }
    }

    Ok(traces)
}

#[cfg(test)]
mod tests {
    use crate::{
        observer::trace::{
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
                space: Default::default(),
                from: "8dda5e016e674683241bf671cced51e7239ea2bc"
                    .parse()
                    .unwrap(),
                to: "37a5e19cc2d49f244805d5c268c0e6f321965ab9".parse().unwrap(),
                value: "3627e8f712373c0000".parse().unwrap(),
                gas: 0x03e8.into(),
                input: vec![],
                call_type: CallType::Call,
            }),
            valid: true,
        };

        let flat_trace1 = ExecTrace {
            action: Action::Call(Call {
                space: Default::default(),
                from: "3d0768da09ce77d25e2d998e6a7b6ed4b9116c2d"
                    .parse()
                    .unwrap(),
                to: "412fda7643b37d436cb40628f6dbbb80a07267ed".parse().unwrap(),
                value: 0.into(),
                gas: 0x010c78.into(),
                input: vec![0x41, 0xc0, 0xe1, 0xb5],
                call_type: CallType::Call,
            }),
            valid: true,
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
