// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_bytes::Bytes;

use crate::AddressPocket;
use cfx_types::{Address, Bloom, BloomInput, Space, U256};
use cfx_vm_types::{ActionParams, CallType, CreateType};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{ser::SerializeStruct, Serialize, Serializer};
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
