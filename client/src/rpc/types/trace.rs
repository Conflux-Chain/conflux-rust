// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::RpcAddress;
use cfx_addr::Network;
use cfx_bytes::Bytes;
use cfx_types::U256;
use cfxcore::{
    trace::trace::{
        Action as VmAction, ActionType as VmActionType, BlockExecTraces,
        Call as VmCall, CallResult, Create as VmCreate,
        CreateResult as VmCreateResult, ExecTrace,
        InternalTransferAction as VmInternalTransferAction, Outcome,
        TransactionExecTraces,
    },
    vm::CallType,
};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use strum_macros::EnumDiscriminants;

#[derive(Debug, Clone, PartialEq, EnumDiscriminants)]
#[strum_discriminants(name(ActionType))]
#[strum_discriminants(derive(Hash, Serialize, Deserialize))]
#[strum_discriminants(serde(rename_all = "snake_case", deny_unknown_fields))]
pub enum Action {
    Call(Call),
    Create(Create),
    CallResult(CallResult),
    CreateResult(CreateResult),
    InternalTransferAction(InternalTransferAction),
}

impl Action {
    fn try_from(action: VmAction, network: Network) -> Result<Self, String> {
        Ok(match action {
            VmAction::Call(x) => Action::Call(Call::try_from(x, network)?),
            VmAction::Create(x) => {
                Action::Create(Create::try_from(x, network)?)
            }
            VmAction::CallResult(x) => Action::CallResult(x),
            VmAction::CreateResult(x) => {
                Action::CreateResult(CreateResult::try_from(x, network)?)
            }
            VmAction::InternalTransferAction(x) => {
                Action::InternalTransferAction(
                    InternalTransferAction::try_from(x, network)?,
                )
            }
        })
    }
}

impl Into<VmActionType> for ActionType {
    fn into(self) -> VmActionType {
        match self {
            Self::Call => VmActionType::Call,
            Self::Create => VmActionType::Create,
            Self::CallResult => VmActionType::CallResult,
            Self::CreateResult => VmActionType::CreateResult,
            Self::InternalTransferAction => {
                VmActionType::InternalTransferAction
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    pub from: RpcAddress,
    pub to: RpcAddress,
    pub value: U256,
    pub gas: U256,
    pub input: Bytes,
    pub call_type: CallType,
}

impl Call {
    fn try_from(call: VmCall, network: Network) -> Result<Self, String> {
        Ok(Self {
            from: RpcAddress::try_from_h160(call.from, network)?,
            to: RpcAddress::try_from_h160(call.to, network)?,
            value: call.value,
            gas: call.gas,
            input: call.input,
            call_type: call.call_type,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    pub from: RpcAddress,
    pub value: U256,
    pub gas: U256,
    pub init: Bytes,
}

impl Create {
    fn try_from(create: VmCreate, network: Network) -> Result<Self, String> {
        Ok(Self {
            from: RpcAddress::try_from_h160(create.from, network)?,
            value: create.value,
            gas: create.gas,
            init: create.init,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResult {
    pub outcome: Outcome,
    pub addr: RpcAddress,
    pub gas_left: U256,
    pub return_data: Bytes,
}

impl CreateResult {
    fn try_from(
        result: VmCreateResult, network: Network,
    ) -> Result<Self, String> {
        Ok(Self {
            outcome: result.outcome,
            addr: RpcAddress::try_from_h160(result.addr, network)?,
            gas_left: result.gas_left,
            return_data: result.return_data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalTransferAction {
    pub from: RpcAddress,
    pub to: RpcAddress,
    pub value: U256,
}

impl InternalTransferAction {
    fn try_from(
        action: VmInternalTransferAction, network: Network,
    ) -> Result<Self, String> {
        Ok(Self {
            from: RpcAddress::try_from_h160(action.from, network)?,
            to: RpcAddress::try_from_h160(action.to, network)?,
            value: action.value,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedBlockTrace {
    pub transaction_traces: Vec<LocalizedTransactionTrace>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedTransactionTrace {
    pub traces: Vec<LocalizedTrace>,
}

#[derive(Debug)]
pub struct LocalizedTrace {
    pub action: Action,
}

impl Serialize for LocalizedTrace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut struc = serializer.serialize_struct("LocalizedTrace", 2)?;

        match self.action {
            Action::Call(ref call) => {
                struc.serialize_field("type", "call")?;
                struc.serialize_field("action", call)?;
            }
            Action::Create(ref create) => {
                struc.serialize_field("type", "create")?;
                struc.serialize_field("action", create)?;
            }
            Action::CallResult(ref call_result) => {
                struc.serialize_field("type", "call_result")?;
                struc.serialize_field("action", call_result)?;
            }
            Action::CreateResult(ref create_result) => {
                struc.serialize_field("type", "create_result")?;
                struc.serialize_field("action", create_result)?;
            }
            Action::InternalTransferAction(ref internal_action) => {
                struc.serialize_field("type", "internal_transfer_action")?;
                struc.serialize_field("action", internal_action)?;
            }
        }

        struc.end()
    }
}

impl LocalizedTrace {
    pub fn from(trace: ExecTrace, network: Network) -> Result<Self, String> {
        Ok(LocalizedTrace {
            action: Action::try_from(trace.action, network)?,
        })
    }
}

impl LocalizedTransactionTrace {
    pub fn from(
        traces: TransactionExecTraces, network: Network,
    ) -> Result<Self, String> {
        let traces: Vec<ExecTrace> = traces.into();

        Ok(LocalizedTransactionTrace {
            traces: traces
                .into_iter()
                .map(|t| LocalizedTrace::from(t, network))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl LocalizedBlockTrace {
    pub fn from(
        traces: BlockExecTraces, network: Network,
    ) -> Result<Self, String> {
        let traces: Vec<TransactionExecTraces> = traces.into();

        Ok(LocalizedBlockTrace {
            transaction_traces: traces
                .into_iter()
                .map(|t| LocalizedTransactionTrace::from(t, network))
                .collect::<Result<_, _>>()?,
        })
    }
}
