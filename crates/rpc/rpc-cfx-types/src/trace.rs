// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::RpcAddress;
use cfx_addr::Network;
use cfx_parity_trace_types::{
    Action as VmAction, ActionType as VmActionType, BlockExecTraces,
    Call as VmCall, CallResult as VmCallResult, Create as VmCreate,
    CreateResult as VmCreateResult, ExecTrace,
    InternalTransferAction as VmInternalTransferAction,
    LocalizedTrace as PrimitiveLocalizedTrace, Outcome,
    SelfDestructAction as VmSelfDestruction, SetAuth as VmSetAuth,
    SetAuthOutcome, TransactionExecTraces,
};
use cfx_rpc_primitives::Bytes;
use cfx_types::{Space, H256, U256, U64};
use cfx_vm_types::{CallType, CreateType};
use primitives::SignedTransaction;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use std::sync::Arc;
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
    SetAuth(SetAuth),
    SelfDestruct(SelfDestructAction),
}

impl Action {
    pub fn try_from(
        action: VmAction, network: Network,
    ) -> Result<Self, String> {
        Ok(match action {
            VmAction::Call(x) => Action::Call(Call::try_from(x, network)?),
            VmAction::Create(x) => {
                Action::Create(Create::try_from(x, network)?)
            }
            VmAction::CallResult(x) => Action::CallResult(x.into()),
            VmAction::CreateResult(x) => {
                Action::CreateResult(CreateResult::try_from(x, network)?)
            }
            VmAction::InternalTransferAction(x) => {
                Action::InternalTransferAction(
                    InternalTransferAction::try_from(x, network)?,
                )
            }
            VmAction::SetAuth(action) => {
                Action::SetAuth(SetAuth::try_from(action, network)?)
            }
            VmAction::SelfDestruct(selfdestruct) => Action::SelfDestruct(
                SelfDestructAction::try_from(selfdestruct, network)?,
            ),
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
            Self::SetAuth => VmActionType::SetAuth,
            Self::SelfDestruct => VmActionType::SelfDestruct,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    pub space: Space,
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
            space: call.space,
            from: RpcAddress::try_from_h160(call.from, network)?,
            to: RpcAddress::try_from_h160(call.to, network)?,
            value: call.value,
            gas: call.gas,
            input: call.input.into(),
            call_type: call.call_type,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallResult {
    pub outcome: Outcome,
    pub gas_left: U256,
    pub return_data: Bytes,
}

impl From<VmCallResult> for CallResult {
    fn from(result: VmCallResult) -> Self {
        Self {
            outcome: result.outcome,
            gas_left: result.gas_left,
            return_data: result.return_data.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    pub space: Space,
    pub from: RpcAddress,
    pub value: U256,
    pub gas: U256,
    pub init: Bytes,
    pub create_type: CreateType,
}

impl Create {
    fn try_from(create: VmCreate, network: Network) -> Result<Self, String> {
        Ok(Self {
            space: create.space,
            from: RpcAddress::try_from_h160(create.from, network)?,
            value: create.value,
            gas: create.gas,
            init: create.init.into(),
            create_type: create.create_type,
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
            return_data: result.return_data.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalTransferAction {
    pub from: RpcAddress,
    pub from_pocket: String,
    pub from_space: String,
    pub to: RpcAddress,
    pub to_pocket: String,
    pub to_space: String,
    pub value: U256,
}

impl InternalTransferAction {
    fn try_from(
        action: VmInternalTransferAction, network: Network,
    ) -> Result<Self, String> {
        Ok(Self {
            from: RpcAddress::try_from_h160(
                action.from.inner_address_or_default(),
                network,
            )?,
            from_pocket: action.from.pocket().into(),
            from_space: action.from.space().into(),
            to: RpcAddress::try_from_h160(
                action.to.inner_address_or_default(),
                network,
            )?,
            to_pocket: action.to.pocket().into(),
            to_space: action.to.space().into(),
            value: action.value,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetAuth {
    pub space: Space,
    /// The address of the impl.
    pub address: RpcAddress,
    pub chain_id: U256,
    pub nonce: U256,
    /// The outcome of the create
    pub outcome: SetAuthOutcome,
    /// The address of the author.
    pub author: Option<RpcAddress>,
}

impl SetAuth {
    fn try_from(action: VmSetAuth, network: Network) -> Result<Self, String> {
        let VmSetAuth {
            space,
            address,
            chain_id,
            nonce,
            outcome,
            author,
        } = action;
        Ok(Self {
            space,
            address: RpcAddress::try_from_h160(address, network)?,
            chain_id,
            nonce,
            outcome,
            author: match author {
                Some(a) => Some(RpcAddress::try_from_h160(a, network)?),
                None => None,
            },
        })
    }
}

/// Represents a _selfdestruct_ action fka `suicide`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfDestructAction {
    // / The space of the contract.
    pub space: Space,
    /// destroyed/suicided address.
    pub address: RpcAddress,
    /// Balance of the contract just before it was destroyed.
    pub balance: U256,
    /// destroyed contract heir.
    pub refund_address: RpcAddress,
}

impl SelfDestructAction {
    fn try_from(
        action: VmSelfDestruction, network: Network,
    ) -> Result<Self, String> {
        let VmSelfDestruction {
            space,
            address,
            balance,
            refund_address,
        } = action;
        Ok(Self {
            space,
            address: RpcAddress::try_from_h160(address, network)?,
            refund_address: RpcAddress::try_from_h160(refund_address, network)?,
            balance,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedBlockTrace {
    pub transaction_traces: Vec<LocalizedTransactionTrace>,
    /// Epoch hash.
    pub epoch_hash: H256,
    /// Epoch number.
    pub epoch_number: U256,
    /// Block hash.
    pub block_hash: H256,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedTransactionTrace {
    pub traces: Vec<LocalizedTrace>,
    /// Transaction position.
    pub transaction_position: U64,
    /// Signed transaction hash.
    pub transaction_hash: H256,
}

#[derive(Debug)]
pub struct LocalizedTrace {
    pub action: Action,
    pub valid: bool,
    /// Epoch hash.
    pub epoch_hash: Option<H256>,
    /// Epoch number.
    pub epoch_number: Option<U256>,
    /// Block hash.
    pub block_hash: Option<H256>,
    /// Transaction position.
    pub transaction_position: Option<U64>,
    /// Signed transaction hash.
    pub transaction_hash: Option<H256>,
}

impl Serialize for LocalizedTrace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut struc = serializer.serialize_struct("LocalizedTrace", 8)?;

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
            Action::SetAuth(ref set_auth) => {
                struc.serialize_field("type", "set_auth")?;
                struc.serialize_field("action", set_auth)?;
            }
            Action::SelfDestruct(ref selfdestruct) => {
                struc.serialize_field("type", "suicide")?;
                struc.serialize_field("action", selfdestruct)?;
            }
        }

        struc.serialize_field("valid", &self.valid)?;

        if self.epoch_hash.is_some() {
            struc.serialize_field("epochHash", &self.epoch_hash.unwrap())?;
        }
        if self.epoch_number.is_some() {
            struc
                .serialize_field("epochNumber", &self.epoch_number.unwrap())?;
        }
        if self.block_hash.is_some() {
            struc.serialize_field("blockHash", &self.block_hash.unwrap())?;
        }
        if self.transaction_position.is_some() {
            struc.serialize_field(
                "transactionPosition",
                &self.transaction_position.unwrap(),
            )?;
        }
        if self.transaction_hash.is_some() {
            struc.serialize_field(
                "transactionHash",
                &self.transaction_hash.unwrap(),
            )?;
        }

        struc.end()
    }
}

impl LocalizedTrace {
    pub fn from(
        trace: PrimitiveLocalizedTrace, network: Network,
    ) -> Result<Self, String> {
        Ok(LocalizedTrace {
            action: Action::try_from(trace.action, network)?,
            epoch_number: Some(trace.epoch_number),
            epoch_hash: Some(trace.epoch_hash),
            block_hash: Some(trace.block_hash),
            transaction_position: Some(trace.transaction_position),
            transaction_hash: Some(trace.transaction_hash),
            valid: trace.valid,
        })
    }
}

impl LocalizedTransactionTrace {
    pub fn from(
        traces: TransactionExecTraces, transaction_hash: H256,
        transaction_position: usize, network: Network,
    ) -> Result<Self, String> {
        let traces: Vec<ExecTrace> = traces.into();

        Ok(LocalizedTransactionTrace {
            traces: traces
                .into_iter()
                .map(|t| {
                    let valid = t.valid;
                    Action::try_from(t.action, network).map(|action| {
                        LocalizedTrace {
                            action,
                            valid,
                            // Set to None because the information has been
                            // included in the outer
                            // structs
                            epoch_hash: None,
                            epoch_number: None,
                            block_hash: None,
                            transaction_position: None,
                            transaction_hash: None,
                        }
                    })
                })
                .collect::<Result<_, _>>()?,
            transaction_position: transaction_position.into(),
            transaction_hash,
        })
    }
}

impl LocalizedBlockTrace {
    pub fn from(
        traces: BlockExecTraces, block_hash: H256, epoch_hash: H256,
        epoch_number: u64, transactions: &Vec<Arc<SignedTransaction>>,
        network: Network,
    ) -> Result<Self, String> {
        let traces: Vec<TransactionExecTraces> = traces.into();
        if traces.len() != transactions.len() {
            cfx_util_macros::bail!("trace and tx hash list length unmatch!");
        }
        let transaction_traces = traces
            .into_iter()
            .enumerate()
            .filter_map(|(tx_pos, t)| match transactions[tx_pos].space() {
                Space::Native => Some((transactions[tx_pos].hash(), t)),
                Space::Ethereum => None,
            })
            .enumerate()
            .map(|(rpc_index, (tx_hash, t))| {
                LocalizedTransactionTrace::from(t, tx_hash, rpc_index, network)
            })
            .collect::<Result<_, _>>()?;

        Ok(LocalizedBlockTrace {
            transaction_traces,
            epoch_hash,
            epoch_number: epoch_number.into(),
            block_hash,
        })
    }
}
