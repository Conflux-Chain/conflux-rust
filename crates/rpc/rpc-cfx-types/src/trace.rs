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
    pub traces: Vec<Trace>,
    /// Transaction position.
    pub transaction_position: U64,
    /// Signed transaction hash.
    pub transaction_hash: H256,
}

#[derive(Debug)]
pub struct Trace {
    pub action: Action,
    pub valid: bool,
}

impl Serialize for Trace {
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
        struc.end()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedTrace {
    #[serde(flatten)]
    pub trace: Trace,
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

impl LocalizedTrace {
    pub fn from(
        trace: PrimitiveLocalizedTrace, network: Network,
    ) -> Result<Self, String> {
        Ok(LocalizedTrace {
            trace: Trace {
                action: Action::try_from(trace.action, network)?,
                valid: trace.valid,
            },
            epoch_number: trace.epoch_number,
            epoch_hash: trace.epoch_hash,
            block_hash: trace.block_hash,
            transaction_position: trace.transaction_position,
            transaction_hash: trace.transaction_hash,
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
                    Action::try_from(t.action, network)
                        .map(|action| Trace { action, valid })
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

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_addr::Network;

    #[test]
    fn test_localized_trace_serialization() {
        let localized_trace = LocalizedTrace {
            trace: Trace {
                action: Action::Call(Call {
                    space: Space::Native,
                    from: RpcAddress::null(Network::Main).unwrap(),
                    to: RpcAddress::null(Network::Main).unwrap(),
                    value: U256::from(1000u64),
                    gas: U256::from(21000u64),
                    input: Bytes::from(vec![0x60, 0x60, 0x60, 0x40]),
                    call_type: CallType::Call,
                }),
                valid: true,
            },
            epoch_hash: Default::default(),
            epoch_number: Default::default(),
            block_hash: Default::default(),
            transaction_position: U64::from(0),
            transaction_hash: Default::default(),
        };

        let serialized =
            serde_json::to_string_pretty(&localized_trace).unwrap();

        let expected = r#"{
  "type": "call",
  "action": {
    "space": "native",
    "from": "CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2",
    "to": "CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2",
    "value": "0x3e8",
    "gas": "0x5208",
    "input": "0x60606040",
    "callType": "call"
  },
  "valid": true,
  "epochHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "epochNumber": "0x0",
  "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "transactionPosition": "0x0",
  "transactionHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}"#;
        assert_eq!(serialized, expected,);
    }
}
