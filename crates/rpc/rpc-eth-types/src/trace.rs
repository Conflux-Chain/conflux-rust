use cfx_parameters::internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS;
use cfx_parity_trace_types::{
    Action as VmAction, Outcome, SetAuth as VmSetAuth,
    SetAuthOutcome as VmSetAuthOutcome,
};
use cfx_rpc_cfx_types::{
    trace::{Action as CfxRpcAction, LocalizedTrace as CfxLocalizedTrace},
    RpcAddress,
};
use cfx_rpc_primitives::Bytes;
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use cfx_util_macros::bail;
use cfx_vm_types::{CallType, CreateType};
use jsonrpc_core::Error as JsonRpcError;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use std::{collections::HashMap, convert::TryFrom, fmt};

/// Create response
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    /// Sender
    from: Address,
    /// Value
    value: U256,
    /// Gas
    gas: U256,
    /// Initialization code
    init: Bytes,
    /// The create type `CREATE` or `CREATE2`
    create_type: CreateType,
}

/// Call response
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    /// Sender
    from: Address,
    /// Recipient
    to: Address,
    /// Transferred Value
    value: U256,
    /// Gas
    gas: U256,
    /// Input data
    input: Bytes,
    /// The type of the call.
    call_type: CallType,
}

/// Represents a _selfdestruct_ action fka `suicide`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfDestructAction {
    /// destroyed/suicided address.
    pub address: Address,
    /// Balance of the contract just before it was destroyed.
    pub balance: U256,
    /// destroyed contract heir.
    pub refund_address: Address,
}

/// Action
#[derive(Debug, Clone)]
pub enum Action {
    /// Call
    Call(Call),
    /// Create
    Create(Create),
    /// SelfDestruct
    SelfDestruct(SelfDestructAction),
    /* TODO: Support Reward */
}

impl Action {
    pub fn gas(&self) -> Option<U256> {
        match self {
            Action::Call(ref call) => Some(call.gas),
            Action::Create(ref create) => Some(create.gas),
            Action::SelfDestruct(_) => None,
        }
    }
}

impl TryFrom<VmAction> for Action {
    type Error = String;

    fn try_from(cfx_action: VmAction) -> Result<Self, String> {
        match cfx_action {
            VmAction::Call(call) => Ok(Action::Call(Call {
                from: call.from,
                to: call.to,
                value: call.value,
                gas: call.gas,
                input: call.input.into(),
                call_type: call.call_type,
            })),
            VmAction::Create(create) => Ok(Action::Create(Create {
                from: create.from,
                value: create.value,
                gas: create.gas,
                init: create.init.into(),
                create_type: create.create_type,
            })),
            VmAction::SelfDestruct(selfdestruct) => {
                Ok(Action::SelfDestruct(SelfDestructAction {
                    address: selfdestruct.address,
                    balance: selfdestruct.balance,
                    refund_address: selfdestruct.refund_address,
                }))
            }
            action => {
                bail!("unsupported action in eth space: {:?}", action);
            }
        }
    }
}

/// Call Result
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CallResult {
    /// Gas used
    gas_used: U256,
    /// Output bytes
    output: Bytes,
}

/// Craete Result
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateResult {
    /// Gas used
    gas_used: U256,
    /// Code
    code: Bytes,
    /// Assigned address
    address: Address,
}

/// Response
#[derive(Debug, Clone)]
pub enum ActionResult {
    /// Call
    Call(CallResult),
    /// Create
    Create(CreateResult),
    /// None
    None,
}

/// Trace
#[derive(Debug, Clone)]
pub struct LocalizedTrace {
    /// Action
    pub action: Action,
    /// Result
    pub result: ActionResult,
    /// The error message if the transaction failed.
    pub error: Option<String>,
    /// Trace address
    pub trace_address: Vec<usize>,
    /// Subtraces
    pub subtraces: usize,
    /// Transaction position
    pub transaction_position: usize,
    /// Transaction hash
    pub transaction_hash: H256,
    /// Block Number
    pub block_number: u64,
    /// Block Hash
    pub block_hash: H256,
    /// Valid
    pub valid: bool,
}

impl Serialize for LocalizedTrace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut struc = serializer.serialize_struct("LocalizedTrace", 9)?;
        match self.action {
            Action::Call(ref call) => {
                struc.serialize_field("type", "call")?;
                struc.serialize_field("action", call)?;
            }
            Action::Create(ref create) => {
                struc.serialize_field("type", "create")?;
                struc.serialize_field("action", create)?;
            }
            Action::SelfDestruct(ref selfdestruct) => {
                struc.serialize_field("type", "suicide")?;
                struc.serialize_field("action", selfdestruct)?;
            }
        }

        match self.result {
            ActionResult::Call(ref call) => {
                struc.serialize_field("result", call)?
            }
            ActionResult::Create(ref create) => {
                struc.serialize_field("result", create)?
            }
            ActionResult::None => {
                struc.serialize_field("result", &None as &Option<u8>)?
            }
        }

        if let Some(error) = &self.error {
            struc.serialize_field("error", error)?;
        }

        struc.serialize_field("traceAddress", &self.trace_address)?;
        struc.serialize_field("subtraces", &self.subtraces)?;
        struc.serialize_field(
            "transactionPosition",
            &self.transaction_position,
        )?;
        struc.serialize_field("transactionHash", &self.transaction_hash)?;
        struc.serialize_field("blockNumber", &self.block_number)?;
        struc.serialize_field("blockHash", &self.block_hash)?;
        struc.serialize_field("valid", &self.valid)?;

        struc.end()
    }
}

impl LocalizedTrace {
    pub fn set_result(
        &mut self, result: Option<VmAction>,
    ) -> Result<(), JsonRpcError> {
        if !matches!(self.result, ActionResult::None) {
            // One action matches exactly one result.
            bail!(JsonRpcError::internal_error());
        }
        if result.is_none() {
            // If the result is None, it means the action has no result.
            self.result = ActionResult::None;
            return Ok(());
        }
        let result = result.unwrap();
        match result {
            VmAction::CallResult(call_result) => {
                if !matches!(self.action, Action::Call(_)) {
                    bail!(JsonRpcError::internal_error());
                }
                let gas =
                    self.action.gas().expect("call action should have gas");
                let gas_used = gas - call_result.gas_left;
                self.result = ActionResult::Call(CallResult {
                    gas_used,
                    output: call_result.return_data.clone().into(),
                });
                match call_result.outcome {
                    Outcome::Reverted => {
                        self.error = Some(TraceError::Reverted.to_string());
                    }
                    Outcome::Fail => {
                        self.error = Some(
                            TraceError::Error(call_result.return_data.into())
                                .to_string(),
                        );
                    }
                    _ => {}
                }
            }
            VmAction::CreateResult(create_result) => {
                if !matches!(self.action, Action::Create(_)) {
                    bail!(JsonRpcError::internal_error());
                }
                // FIXME(lpl): Check if `return_data` is `code`.
                let gas =
                    self.action.gas().expect("call action should have gas");
                let gas_used = gas - create_result.gas_left;
                self.result = ActionResult::Create(CreateResult {
                    gas_used,
                    code: create_result.return_data.clone().into(),
                    address: create_result.addr,
                });
                match create_result.outcome {
                    Outcome::Reverted => {
                        self.error = Some(TraceError::Reverted.to_string());
                    }
                    Outcome::Fail => {
                        self.error = Some(
                            TraceError::Error(create_result.return_data.into())
                                .to_string(),
                        );
                    }
                    _ => {}
                }
            }
            _ => bail!(JsonRpcError::internal_error()),
        }
        Ok(())
    }
}

/// Trace
#[derive(Debug)]
pub struct Trace {
    /// Trace address
    trace_address: Vec<usize>,
    /// Subtraces
    subtraces: usize,
    /// Action
    action: Action,
    /// Result
    result: ActionResult,
    /// Error
    error: Option<String>,
}

impl Serialize for Trace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut struc = serializer.serialize_struct("Trace", 4)?;
        match self.action {
            Action::Call(ref call) => {
                struc.serialize_field("type", "call")?;
                struc.serialize_field("action", call)?;
            }
            Action::Create(ref create) => {
                struc.serialize_field("type", "create")?;
                struc.serialize_field("action", create)?;
            }
            Action::SelfDestruct(ref selfdestruct) => {
                struc.serialize_field("type", "suicide")?;
                struc.serialize_field("action", selfdestruct)?;
            }
        }

        match self.result {
            ActionResult::Call(ref call) => {
                struc.serialize_field("result", call)?
            }
            ActionResult::Create(ref create) => {
                struc.serialize_field("result", create)?
            }
            ActionResult::None => {
                struc.serialize_field("result", &None as &Option<u8>)?
            }
        }

        if let Some(error) = &self.error {
            struc.serialize_field("error", error)?;
        }

        struc.serialize_field("traceAddress", &self.trace_address)?;
        struc.serialize_field("subtraces", &self.subtraces)?;

        struc.end()
    }
}

#[derive(Debug, Clone)]
pub enum TraceError {
    /// Execution has been reverted with REVERT instruction.
    Reverted,
    /// Other errors with error message encoded.
    Error(Bytes),
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match &self {
            TraceError::Reverted => "Reverted",
            // error bytes are constructed from `format`, so this should
            // succeed.
            TraceError::Error(b) => {
                std::str::from_utf8(&b.0).map_err(|_| fmt::Error)?
            }
        };
        message.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetAuth {
    /// The address of the impl.
    pub address: Address,
    pub chain_id: U256,
    pub nonce: U256,
    pub author: Option<Address>,
}

/// Trace
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedSetAuthTrace {
    /// Action
    pub action: SetAuth,
    /// Result
    pub result: VmSetAuthOutcome,
    /// Transaction position
    pub transaction_position: usize,
    /// Transaction hash
    pub transaction_hash: H256,
    /// Block Number
    pub block_number: u64,
    /// Block Hash
    pub block_hash: H256,
}

impl LocalizedSetAuthTrace {
    pub fn new(
        vm_action: &VmSetAuth, transaction_position: usize,
        transaction_hash: H256, block_number: u64, block_hash: H256,
    ) -> Self {
        let action = SetAuth {
            address: vm_action.address,
            chain_id: vm_action.chain_id,
            nonce: vm_action.nonce,
            author: vm_action.author,
        };
        Self {
            action,
            result: vm_action.outcome,
            transaction_position,
            transaction_hash,
            block_number,
            block_hash,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochTrace {
    cfx_traces: Vec<CfxLocalizedTrace>,
    eth_traces: Vec<LocalizedTrace>,
    mirror_address_map: HashMap<Address, RpcAddress>,
}

impl EpochTrace {
    pub fn new(
        cfx_traces: Vec<CfxLocalizedTrace>, eth_traces: Vec<LocalizedTrace>,
    ) -> Self {
        let mut mirror_address_map = HashMap::new();
        for t in &cfx_traces {
            if let CfxRpcAction::Call(action) = &t.trace.action {
                if action.to.hex_address == CROSS_SPACE_CONTRACT_ADDRESS {
                    mirror_address_map.insert(
                        action.from.hex_address.evm_map().address,
                        action.from.clone(),
                    );
                }
            }
        }
        Self {
            cfx_traces,
            eth_traces,
            mirror_address_map,
        }
    }
}
