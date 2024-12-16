use crate::trace::{
    Action as RpcCfxAction, LocalizedTrace as RpcCfxLocalizedTrace,
};
use cfx_parity_trace_types::Outcome;
use cfx_rpc_primitives::Bytes;
use cfx_types::{H160, H256, U256};
use cfx_util_macros::bail;
use cfx_vm_types::{CallType as CfxCallType, CreateType as CfxCreateType};
use jsonrpc_core::Error as JsonRpcError;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::{
    convert::{TryFrom, TryInto},
    fmt,
};

/// Create response
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    /// Sender
    from: H160,
    /// Value
    value: U256,
    /// Gas
    gas: U256,
    /// Initialization code
    init: Bytes,
    /// The create type `CREATE` or `CREATE2`
    create_type: CreateType,
}

/// The type of the create-like instruction.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum CreateType {
    /// Not a create
    None,
    /// CREATE
    CREATE,
    /// CREATE2
    CREATE2,
}

impl From<CfxCreateType> for CreateType {
    fn from(cfx_create_type: CfxCreateType) -> Self {
        match cfx_create_type {
            CfxCreateType::None => CreateType::None,
            CfxCreateType::CREATE => CreateType::CREATE,
            CfxCreateType::CREATE2 => CreateType::CREATE2,
        }
    }
}

/// Call type.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum CallType {
    /// None
    None,
    /// Call
    Call,
    /// Call code
    CallCode,
    /// Delegate call
    DelegateCall,
    /// Static call
    StaticCall,
}

impl From<CfxCallType> for CallType {
    fn from(cfx_call_type: CfxCallType) -> Self {
        match cfx_call_type {
            CfxCallType::None => CallType::None,
            CfxCallType::Call => CallType::Call,
            CfxCallType::CallCode => CallType::CallCode,
            CfxCallType::DelegateCall => CallType::DelegateCall,
            CfxCallType::StaticCall => CallType::StaticCall,
        }
    }
}

/// Call response
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    /// Sender
    from: H160,
    /// Recipient
    to: H160,
    /// Transfered Value
    value: U256,
    /// Gas
    gas: U256,
    /// Input data
    input: Bytes,
    /// The type of the call.
    call_type: CallType,
}

/// Action
#[derive(Debug, Clone)]
pub enum Action {
    /// Call
    Call(Call),
    /// Create
    Create(Create),
    /* TODO: Support Suicide
     * TODO: Support Reward */
}

impl TryFrom<RpcCfxAction> for Action {
    type Error = String;

    fn try_from(cfx_action: RpcCfxAction) -> Result<Self, String> {
        match cfx_action {
            RpcCfxAction::Call(call) => Ok(Action::Call(Call {
                from: call.from.hex_address,
                to: call.to.hex_address,
                value: call.value,
                gas: call.gas,
                input: call.input,
                call_type: call.call_type.into(),
            })),
            RpcCfxAction::Create(create) => Ok(Action::Create(Create {
                from: create.from.hex_address,
                value: create.value,
                gas: create.gas,
                init: create.init,
                create_type: create.create_type.into(),
            })),
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
    address: H160,
}

/// Response
#[derive(Debug, Clone)]
pub enum Res {
    /// Call
    Call(CallResult),
    /// Create
    Create(CreateResult),
    /// Call failure
    FailedCall(TraceError),
    /// Creation failure
    FailedCreate(TraceError),
    /// None
    None,
}

/// Trace
#[derive(Debug, Clone)]
pub struct LocalizedTrace {
    /// Action
    pub action: Action,
    /// Result
    pub result: Res,
    /// Trace address
    pub trace_address: Vec<usize>,
    /// Subtraces
    pub subtraces: usize,
    /// Transaction position
    pub transaction_position: Option<usize>,
    /// Transaction hash
    pub transaction_hash: Option<H256>,
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
        }

        match self.result {
            Res::Call(ref call) => struc.serialize_field("result", call)?,
            Res::Create(ref create) => {
                struc.serialize_field("result", create)?
            }
            Res::FailedCall(ref error) => {
                struc.serialize_field("error", &error.to_string())?
            }
            Res::FailedCreate(ref error) => {
                struc.serialize_field("error", &error.to_string())?
            }
            Res::None => {
                struc.serialize_field("result", &None as &Option<u8>)?
            }
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

impl TryFrom<RpcCfxLocalizedTrace> for LocalizedTrace {
    type Error = String;

    fn try_from(cfx_trace: RpcCfxLocalizedTrace) -> Result<Self, String> {
        Ok(Self {
            action: cfx_trace.action.try_into()?,
            result: Res::None,
            trace_address: vec![],
            subtraces: 0,
            // note: `as_usize` will panic on overflow,
            // however, this should not happen for tx position
            transaction_position: cfx_trace
                .transaction_position
                .map(|x| x.as_usize()),
            transaction_hash: cfx_trace.transaction_hash,
            block_number: cfx_trace
                .epoch_number
                .map(|en| en.as_u64())
                .unwrap_or(0),
            block_hash: cfx_trace.epoch_hash.unwrap_or_default(),
            valid: cfx_trace.valid,
        })
    }
}

impl LocalizedTrace {
    pub fn set_result(
        &mut self, result: RpcCfxAction,
    ) -> Result<(), JsonRpcError> {
        if !matches!(self.result, Res::None) {
            // One action matches exactly one result.
            bail!(JsonRpcError::internal_error());
        }
        match result {
            RpcCfxAction::CallResult(call_result) => {
                if !matches!(self.action, Action::Call(_)) {
                    bail!(JsonRpcError::internal_error());
                }
                match call_result.outcome {
                    Outcome::Success => {
                        // FIXME(lpl): Convert gas_left to gas_used.
                        self.result = Res::Call(CallResult {
                            gas_used: call_result.gas_left,
                            output: call_result.return_data,
                        })
                    }
                    Outcome::Reverted => {
                        self.result = Res::FailedCall(TraceError::Reverted);
                    }
                    Outcome::Fail => {
                        self.result = Res::FailedCall(TraceError::Error(
                            call_result.return_data,
                        ));
                    }
                }
            }
            RpcCfxAction::CreateResult(create_result) => {
                if !matches!(self.action, Action::Create(_)) {
                    bail!(JsonRpcError::internal_error());
                }
                match create_result.outcome {
                    Outcome::Success => {
                        // FIXME(lpl): Convert gas_left to gas_used.
                        // FIXME(lpl): Check if `return_data` is `code`.
                        self.result = Res::Create(CreateResult {
                            gas_used: create_result.gas_left,
                            code: create_result.return_data,
                            address: create_result.addr.hex_address,
                        })
                    }
                    Outcome::Reverted => {
                        self.result = Res::FailedCreate(TraceError::Reverted);
                    }
                    Outcome::Fail => {
                        self.result = Res::FailedCreate(TraceError::Error(
                            create_result.return_data,
                        ));
                    }
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
    result: Res,
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
        }

        match self.result {
            Res::Call(ref call) => struc.serialize_field("result", call)?,
            Res::Create(ref create) => {
                struc.serialize_field("result", create)?
            }
            Res::FailedCall(ref error) => {
                struc.serialize_field("error", &error.to_string())?
            }
            Res::FailedCreate(ref error) => {
                struc.serialize_field("error", &error.to_string())?
            }
            Res::None => {
                struc.serialize_field("result", &None as &Option<u8>)?
            }
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
