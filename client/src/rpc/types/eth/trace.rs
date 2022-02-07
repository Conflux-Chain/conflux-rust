use crate::rpc::types::Bytes;
use cfx_types::{H160, H256, U256};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::fmt;

/// Create response
#[derive(Debug, Serialize)]
pub struct Create {
    /// Sender
    from: H160,
    /// Value
    value: U256,
    /// Gas
    gas: U256,
    /// Initialization code
    init: Bytes,
}

/// Call type.
#[derive(Debug, Serialize)]
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

/// Call response
#[derive(Debug, Serialize)]
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
#[derive(Debug)]
pub enum Action {
    /// Call
    Call(Call),
    /// Create
    Create(Create),
    /* TODO: Support Suicide
     * TODO: Support Reward */
}

/// Call Result
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallResult {
    /// Gas used
    gas_used: U256,
    /// Output bytes
    output: Bytes,
}

/// Craete Result
#[derive(Debug, Serialize)]
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
#[derive(Debug)]
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
#[derive(Debug)]
pub struct LocalizedTrace {
    /// Action
    action: Action,
    /// Result
    result: Res,
    /// Trace address
    trace_address: Vec<usize>,
    /// Subtraces
    subtraces: usize,
    /// Transaction position
    transaction_position: Option<usize>,
    /// Transaction hash
    transaction_hash: Option<H256>,
    /// Block Number
    block_number: u64,
    /// Block Hash
    block_hash: H256,
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

        struc.end()
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

#[derive(Debug)]
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
