use crate::{BlockNumber as BlockId, BlockOverrides, TransactionRequest};
use cfx_bytes::Bytes;

/// Bundle of transactions
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Bundle {
    /// All transactions to execute
    pub transactions: Vec<TransactionRequest>,
    /// Block overrides to apply
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub block_override: Option<BlockOverrides>,
}

impl From<Vec<TransactionRequest>> for Bundle {
    /// Converts a `TransactionRequest` into a `Bundle`.
    fn from(tx_request: Vec<TransactionRequest>) -> Self {
        Self {
            transactions: tx_request,
            block_override: None,
        }
    }
}

/// State context for callMany
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct StateContext {
    /// Block Number
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub block_number: Option<BlockId>,
    /// Inclusive number of tx to replay in block. -1 means replay all
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none")
    )]
    #[doc(alias = "tx_index")]
    pub transaction_index: Option<TransactionIndex>,
}

/// CallResponse for eth_callMany
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct EthCallResponse {
    /// eth_call output (if no error)
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub value: Option<Bytes>,
    /// eth_call output (if error)
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub error: Option<String>,
}

impl EthCallResponse {
    /// Returns the value if present, otherwise returns the error.
    pub fn ensure_ok(self) -> Result<Bytes, String> {
        match self.value {
            Some(output) => Ok(output),
            None => {
                Err(self.error.unwrap_or_else(|| "Unknown error".to_string()))
            }
        }
    }
}

/// Represents a transaction index where -1 means all transactions
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransactionIndex {
    /// -1 means all transactions
    #[default]
    All,
    /// Transaction index
    Index(usize),
}

impl TransactionIndex {
    /// Returns true if this is the all variant
    pub const fn is_all(&self) -> bool { matches!(self, Self::All) }

    /// Returns true if this is the index variant
    pub const fn is_index(&self) -> bool { matches!(self, Self::Index(_)) }

    /// Returns the index if this is the index variant
    pub const fn index(&self) -> Option<usize> {
        match self {
            Self::All => None,
            Self::Index(idx) => Some(*idx),
        }
    }
}

impl From<usize> for TransactionIndex {
    fn from(index: usize) -> Self { Self::Index(index) }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TransactionIndex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        match self {
            Self::All => serializer.serialize_i8(-1),
            Self::Index(idx) => idx.serialize(serializer),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TransactionIndex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        match isize::deserialize(deserializer)? {
            -1 => Ok(Self::All),
            idx if idx < -1 => Err(serde::de::Error::custom(format!(
                "Invalid transaction index, expected -1 or positive integer, got {}",
                idx
            ))),
            idx => Ok(Self::Index(idx as usize)),
        }
    }
}
