use cfx_types::U256;
use primitives::AccessList;

/// Access list with gas used appended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AccessListWithGasUsed {
    /// List with accounts accessed during transaction.
    pub access_list: AccessList,
    /// Estimated gas used with access list.
    pub gas_used: U256,
}

/// `AccessListResult` for handling errors from `eth_createAccessList`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AccessListResult {
    /// List with accounts accessed during transaction.
    pub access_list: AccessList,
    /// Estimated gas used with access list.
    pub gas_used: U256,
    /// Optional error message if the transaction failed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub error: Option<String>,
}

impl AccessListResult {
    /// Ensures the result is OK, returning [`AccessListWithGasUsed`] if so, or
    /// an error message if not.
    pub fn ensure_ok(self) -> Result<AccessListWithGasUsed, String> {
        match self.error {
            Some(err) => Err(err),
            None => Ok(AccessListWithGasUsed {
                access_list: self.access_list,
                gas_used: self.gas_used,
            }),
        }
    }

    /// Checks if there is an error in the result.
    #[inline]
    pub const fn is_err(&self) -> bool { self.error.is_some() }
}
