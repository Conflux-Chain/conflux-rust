// Copyright 2023-2024 Paradigm.xyz
// This file is part of reth.
// Reth is a modular, contributor-friendly and blazing-fast implementation of
// the Ethereum protocol

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
use crate::BlockOverrides;
use cfx_bytes::Bytes;
use cfx_rpc_primitives::Bytes as RpcBytes;
use cfx_types::{Address, H256, U256, U64};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A set of account overrides
pub type RpcStateOverride = HashMap<Address, RpcAccountOverride>;

/// Custom account override used in rpc call
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcAccountOverride {
    /// Fake balance to set for the account before executing the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,
    /// Fake nonce to set for the account before executing the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U64>,
    /// Fake EVM bytecode to inject into the account before executing the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<RpcBytes>,
    /// Fake key-value mapping to override all slots in the account storage
    /// before executing the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<H256, H256>>,
    /// Fake key-value mapping to override individual slots in the account
    /// storage before executing the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_diff: Option<HashMap<H256, H256>>,
    /// Moves addresses precompile into the specified address. This move is
    /// done before the 'code' override is set. When the specified address
    /// is not a precompile, the behaviour is undefined and different
    /// clients might behave differently.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "movePrecompileToAddress"
    )]
    pub move_precompile_to: Option<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountStateOverrideMode {
    State(HashMap<H256, H256>),
    Diff(HashMap<H256, H256>),
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountOverride {
    pub balance: Option<U256>,
    pub nonce: Option<U64>,
    pub code: Option<Bytes>,
    pub state: AccountStateOverrideMode,
    pub move_precompile_to: Option<Address>,
}

impl TryFrom<RpcAccountOverride> for AccountOverride {
    type Error = &'static str;

    fn try_from(value: RpcAccountOverride) -> Result<Self, Self::Error> {
        Ok(Self {
            balance: value.balance,
            nonce: value.nonce,
            code: value.code.map(|v| v.into()),
            state: match (value.state, value.state_diff) {
                (Some(state), None) => AccountStateOverrideMode::State(state),
                (None, Some(diff)) => AccountStateOverrideMode::Diff(diff),
                (None, None) => AccountStateOverrideMode::None,
                _ => return Err("state and stateDiff are mutually exclusive"),
            },
            move_precompile_to: value.move_precompile_to,
        })
    }
}

pub type StateOverride = HashMap<Address, AccountOverride>;

/// Helper type that bundles various overrides for EVM Execution.
///
/// By `Default`, no overrides are included.
#[derive(Debug, Clone, Default)]
pub struct EvmOverrides {
    /// Applies overrides to the state before execution.
    pub state: Option<StateOverride>,
    /// Applies overrides to the block before execution.
    ///
    /// This is a `Box` because less common and only available in debug trace
    /// endpoints.
    pub block: Option<Box<BlockOverrides>>,
}

impl EvmOverrides {
    /// Creates a new instance with the given overrides
    pub const fn new(
        state: Option<StateOverride>, block: Option<Box<BlockOverrides>>,
    ) -> Self {
        Self { state, block }
    }

    /// Creates a new instance with the given state overrides.
    pub const fn state(state: Option<StateOverride>) -> Self {
        Self { state, block: None }
    }

    /// Creates a new instance with the given block overrides.
    pub const fn block(block: Option<Box<BlockOverrides>>) -> Self {
        Self { state: None, block }
    }

    /// Returns `true` if the overrides contain state overrides.
    pub const fn has_state(&self) -> bool { self.state.is_some() }

    /// Returns `true` if the overrides contain block overrides.
    pub const fn has_block(&self) -> bool { self.block.is_some() }

    pub const fn is_none(&self) -> bool {
        self.state.is_none() && self.block.is_none()
    }

    /// Adds state overrides to an existing instance.
    pub fn with_state(mut self, state: StateOverride) -> Self {
        self.state = Some(state);
        self
    }

    /// Adds block overrides to an existing instance.
    pub fn with_block(mut self, block: Box<BlockOverrides>) -> Self {
        self.block = Some(block);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use cfx_types::address_util::hex_to_address;
    use similar_asserts::assert_eq;

    #[test]
    fn test_default_account_override() {
        let acc_override = RpcAccountOverride::default();
        assert!(acc_override.balance.is_none());
        assert!(acc_override.nonce.is_none());
        assert!(acc_override.code.is_none());
        assert!(acc_override.state.is_none());
        assert!(acc_override.state_diff.is_none());
    }

    #[test]
    #[cfg(feature = "serde")]
    #[should_panic(expected = "invalid type")]
    fn test_invalid_json_structure() {
        let invalid_json = r#"{
            "0x1234567890123456789012345678901234567890": {
                "balance": true
            }
        }"#;

        let _: RpcStateOverride = serde_json::from_str(invalid_json).unwrap();
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_large_values_in_override() {
        let large_values_json = r#"{
            "0x1234567890123456789012345678901234567890": {
                "balance": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "nonce": "0xffffffffffffffff"
            }
        }"#;

        let state_override: RpcStateOverride =
            serde_json::from_str(large_values_json).unwrap();
        let acc = state_override
            .get(
                &hex_to_address("1234567890123456789012345678901234567890")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(acc.balance, Some(U256::MAX));
        assert_eq!(acc.nonce, Some(U64::from(u64::MAX)));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_state_override() {
        let s = r#"{
            "0x0000000000000000000000000000000000000124": {
                "code": "0x6080604052348015600e575f80fd5b50600436106026575f3560e01c80632096525514602a575b5f80fd5b60306044565b604051901515815260200160405180910390f35b5f604e600242605e565b5f0360595750600190565b505f90565b5f82607757634e487b7160e01b5f52601260045260245ffd5b50069056fea2646970667358221220287f77a4262e88659e3fb402138d2ee6a7ff9ba86bae487a95aa28156367d09c64736f6c63430008140033"
            }
        }"#;
        let state_override: RpcStateOverride = serde_json::from_str(s).unwrap();
        let acc = state_override
            .get(
                &hex_to_address("0000000000000000000000000000000000000124")
                    .unwrap(),
            )
            .unwrap();
        assert!(acc.code.is_some());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_state_override_state_diff() {
        let s = r#"{
                "0x1b5212AF6b76113afD94cD2B5a78a73B7d7A8222": {
                    "balance": "0x39726378b58c400000",
                    "stateDiff": {}
                },
                "0xdAC17F958D2ee523a2206206994597C13D831ec7": {
                    "stateDiff": {
                        "0xede27e4e7f3676edbf125879f17a896d6507958df3d57bda6219f1880cae8a41": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    }
                }
            }"#;
        let state_override: RpcStateOverride = serde_json::from_str(s).unwrap();
        let acc = state_override
            .get(
                &hex_to_address("1b5212AF6b76113afD94cD2B5a78a73B7d7A8222")
                    .unwrap(),
            )
            .unwrap();
        assert!(acc.state_diff.is_some());
    }

    #[test]
    fn test_evm_overrides_new() {
        let state = StateOverride::default();
        let block: Box<BlockOverrides> = Box::default();

        let evm_overrides =
            EvmOverrides::new(Some(state.clone()), Some(block.clone()));

        assert!(evm_overrides.has_state());
        assert!(evm_overrides.has_block());
        assert_eq!(evm_overrides.state.unwrap(), state);
        assert_eq!(*evm_overrides.block.unwrap(), *block);
    }

    #[test]
    fn test_evm_overrides_state() {
        let state = StateOverride::default();
        let evm_overrides = EvmOverrides::state(Some(state.clone()));

        assert!(evm_overrides.has_state());
        assert!(!evm_overrides.has_block());
        assert_eq!(evm_overrides.state.unwrap(), state);
    }

    #[test]
    fn test_evm_overrides_block() {
        let block: Box<BlockOverrides> = Box::default();
        let evm_overrides = EvmOverrides::block(Some(block.clone()));

        assert!(!evm_overrides.has_state());
        assert!(evm_overrides.has_block());
        assert_eq!(*evm_overrides.block.unwrap(), *block);
    }

    #[test]
    fn test_evm_overrides_with_state() {
        let state = StateOverride::default();
        let mut evm_overrides = EvmOverrides::default();

        assert!(!evm_overrides.has_state());

        evm_overrides = evm_overrides.with_state(state.clone());

        assert!(evm_overrides.has_state());
        assert_eq!(evm_overrides.state.unwrap(), state);
    }

    #[test]
    fn test_evm_overrides_with_block() {
        let block: Box<BlockOverrides> = Box::default();
        let mut evm_overrides = EvmOverrides::default();

        assert!(!evm_overrides.has_block());

        evm_overrides = evm_overrides.with_block(block.clone());

        assert!(evm_overrides.has_block());
        assert_eq!(*evm_overrides.block.unwrap(), *block);
    }
}
