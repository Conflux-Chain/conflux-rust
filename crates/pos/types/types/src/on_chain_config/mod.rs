// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{account_address::AccountAddress, event::EventKey};
use anyhow::{format_err, Result};
use serde::de::DeserializeOwned;
use std::{collections::HashMap, fmt, sync::Arc};

mod validator_set;

pub use self::validator_set::ValidatorSet;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConfigID(&'static str, &'static str);

impl fmt::Display for ConfigID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OnChain config ID [address: {}, identifier: {}]",
            self.0, self.1
        )
    }
}

/// State sync will panic if the value of any config in this registry is
/// uninitialized
pub const ON_CHAIN_CONFIG_REGISTRY: &[ConfigID] = &[ValidatorSet::CONFIG_ID];

#[derive(Clone, Debug, PartialEq)]
pub struct OnChainConfigPayload {
    epoch: u64,
    configs: Arc<HashMap<ConfigID, Vec<u8>>>,
}

impl OnChainConfigPayload {
    pub fn new(epoch: u64, configs: Arc<HashMap<ConfigID, Vec<u8>>>) -> Self {
        Self { epoch, configs }
    }

    pub fn epoch(&self) -> u64 { self.epoch }

    pub fn get<T: OnChainConfig>(&self) -> Result<T> {
        let bytes = self.configs.get(&T::CONFIG_ID).ok_or_else(|| {
            format_err!("[on-chain cfg] config not in payload")
        })?;
        T::deserialize_into_config(bytes)
    }

    pub fn configs(&self) -> &HashMap<ConfigID, Vec<u8>> { &self.configs }
}

impl fmt::Display for OnChainConfigPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut config_ids = "".to_string();
        for id in self.configs.keys() {
            config_ids += &id.to_string();
        }
        write!(
            f,
            "OnChainConfigPayload [epoch: {}, configs: {}]",
            self.epoch, config_ids
        )
    }
}

/// Trait to be implemented by a Rust struct representation of an on-chain
/// config that is stored in storage as a serialized byte array
pub trait OnChainConfig: Send + Sync + DeserializeOwned {
    const ADDRESS: &'static str = "0xA550C18";
    const IDENTIFIER: &'static str;
    const CONFIG_ID: ConfigID = ConfigID(Self::ADDRESS, Self::IDENTIFIER);

    fn deserialize_default_impl(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes::<Self>(&bytes).map_err(|e| {
            format_err!(
                "[on-chain config] Failed to deserialize into config: {}",
                e
            )
        })
    }

    fn deserialize_into_config(bytes: &[u8]) -> Result<Self> {
        Self::deserialize_default_impl(bytes)
    }
}

pub fn config_address() -> AccountAddress {
    AccountAddress::from_hex_literal("0xA550C18")
        .expect("failed to get address")
}

pub fn new_epoch_event_key() -> EventKey {
    EventKey::new_from_address(&config_address(), 4)
}
