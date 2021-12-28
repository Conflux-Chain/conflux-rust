// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use anyhow::{ensure, format_err, Error, Result};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};

/// A registry of named chain IDs
/// Its main purpose is to improve human readability of reserved chain IDs in
/// config files and CLI When signing transactions for such chains, the
/// numerical chain ID should still be used (e.g. MAINNET has numeric chain ID
/// 1, TESTNET has chain ID 2, etc)
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum NamedChain {
    /// Users might accidentally initialize the ChainId field to 0, hence
    /// reserving ChainId 0 for accidental initialization.
    /// MAINNET is the Diem mainnet production chain and is reserved for 1
    MAINNET = 1,
    // Even though these CHAIN IDs do not correspond to MAINNET, changing them
    // should be avoided since they can break test environments for
    // various organisations.
    TESTNET = 2,
    DEVNET = 3,
    TESTING = 4,
    PREMAINNET = 5,
}

impl NamedChain {
    fn str_to_chain_id(s: &str) -> Result<ChainId> {
        // TODO implement custom macro that derives FromStr impl for enum
        // (similar to diem/common/num-variants)
        let reserved_chain = match s {
            "MAINNET" => NamedChain::MAINNET,
            "TESTNET" => NamedChain::TESTNET,
            "DEVNET" => NamedChain::DEVNET,
            "TESTING" => NamedChain::TESTING,
            "PREMAINNET" => NamedChain::PREMAINNET,
            _ => {
                return Err(format_err!("Not a reserved chain: {:?}", s));
            }
        };
        Ok(ChainId::new(reserved_chain.id()))
    }

    pub fn id(&self) -> u64 { *self as u64 }

    pub fn from_chain_id(chain_id: &ChainId) -> Result<NamedChain, String> {
        match chain_id.id() {
            1 => Ok(NamedChain::MAINNET),
            2 => Ok(NamedChain::TESTNET),
            3 => Ok(NamedChain::DEVNET),
            4 => Ok(NamedChain::TESTING),
            5 => Ok(NamedChain::PREMAINNET),
            _ => Err(String::from("Not a named chain")),
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ChainId(u64);

pub fn deserialize_config_chain_id<'de, D>(
    deserializer: D,
) -> std::result::Result<ChainId, D::Error>
where D: Deserializer<'de> {
    struct ChainIdVisitor;

    impl<'de> Visitor<'de> for ChainIdVisitor {
        type Value = ChainId;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ChainId as string or u8")
        }

        fn visit_str<E>(
            self, value: &str,
        ) -> std::result::Result<Self::Value, E>
        where E: serde::de::Error {
            ChainId::from_str(value).map_err(serde::de::Error::custom)
        }

        fn visit_u64<E>(
            self, value: u64,
        ) -> std::result::Result<Self::Value, E>
        where E: serde::de::Error {
            Ok(ChainId::new(
                u64::try_from(value).map_err(serde::de::Error::custom)?,
            ))
        }
    }

    deserializer.deserialize_any(ChainIdVisitor)
}

impl fmt::Debug for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            NamedChain::from_chain_id(&self)
                .map_or_else(|_| self.0.to_string(), |chain| chain.to_string())
        )
    }
}

impl fmt::Display for NamedChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                NamedChain::DEVNET => "DEVNET",
                NamedChain::TESTNET => "TESTNET",
                NamedChain::MAINNET => "MAINNET",
                NamedChain::TESTING => "TESTING",
                NamedChain::PREMAINNET => "PREMAINNET",
            }
        )
    }
}

impl Default for ChainId {
    fn default() -> Self { Self::test() }
}

impl FromStr for ChainId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        ensure!(!s.is_empty(), "Cannot create chain ID from empty string");
        NamedChain::str_to_chain_id(s).or_else(|_err| {
            let value = s.parse::<u64>()?;
            ensure!(value > 0, "cannot have chain ID with 0");
            Ok(ChainId::new(value))
        })
    }
}

impl ChainId {
    pub fn new(id: u64) -> Self {
        assert!(id > 0, "cannot have chain ID with 0");
        Self(id)
    }

    pub fn id(&self) -> u64 { self.0 }

    pub fn test() -> Self { ChainId::new(NamedChain::TESTING.id()) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chain_id_from_str() {
        assert!(ChainId::from_str("").is_err());
        assert!(ChainId::from_str("0").is_err());
        // 2^64 overflows.
        assert!(ChainId::from_str("18446744073709551616").is_err());
        assert_eq!(ChainId::from_str("TESTING").unwrap(), ChainId::test());
        assert_eq!(ChainId::from_str("255").unwrap(), ChainId::new(255));
    }
}
