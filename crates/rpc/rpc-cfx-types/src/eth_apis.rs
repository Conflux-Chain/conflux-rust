// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Temp put it here, will be removed very soon

use std::{
    collections::HashSet,
    fmt::{Display, Formatter},
    str::FromStr,
};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum EthApi {
    Eth,
    Debug,
    Pubsub,
}

impl FromStr for EthApi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::EthApi::*;
        match s {
            "eth" => Ok(Eth),
            "debug" => Ok(Debug),
            "pubsub" => Ok(Pubsub),
            "ethpubsub" => Ok(Pubsub),
            "ethdebug" => Ok(Debug),
            _ => Err("Unknown api type".into()),
        }
    }
}

impl Display for EthApi {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EthApi::Eth => write!(f, "eth"),
            EthApi::Debug => write!(f, "debug"),
            EthApi::Pubsub => write!(f, "pubsub"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EthApiSet {
    All, // eSpace all apis
    Evm, // Ethereum api set
    List(HashSet<EthApi>),
}

impl EthApiSet {
    pub fn list_apis(&self) -> HashSet<EthApi> {
        match *self {
            EthApiSet::List(ref apis) => apis.clone(),
            EthApiSet::All => [EthApi::Eth, EthApi::Debug, EthApi::Pubsub]
                .iter()
                .cloned()
                .collect(),
            EthApiSet::Evm => {
                [EthApi::Eth, EthApi::Pubsub].iter().cloned().collect()
            }
        }
    }
}

impl Default for EthApiSet {
    fn default() -> Self { EthApiSet::Evm }
}

impl FromStr for EthApiSet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut apis = HashSet::new();

        for api in s.split(',') {
            match api {
                "all" => {
                    apis.extend(EthApiSet::All.list_apis());
                }
                "evm" => {
                    apis.extend(EthApiSet::Evm.list_apis());
                }
                // Remove the API
                api if api.starts_with("-") => {
                    let api = api[1..].parse()?;
                    apis.remove(&api);
                }
                api => {
                    let api = api.parse()?;
                    apis.insert(api);
                }
            }
        }

        Ok(EthApiSet::List(apis))
    }
}
