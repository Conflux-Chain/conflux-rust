// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::HashSet,
    fmt::{Display, Formatter},
    str::FromStr,
};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum Api {
    Cfx,
    Debug,
    Pubsub,
    Test,
    Trace,
    TxPool,
    Pos,
}

impl FromStr for Api {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::Api::*;
        match s {
            "cfx" => Ok(Cfx),
            "debug" => Ok(Debug),
            "pubsub" => Ok(Pubsub),
            "test" => Ok(Test),
            "trace" => Ok(Trace),
            "txpool" => Ok(TxPool),
            "pos" => Ok(Pos),
            _ => Err("Unknown api type".into()),
        }
    }
}

impl Display for Api {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Api::Cfx => write!(f, "cfx"),
            Api::Debug => write!(f, "debug"),
            Api::Pubsub => write!(f, "pubsub"),
            Api::Test => write!(f, "test"),
            Api::Trace => write!(f, "trace"),
            Api::TxPool => write!(f, "txpool"),
            Api::Pos => write!(f, "pos"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ApiSet {
    All, // core space all apis
    Safe,
    List(HashSet<Api>),
}

impl ApiSet {
    pub fn list_apis(&self) -> HashSet<Api> {
        match *self {
            ApiSet::List(ref apis) => apis.clone(),
            ApiSet::All => [
                Api::Cfx,
                Api::Debug,
                Api::Pubsub,
                Api::Test,
                Api::Trace,
                Api::Pos,
                Api::TxPool,
            ]
            .iter()
            .cloned()
            .collect(),
            ApiSet::Safe => [Api::Cfx, Api::Pubsub, Api::TxPool]
                .iter()
                .cloned()
                .collect(),
        }
    }
}

impl Default for ApiSet {
    fn default() -> Self { ApiSet::Safe }
}

impl FromStr for ApiSet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut apis = HashSet::new();

        for api in s.split(',') {
            match api {
                "all" => {
                    apis.extend(ApiSet::All.list_apis());
                }
                "safe" => {
                    // Safe APIs are those that are safe even in UnsafeContext.
                    apis.extend(ApiSet::Safe.list_apis());
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

        Ok(ApiSet::List(apis))
    }
}
