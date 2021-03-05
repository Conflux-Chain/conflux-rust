// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{collections::HashSet, str::FromStr};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum Api {
    Cfx,
    Debug,
    Pubsub,
    Test,
    Trace,
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
            _ => Err("Unknown api type".into()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ApiSet {
    All,
    Safe,
    List(HashSet<Api>),
}

impl ApiSet {
    pub fn list_apis(&self) -> HashSet<Api> {
        match *self {
            ApiSet::List(ref apis) => apis.clone(),
            ApiSet::All => {
                [Api::Cfx, Api::Debug, Api::Pubsub, Api::Test, Api::Trace]
                    .iter()
                    .cloned()
                    .collect()
            }
            ApiSet::Safe => [Api::Cfx, Api::Pubsub].iter().cloned().collect(),
        }
    }
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
