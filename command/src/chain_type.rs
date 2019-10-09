// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{fmt, str};

#[derive(Debug, PartialEq)]
pub enum ChainType {
    Conflux,
    Ethereum,
    Classic,
    Poanet,
    Xdai,
    Volta,
    Ewc,
    Musicoin,
    Ellaism,
    Mix,
    Callisto,
    Morden,
    Ropsten,
    Kovan,
    Rinkeby,
    Goerli,
    Kotti,
    Sokol,
    Dev,
    Custom(String),
}

impl ChainType {
    pub fn name(&self) -> String {
        match self {
            ChainType::Conflux => "conflux".to_string(),
            ChainType::Ethereum => "ethereum".to_string(),
            ChainType::Classic => "classic".to_string(),
            ChainType::Poanet => "poanet".to_string(),
            ChainType::Xdai => "xdai".to_string(),
            ChainType::Volta => "volta".to_string(),
            ChainType::Ewc => "energyweb".to_string(),
            ChainType::Musicoin => "musicoin".to_string(),
            ChainType::Ellaism => "ellaism".to_string(),
            ChainType::Mix => "mix".to_string(),
            ChainType::Callisto => "callisto".to_string(),
            ChainType::Morden => "morden".to_string(),
            ChainType::Ropsten => "ropsten".to_string(),
            ChainType::Kovan => "kovan".to_string(),
            ChainType::Rinkeby => "rinkeby".to_string(),
            ChainType::Goerli => "goerli".to_string(),
            ChainType::Kotti => "kotti".to_string(),
            ChainType::Sokol => "sokol".to_string(),
            ChainType::Dev => "dev".to_string(),
            ChainType::Custom(custom) => custom.clone(),
        }
    }
}

impl Default for ChainType {
    fn default() -> Self { ChainType::Conflux }
}

impl str::FromStr for ChainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let chain = match s {
            "conflux" => ChainType::Conflux,
            "ethereum" => ChainType::Ethereum,
            "classic" => ChainType::Classic,
            "poanet" => ChainType::Poanet,
            "xdai" => ChainType::Xdai,
            "volta" => ChainType::Volta,
            "ewc" => ChainType::Ewc,
            "musicoin" => ChainType::Musicoin,
            "ellaism" => ChainType::Ellaism,
            "mix" => ChainType::Mix,
            "callisto" => ChainType::Callisto,
            "morden" => ChainType::Morden,
            "ropsten" => ChainType::Ropsten,
            "kovan" => ChainType::Kovan,
            "rinkeby" => ChainType::Rinkeby,
            "goerli" => ChainType::Goerli,
            "kotti" => ChainType::Kotti,
            "sokol" => ChainType::Sokol,
            "dev" => ChainType::Dev,
            other => ChainType::Custom(other.into()),
        };
        Ok(chain)
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.name())
    }
}
