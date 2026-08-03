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
use std::{collections::HashSet, fmt, str::FromStr};

use cfx_rpc_cfx_types::apis::{Api, ApiSet};
use serde::{Deserialize, Serialize, Serializer};
use strum::{
    AsRefStr, EnumIter, IntoStaticStr, ParseError, VariantArray, VariantNames,
};

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub enum RpcModuleSelection {
    #[default]
    All,
    None,
    Standard,
    Selection(HashSet<CfxRpcModule>),
}

impl RpcModuleSelection {
    pub const STANDARD_MODULES: [CfxRpcModule; 2] =
        [CfxRpcModule::Cfx, CfxRpcModule::PubSub];

    pub fn all_modules() -> HashSet<CfxRpcModule> {
        CfxRpcModule::modules().into_iter().collect()
    }

    pub fn standard_modules() -> HashSet<CfxRpcModule> {
        HashSet::from(Self::STANDARD_MODULES)
    }

    pub fn len(&self) -> usize {
        match self {
            Self::All => CfxRpcModule::variant_count(),
            Self::None => 0,
            Self::Standard => Self::STANDARD_MODULES.len(),
            Self::Selection(s) => s.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Selection(s) => s.is_empty(),
            Self::None => true,
            _ => false,
        }
    }

    pub fn iter_selection(
        &self,
    ) -> Box<dyn Iterator<Item = CfxRpcModule> + '_> {
        match self {
            Self::All => Box::new(CfxRpcModule::modules().into_iter()),
            Self::None => Box::new(std::iter::empty()),
            Self::Standard => Box::new(Self::STANDARD_MODULES.iter().copied()),
            Self::Selection(s) => Box::new(s.iter().copied()),
        }
    }

    pub fn to_selection(&self) -> HashSet<CfxRpcModule> {
        match self {
            Self::All => Self::all_modules(),
            Self::None => HashSet::new(),
            Self::Standard => Self::standard_modules(),
            Self::Selection(s) => s.clone(),
        }
    }

    pub fn into_selection(self) -> HashSet<CfxRpcModule> {
        match self {
            Self::All => Self::all_modules(),
            Self::None => HashSet::new(),
            Self::Standard => Self::standard_modules(),
            Self::Selection(s) => s,
        }
    }

    pub fn are_identical(http: Option<&Self>, ws: Option<&Self>) -> bool {
        match (http, ws) {
            (Some(Self::All), Some(other)) | (Some(other), Some(Self::All)) => {
                other.len() == CfxRpcModule::variant_count()
            }
            (Some(some), None) | (None, Some(some)) => some.is_empty(),
            (Some(http), Some(ws)) => http.to_selection() == ws.to_selection(),
            (None, None) => true,
        }
    }
}

impl From<&HashSet<CfxRpcModule>> for RpcModuleSelection {
    fn from(s: &HashSet<CfxRpcModule>) -> Self { Self::from(s.clone()) }
}

impl From<HashSet<CfxRpcModule>> for RpcModuleSelection {
    fn from(s: HashSet<CfxRpcModule>) -> Self { Self::Selection(s) }
}

impl From<&[CfxRpcModule]> for RpcModuleSelection {
    fn from(s: &[CfxRpcModule]) -> Self {
        Self::Selection(s.iter().copied().collect())
    }
}

impl From<Vec<CfxRpcModule>> for RpcModuleSelection {
    fn from(s: Vec<CfxRpcModule>) -> Self {
        Self::Selection(s.into_iter().collect())
    }
}

impl<const N: usize> From<[CfxRpcModule; N]> for RpcModuleSelection {
    fn from(s: [CfxRpcModule; N]) -> Self {
        Self::Selection(s.iter().copied().collect())
    }
}

impl<'a> FromIterator<&'a CfxRpcModule> for RpcModuleSelection {
    fn from_iter<I>(iter: I) -> Self
    where I: IntoIterator<Item = &'a CfxRpcModule> {
        iter.into_iter().copied().collect()
    }
}

impl FromIterator<CfxRpcModule> for RpcModuleSelection {
    fn from_iter<I>(iter: I) -> Self
    where I: IntoIterator<Item = CfxRpcModule> {
        Self::Selection(iter.into_iter().collect())
    }
}

impl FromStr for RpcModuleSelection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self::Selection(Default::default()));
        }
        let mut modules = s.split(',').map(str::trim).peekable();
        let first = modules
            .peek()
            .copied()
            .ok_or(ParseError::VariantNotFound.to_string())?;
        match first {
            "all" | "All" => Ok(Self::All),
            "none" | "None" => Ok(Self::None),
            "standard" | "Standard" => Ok(Self::Standard),
            "safe" => {
                let mut selection = HashSet::new();
                selection.insert(CfxRpcModule::Cfx);
                selection.insert(CfxRpcModule::PubSub);
                selection.insert(CfxRpcModule::Txpool);
                Ok(Self::Selection(selection))
            }
            _ => {
                let mut selection = HashSet::new();
                for module in modules {
                    let m: CfxRpcModule = module
                        .parse()
                        .map_err(|e: ParseError| e.to_string())?;
                    selection.insert(m);
                }
                Ok(Self::Selection(selection))
            }
        }
    }
}

impl fmt::Display for RpcModuleSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}]",
            self.iter_selection()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl From<Api> for CfxRpcModule {
    fn from(value: Api) -> Self {
        match value {
            Api::Cfx => Self::Cfx,
            Api::Debug => Self::Debug,
            Api::Pubsub => Self::PubSub,
            Api::Test => Self::Test,
            Api::Trace => Self::Trace,
            Api::TxPool => Self::Txpool,
            Api::Pos => Self::Pos,
        }
    }
}

impl From<CfxRpcModule> for Api {
    fn from(value: CfxRpcModule) -> Self {
        match value {
            CfxRpcModule::Cfx => Self::Cfx,
            CfxRpcModule::Debug => Self::Debug,
            CfxRpcModule::Pos => Self::Pos,
            CfxRpcModule::Trace => Self::Trace,
            CfxRpcModule::Txpool => Self::TxPool,
            CfxRpcModule::Test => Self::Test,
            CfxRpcModule::PubSub => Self::Pubsub,
        }
    }
}

impl From<ApiSet> for RpcModuleSelection {
    fn from(value: ApiSet) -> Self {
        Self::Selection(value.list_apis().into_iter().map(Into::into).collect())
    }
}

impl From<RpcModuleSelection> for ApiSet {
    fn from(value: RpcModuleSelection) -> Self {
        ApiSet::List(
            value.into_selection().into_iter().map(Into::into).collect(),
        )
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    AsRefStr,
    IntoStaticStr,
    VariantNames,
    VariantArray,
    EnumIter,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "kebab-case")]
pub enum CfxRpcModule {
    Cfx,
    Debug,
    Pos,
    Trace,
    Txpool,
    Test,
    PubSub,
}

impl CfxRpcModule {
    pub const fn variant_count() -> usize {
        <Self as VariantArray>::VARIANTS.len()
    }

    pub const fn all_variant_names() -> &'static [&'static str] {
        <Self as VariantNames>::VARIANTS
    }

    pub const fn all_variants() -> &'static [Self] {
        <Self as VariantArray>::VARIANTS
    }

    pub fn modules() -> impl IntoIterator<Item = Self> {
        use strum::IntoEnumIterator;
        Self::iter()
    }

    #[inline]
    pub fn as_str(&self) -> &'static str { self.into() }
}

impl FromStr for CfxRpcModule {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "cfx" => Self::Cfx,
            "debug" => Self::Debug,
            "pos" => Self::Pos,
            "trace" => Self::Trace,
            "txpool" => Self::Txpool,
            "test" => Self::Test,
            "pubsub" => Self::PubSub,
            _ => return Err(ParseError::VariantNotFound),
        })
    }
}

impl TryFrom<&str> for CfxRpcModule {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
        FromStr::from_str(s)
    }
}

impl fmt::Display for CfxRpcModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_ref())
    }
}

impl Serialize for CfxRpcModule {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_str(self.as_ref())
    }
}
