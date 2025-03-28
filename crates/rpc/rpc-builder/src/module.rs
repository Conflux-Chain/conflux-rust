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

use serde::{Deserialize, Serialize, Serializer};
use strum::{
    AsRefStr, EnumIter, IntoStaticStr, ParseError, VariantArray, VariantNames,
};

/// Describes the modules that should be installed.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub enum RpcModuleSelection {
    /// Use _all_ available modules.
    All,
    /// The default modules `eth`, `net`, `web3`
    #[default]
    Standard,
    /// eth, ethpubsub(not implemented)
    Evm,
    /// Only use the configured modules.
    Selection(HashSet<EthRpcModule>),
}

impl RpcModuleSelection {
    pub const EVM_MODULES: [EthRpcModule; 1] = [EthRpcModule::Eth];
    /// The standard modules to instantiate by default `eth`, `net`, `web3`
    pub const STANDARD_MODULES: [EthRpcModule; 3] =
        [EthRpcModule::Eth, EthRpcModule::Net, EthRpcModule::Web3];

    /// Returns a selection of [`EthRpcModule`] with all
    /// [`EthRpcModule::all_variants`].
    pub fn all_modules() -> HashSet<EthRpcModule> {
        EthRpcModule::modules().into_iter().collect()
    }

    /// Returns the [`RpcModuleSelection::STANDARD_MODULES`] as a selection.
    pub fn standard_modules() -> HashSet<EthRpcModule> {
        HashSet::from(Self::STANDARD_MODULES)
    }

    pub fn evm_modules() -> HashSet<EthRpcModule> {
        HashSet::from(Self::EVM_MODULES)
    }

    /// All modules that are available by default on IPC.
    ///
    /// By default all modules are available on IPC.
    pub fn default_ipc_modules() -> HashSet<EthRpcModule> {
        Self::all_modules()
    }

    /// Creates a new _unique_ [`RpcModuleSelection::Selection`] from the given
    /// items.
    ///
    /// # Note
    ///
    /// This will dedupe the selection and remove duplicates while preserving
    /// the order.
    pub fn try_from_selection<I, T>(selection: I) -> Result<Self, T::Error>
    where
        I: IntoIterator<Item = T>,
        T: TryInto<EthRpcModule>,
    {
        selection.into_iter().map(TryInto::try_into).collect()
    }

    /// Returns the number of modules in the selection
    pub fn len(&self) -> usize {
        match self {
            Self::All => EthRpcModule::variant_count(),
            Self::Standard => Self::STANDARD_MODULES.len(),
            Self::Evm => Self::EVM_MODULES.len(),
            Self::Selection(s) => s.len(),
        }
    }

    /// Returns true if no selection is configured
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Selection(sel) => sel.is_empty(),
            _ => false,
        }
    }

    /// Returns an iterator over all configured [`EthRpcModule`]
    pub fn iter_selection(
        &self,
    ) -> Box<dyn Iterator<Item = EthRpcModule> + '_> {
        match self {
            Self::All => Box::new(EthRpcModule::modules().into_iter()),
            Self::Standard => Box::new(Self::STANDARD_MODULES.iter().copied()),
            Self::Evm => Box::new(Self::EVM_MODULES.iter().copied()),
            Self::Selection(s) => Box::new(s.iter().copied()),
        }
    }

    /// Clones the set of configured [`EthRpcModule`].
    pub fn to_selection(&self) -> HashSet<EthRpcModule> {
        match self {
            Self::All => Self::all_modules(),
            Self::Standard => Self::standard_modules(),
            Self::Evm => Self::evm_modules(),
            Self::Selection(s) => s.clone(),
        }
    }

    /// Converts the selection into a [`HashSet`].
    pub fn into_selection(self) -> HashSet<EthRpcModule> {
        match self {
            Self::All => Self::all_modules(),
            Self::Standard => Self::standard_modules(),
            Self::Evm => Self::evm_modules(),
            Self::Selection(s) => s,
        }
    }

    /// Returns true if both selections are identical.
    pub fn are_identical(http: Option<&Self>, ws: Option<&Self>) -> bool {
        match (http, ws) {
            // Shortcut for common case to avoid iterating later
            (Some(Self::All), Some(other)) | (Some(other), Some(Self::All)) => {
                other.len() == EthRpcModule::variant_count()
            }

            // If either side is disabled, then the other must be empty
            (Some(some), None) | (None, Some(some)) => some.is_empty(),

            (Some(http), Some(ws)) => http.to_selection() == ws.to_selection(),
            (None, None) => true,
        }
    }
}

impl From<&HashSet<EthRpcModule>> for RpcModuleSelection {
    fn from(s: &HashSet<EthRpcModule>) -> Self { Self::from(s.clone()) }
}

impl From<HashSet<EthRpcModule>> for RpcModuleSelection {
    fn from(s: HashSet<EthRpcModule>) -> Self { Self::Selection(s) }
}

impl From<&[EthRpcModule]> for RpcModuleSelection {
    fn from(s: &[EthRpcModule]) -> Self {
        Self::Selection(s.iter().copied().collect())
    }
}

impl From<Vec<EthRpcModule>> for RpcModuleSelection {
    fn from(s: Vec<EthRpcModule>) -> Self {
        Self::Selection(s.into_iter().collect())
    }
}

impl<const N: usize> From<[EthRpcModule; N]> for RpcModuleSelection {
    fn from(s: [EthRpcModule; N]) -> Self {
        Self::Selection(s.iter().copied().collect())
    }
}

impl<'a> FromIterator<&'a EthRpcModule> for RpcModuleSelection {
    fn from_iter<I>(iter: I) -> Self
    where I: IntoIterator<Item = &'a EthRpcModule> {
        iter.into_iter().copied().collect()
    }
}

impl FromIterator<EthRpcModule> for RpcModuleSelection {
    fn from_iter<I>(iter: I) -> Self
    where I: IntoIterator<Item = EthRpcModule> {
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
            "none" | "None" => Ok(Self::Selection(Default::default())),
            "standard" | "Standard" => Ok(Self::Standard),
            "evm" | "Evm" => Ok(Self::Evm),
            _ => Self::try_from_selection(modules).map_err(|e| e.to_string()),
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
pub enum EthRpcModule {
    /// `admin_` module
    // Admin,
    /// `debug_` module
    Debug,
    /// `eth_` module
    Eth,
    /// `net_` module
    Net,
    /// `trace_` module
    Trace,
    /// `txpool_` module
    Txpool,
    /// `web3_` module
    Web3,
    /// `rpc_` module
    Rpc,
    /// `parity_` module
    Parity,
}

impl EthRpcModule {
    /// Returns the number of variants in the enum
    pub const fn variant_count() -> usize {
        <Self as VariantArray>::VARIANTS.len()
    }

    /// Returns all variant names of the enum
    pub const fn all_variant_names() -> &'static [&'static str] {
        <Self as VariantNames>::VARIANTS
    }

    /// Returns all variants of the enum
    pub const fn all_variants() -> &'static [Self] {
        <Self as VariantArray>::VARIANTS
    }

    /// Returns all variants of the enum
    pub fn modules() -> impl IntoIterator<Item = Self> {
        use strum::IntoEnumIterator;
        Self::iter()
    }

    /// Returns the string representation of the module.
    #[inline]
    pub fn as_str(&self) -> &'static str { self.into() }
}

impl FromStr for EthRpcModule {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            // "admin" => Self::Admin,
            "debug" => Self::Debug,
            "eth" => Self::Eth,
            "net" => Self::Net,
            "trace" => Self::Trace,
            "txpool" => Self::Txpool,
            "web3" => Self::Web3,
            "rpc" => Self::Rpc,
            "parity" => Self::Parity,
            _ => return Err(ParseError::VariantNotFound),
        })
    }
}

impl TryFrom<&str> for EthRpcModule {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
        FromStr::from_str(s)
    }
}

impl fmt::Display for EthRpcModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_ref())
    }
}

impl Serialize for EthRpcModule {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_str(self.as_ref())
    }
}
