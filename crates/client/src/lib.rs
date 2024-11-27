// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![recursion_limit = "512"]
#![allow(deprecated)]

use cfxkey as keylib;

#[macro_use]
mod config_macro;
pub mod accounts;
pub mod archive;
pub mod common;
pub mod configuration;
pub mod full;
pub mod light;
pub mod rpc;

/// Used in Genesis author to indicate test-net/main-net version.
/// Increased for every test-net/main-net release with reset.
const GENESIS_VERSION: &str = "1949000000000000000000000000000000001001";
