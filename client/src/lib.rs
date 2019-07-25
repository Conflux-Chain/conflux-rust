// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(deprecated)]
use jsonrpc_http_server as http;
use jsonrpc_tcp_server as tcp;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

#[macro_use]
mod config_macro;
pub mod archive;
pub mod configuration;
mod rpc;
#[cfg(test)]
mod tests;

/// Used in Genesis author to indicate testnet version
/// Increase by one for every test net reset
const TESTNET_VERSION: &'static str =
    "000000000000000000000000000000000000000a";
