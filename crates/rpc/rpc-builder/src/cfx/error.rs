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
use super::CfxRpcModule;
use std::{
    collections::HashSet,
    io::{self, ErrorKind},
    net::SocketAddr,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ServerKind {
    Http(SocketAddr),
    WS(SocketAddr),
    WsHttp(SocketAddr),
}

impl ServerKind {
    pub const fn flags(&self) -> &'static str {
        match self {
            Self::Http(_) => "--http.port",
            Self::WS(_) => "--ws.port",
            Self::WsHttp(_) => "--ws.port and --http.port",
        }
    }
}

impl std::fmt::Display for ServerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(addr) => write!(f, "{addr} (HTTP-RPC server)"),
            Self::WS(addr) => write!(f, "{addr} (WS-RPC server)"),
            Self::WsHttp(addr) => write!(f, "{addr} (WS-HTTP-RPC server)"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Failed to start {kind} server: {error}")]
    ServerError { kind: ServerKind, error: io::Error },
    #[error("address {kind} is already in use (os error 98). Choose a different port using {}", kind.flags())]
    AddressAlreadyInUse { kind: ServerKind, error: io::Error },
    #[error(transparent)]
    WsHttpSamePortError(#[from] WsHttpSamePortError),
    #[error("{0}")]
    Custom(String),
}

impl RpcError {
    pub fn server_error(io_error: io::Error, kind: ServerKind) -> Self {
        if io_error.kind() == ErrorKind::AddrInUse {
            return Self::AddressAlreadyInUse {
                kind,
                error: io_error,
            };
        }
        Self::ServerError {
            kind,
            error: io_error,
        }
    }
}

#[derive(Debug)]
pub struct ConflictingModules {
    pub overlap: HashSet<CfxRpcModule>,
    pub http_not_ws: HashSet<CfxRpcModule>,
    pub ws_not_http: HashSet<CfxRpcModule>,
}

impl std::fmt::Display for ConflictingModules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "different API modules for HTTP and WS on the same port is currently not supported: \
             Overlap: {:?}, \
             HTTP modules not present in WS: {:?} \
             WS modules not present in HTTP: {:?}
             ",
            self.overlap, self.http_not_ws, self.ws_not_http
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WsHttpSamePortError {
    #[error(
        "CORS domains for HTTP and WS are different, but they are on the same port: \
         HTTP: {http_cors_domains:?}, WS: {ws_cors_domains:?}"
    )]
    ConflictingCorsDomains {
        http_cors_domains: Option<String>,
        ws_cors_domains: Option<String>,
    },
    #[error("{0}")]
    ConflictingModules(Box<ConflictingModules>),
}
