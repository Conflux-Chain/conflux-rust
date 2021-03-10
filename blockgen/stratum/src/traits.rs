// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use cfx_types::H256;
use jsonrpc_tcp_server::PushMessageError;
use std;

#[derive(Debug, Clone)]
pub enum Error {
    NoWork,
    NoWorkers,
    InvalidSolution(String),
    Io(String),
    Tcp(String),
    Dispatch(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<PushMessageError> for Error {
    fn from(err: PushMessageError) -> Self {
        Error::Tcp(format!("Push message error: {:?}", err))
    }
}

/// Interface that can provide pow/blockchain-specific responses for the clients
pub trait JobDispatcher: Send + Sync {
    // miner job result
    fn submit(&self, payload: Vec<String>) -> Result<(), Error>;
}

/// Interface that can handle requests to push job for workers
pub trait PushWorkHandler: Send + Sync {
    /// push the same work package for all workers (`payload`: json of
    /// pow-specific set of work specification)
    fn push_work_all(&self, payload: String) -> Result<(), Error>;
}

pub struct ServiceConfiguration {
    pub io_path: String,
    pub listen_addr: String,
    pub port: u16,
    pub secret: Option<H256>,
}
