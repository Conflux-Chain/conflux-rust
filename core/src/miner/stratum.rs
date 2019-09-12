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

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Client-side stratum job dispatcher and mining notifier handler

use crate::{miner::work_notify::NotifyWork, pow::ProofOfWorkSolution};
use cfx_stratum::{
    Error as StratumServiceError, JobDispatcher, PushWorkHandler,
    Stratum as StratumService,
};
use cfx_types::H256;
use parking_lot::Mutex;
use std::{
    fmt,
    net::{AddrParseError, SocketAddr},
    sync::{mpsc, Arc},
};

/// Configures stratum server options.
#[derive(Debug, PartialEq, Clone)]
pub struct Options {
    /// Network address
    pub listen_addr: String,
    /// Port
    pub port: u16,
    /// Secret for peers
    pub secret: Option<H256>,
}

fn clean_0x(s: &str) -> &str {
    if s.starts_with("0x") {
        &s[2..]
    } else {
        s
    }
}

struct SubmitPayload {
    nonce: u64,
    pow_hash: H256,
}

impl SubmitPayload {
    fn from_args(payload: Vec<String>) -> Result<Self, PayloadError> {
        if payload.len() != 2 {
            return Err(PayloadError::ArgumentsAmountUnexpected(payload.len()));
        }

        let nonce = match clean_0x(&payload[0]).parse::<u64>() {
            Ok(nonce) => nonce,
            Err(e) => {
                warn!(target: "stratum", "submit_work ({}): invalid nonce ({:?})", &payload[0], e);
                return Err(PayloadError::InvalidNonce(payload[0].clone()));
            }
        };

        let pow_hash = match clean_0x(&payload[1]).parse::<H256>() {
            Ok(pow_hash) => pow_hash,
            Err(e) => {
                warn!(target: "stratum", "submit_work ({}): invalid hash ({:?})", &payload[1], e);
                return Err(PayloadError::InvalidPowHash(payload[1].clone()));
            }
        };

        Ok(SubmitPayload { nonce, pow_hash })
    }
}

#[derive(Debug)]
enum PayloadError {
    ArgumentsAmountUnexpected(usize),
    InvalidNonce(String),
    InvalidPowHash(String),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Job dispatcher for stratum service
pub struct StratumJobDispatcher {
    solution_sender: Mutex<mpsc::Sender<ProofOfWorkSolution>>,
}

impl JobDispatcher for StratumJobDispatcher {
    fn submit(&self, payload: Vec<String>) -> Result<(), StratumServiceError> {
        let payload = SubmitPayload::from_args(payload)
            .map_err(|e| StratumServiceError::Dispatch(e.to_string()))?;

        trace!(
            target: "stratum",
            "submit_work: Decoded: nonce={}, pow_hash={}",
            payload.nonce,
            payload.pow_hash,
        );

        match self.solution_sender.lock().send(ProofOfWorkSolution {
            nonce: payload.nonce,
        }) {
            Ok(_) => {}
            Err(e) => {
                warn!("{}", e);
            }
        }

        Ok(())
    }
}

impl StratumJobDispatcher {
    /// New stratum job dispatcher given the miner and client
    fn new(
        solution_sender: mpsc::Sender<ProofOfWorkSolution>,
    ) -> StratumJobDispatcher {
        StratumJobDispatcher {
            solution_sender: Mutex::new(solution_sender),
        }
    }

    /// Serializes payload for stratum service
    fn payload(&self, pow_hash: H256, boundary: H256) -> String {
        format!(r#"["0x", "0x{:x}","0x{:x}"]"#, pow_hash, boundary)
    }
}

/// Wrapper for dedicated stratum service
pub struct Stratum {
    dispatcher: Arc<StratumJobDispatcher>,
    service: Arc<StratumService>,
}

#[derive(Debug)]
/// Stratum error
pub enum Error {
    /// IPC sockets error
    Service(StratumServiceError),
    /// Invalid network address
    Address(AddrParseError),
}

impl From<StratumServiceError> for Error {
    fn from(service_err: StratumServiceError) -> Error {
        Error::Service(service_err)
    }
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Error { Error::Address(err) }
}

impl NotifyWork for Stratum {
    fn notify(&self, pow_hash: H256, boundary: H256) {
        trace!(target: "stratum", "Notify work");

        self.service.push_work_all(
            self.dispatcher.payload(pow_hash, boundary)
        ).unwrap_or_else(
            |e| warn!(target: "stratum", "Error while pushing work: {:?}", e)
        );
    }
}

impl Stratum {
    /// New stratum job dispatcher, given the miner, client and dedicated
    /// stratum service
    pub fn start(
        options: &Options, solution_sender: mpsc::Sender<ProofOfWorkSolution>,
    ) -> Result<Stratum, Error> {
        use std::net::IpAddr;

        let dispatcher = Arc::new(StratumJobDispatcher::new(solution_sender));

        let stratum_svc = StratumService::start(
            &SocketAddr::new(
                options.listen_addr.parse::<IpAddr>()?,
                options.port,
            ),
            dispatcher.clone(),
            options.secret.clone(),
        )?;

        Ok(Stratum {
            dispatcher,
            service: stratum_svc,
        })
    }
}
