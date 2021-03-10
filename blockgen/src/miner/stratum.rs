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

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Client-side stratum job dispatcher and mining notifier handler

use crate::miner::work_notify::NotifyWork;
use cfx_stratum::{
    Error as StratumServiceError, JobDispatcher, PushWorkHandler,
    Stratum as StratumService,
};
use cfx_types::{H256, U256};
use cfxcore::pow::{
    validate, PowComputer, ProofOfWorkProblem, ProofOfWorkSolution,
};
use log::{info, trace, warn};
use parking_lot::Mutex;
use std::{
    collections::HashSet,
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
    worker_id: String,
    nonce: U256,
    pow_hash: H256,
}

impl SubmitPayload {
    fn from_args(payload: Vec<String>) -> Result<Self, PayloadError> {
        if payload.len() != 4 {
            return Err(PayloadError::ArgumentsAmountUnexpected(payload.len()));
        }

        let worker_id = payload[0].clone();

        let nonce = match clean_0x(&payload[2]).parse::<U256>() {
            Ok(nonce) => nonce,
            Err(e) => {
                warn!(target: "stratum", "submit_work ({}): invalid nonce ({:?})", &payload[0], e);
                return Err(PayloadError::InvalidNonce(payload[0].clone()));
            }
        };

        let pow_hash = match clean_0x(&payload[3]).parse::<H256>() {
            Ok(pow_hash) => pow_hash,
            Err(e) => {
                warn!(target: "stratum", "submit_work ({}): invalid hash ({:?})", &payload[1], e);
                return Err(PayloadError::InvalidPowHash(payload[1].clone()));
            }
        };

        Ok(SubmitPayload {
            worker_id,
            nonce,
            pow_hash,
        })
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
    recent_problems: Mutex<Vec<(ProofOfWorkProblem, HashSet<U256>)>>,
    solution_sender: Mutex<mpsc::Sender<ProofOfWorkSolution>>,
    pow: Arc<PowComputer>,
    window_size: usize,
}

impl JobDispatcher for StratumJobDispatcher {
    fn submit(&self, payload: Vec<String>) -> Result<(), StratumServiceError> {
        let payload = SubmitPayload::from_args(payload)
            .map_err(|e| StratumServiceError::Dispatch(e.to_string()))?;

        trace!(
            target: "stratum",
            "submit_work: Decoded: nonce={}, pow_hash={}, worker_id={}",
            payload.nonce,
            payload.pow_hash,
            payload.worker_id,
        );

        let sol = ProofOfWorkSolution {
            nonce: payload.nonce,
        };
        {
            let mut probs = self.recent_problems.lock();
            let mut found = false;
            for (pow_prob, solved_nonce) in probs.iter_mut() {
                if pow_prob.block_hash == payload.pow_hash {
                    if solved_nonce.contains(&sol.nonce) {
                        return Err(StratumServiceError::InvalidSolution(
                            format!(
                                "Problem already solved with nonce = {}! worker_id = {}",
                                sol.nonce, payload.worker_id
                            ).into(),
                        ));
                    } else if validate(self.pow.clone(), pow_prob, &sol) {
                        solved_nonce.insert(sol.nonce);
                        info!(
                            "Stratum worker {} mined a block!",
                            payload.worker_id
                        );
                        found = true;
                    } else {
                        return Err(StratumServiceError::InvalidSolution(
                            format!(
                                "Incorrect Nonce! worker_id = {}!",
                                payload.worker_id
                            )
                            .into(),
                        ));
                    }
                }
            }
            if !found {
                return Err(StratumServiceError::InvalidSolution(
                    format!(
                        "Solution for a stale job! worker_id = {}",
                        payload.worker_id
                    )
                    .into(),
                ));
            }

            match self.solution_sender.lock().send(sol) {
                Ok(_) => {}
                Err(e) => {
                    warn!("{}", e);
                }
            }
        }

        Ok(())
    }
}

impl StratumJobDispatcher {
    /// New stratum job dispatcher given the miner and client
    fn new(
        solution_sender: mpsc::Sender<ProofOfWorkSolution>,
        pow: Arc<PowComputer>, pow_window_size: usize,
    ) -> StratumJobDispatcher {
        StratumJobDispatcher {
            recent_problems: Mutex::new(vec![]),
            solution_sender: Mutex::new(solution_sender),
            pow,
            window_size: pow_window_size,
        }
    }

    fn notify_new_problem(&self, current_problem: &ProofOfWorkProblem) {
        let mut probs = self.recent_problems.lock();
        if probs.len() == self.window_size {
            probs.remove(0);
        }
        probs.push((current_problem.clone(), HashSet::new()));
    }

    /// Serializes payload for stratum service
    fn payload(
        &self, block_height: u64, pow_hash: H256, boundary: U256,
    ) -> String {
        // Now we just fill the job_id as pow_hash. This will be more consistent
        // with the convention.
        format!(
            r#"["0x{:x}", "{}", "0x{:x}","0x{:x}"]"#,
            pow_hash, block_height, pow_hash, boundary
        )
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
    fn from(err: AddrParseError) -> Error {
        Error::Address(err)
    }
}

impl NotifyWork for Stratum {
    fn notify(&self, prob: ProofOfWorkProblem) {
        trace!(target: "stratum", "Notify work");

        self.dispatcher.notify_new_problem(&prob);
        self.service.push_work_all(
            self.dispatcher.payload(prob.block_height, prob.block_hash, prob.boundary)
        ).unwrap_or_else(
            |e| warn!(target: "stratum", "Error while pushing work: {:?}", e)
        );
    }
}

impl Stratum {
    /// New stratum job dispatcher, given the miner, client and dedicated
    /// stratum service
    pub fn start(
        options: &Options, pow: Arc<PowComputer>, pow_window_size: usize,
        solution_sender: mpsc::Sender<ProofOfWorkSolution>,
    ) -> Result<Stratum, Error> {
        use std::net::IpAddr;

        let dispatcher = Arc::new(StratumJobDispatcher::new(
            solution_sender,
            pow,
            pow_window_size,
        ));

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
