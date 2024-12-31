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

//! Stratum protocol implementation for Conflux clients

use keccak_hash as hash;
use log::{debug, trace, warn};

mod traits;

pub use traits::{Error, JobDispatcher, PushWorkHandler, ServiceConfiguration};

use jsonrpc_core::{
    to_value, Compatibility, IoDelegate, MetaIoHandler, Metadata, Params, Value,
};
use jsonrpc_tcp_server::{
    Dispatcher, MetaExtractor, PushMessageError, RequestContext,
    Server as JsonRpcServer, ServerBuilder as JsonRpcServerBuilder,
};
use std::sync::Arc;

use crate::traits::Error::InvalidSolution;
use cfx_types::H256;
use hash::keccak;
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

type RpcResult = Result<jsonrpc_core::Value, jsonrpc_core::Error>;

const NOTIFY_COUNTER_INITIAL: u32 = 16;

/// Container which owns rpc server and stratum implementation
pub struct Stratum {
    /// RPC server
    ///
    /// It is an `Option` so it can be easily closed and released during `drop`
    /// phase
    rpc_server: Option<JsonRpcServer>,
    /// stratum protocol implementation
    ///
    /// It is owned by a container and rpc server
    implementation: Arc<StratumImpl>,
    /// Message dispatcher (tcp/ip service)
    ///
    /// Used to push messages to peers
    tcp_dispatcher: Dispatcher,
}

impl Stratum {
    pub fn start(
        addr: &SocketAddr, dispatcher: Arc<dyn JobDispatcher>,
        secret: Option<H256>,
    ) -> Result<Arc<Stratum>, Error> {
        let implementation = Arc::new(StratumImpl {
            dispatcher,
            workers: Arc::new(RwLock::default()),
            secret,
            notify_counter: RwLock::new(NOTIFY_COUNTER_INITIAL),
        });

        let mut delegate = IoDelegate::<StratumImpl, SocketMetadata>::new(
            implementation.clone(),
        );
        delegate
            .add_method_with_meta("mining.subscribe", StratumImpl::subscribe);
        delegate.add_method_with_meta("mining.submit", StratumImpl::submit);
        let mut handler = MetaIoHandler::<SocketMetadata>::with_compatibility(
            Compatibility::Both,
        );
        handler.extend_with(delegate);

        let server_builder = JsonRpcServerBuilder::new(handler);
        let tcp_dispatcher = server_builder.dispatcher();
        let server_builder = server_builder.session_meta_extractor(
            PeerMetaExtractor::new(tcp_dispatcher.clone()),
        );
        let server = server_builder.start(addr)?;

        let stratum = Arc::new(Stratum {
            rpc_server: Some(server),
            implementation,
            tcp_dispatcher,
        });

        Ok(stratum)
    }
}

impl PushWorkHandler for Stratum {
    fn push_work_all(&self, payload: String) -> Result<(), Error> {
        debug!("Pushing job {} to miners", payload);

        self.implementation
            .push_work_all(payload, &self.tcp_dispatcher)
    }
}

impl Drop for Stratum {
    fn drop(&mut self) {
        // shut down rpc server
        if let Some(server) = self.rpc_server.take() {
            server.close()
        }
    }
}

struct StratumImpl {
    /// Payload manager
    dispatcher: Arc<dyn JobDispatcher>,
    /// Authorized workers (socket - worker_id)
    workers: Arc<RwLock<HashMap<SocketAddr, String>>>,
    /// Secret if any
    secret: Option<H256>,
    /// Dispatch notify couinter
    notify_counter: RwLock<u32>,
}

impl StratumImpl {
    /// rpc method `mining.subscribe`
    fn subscribe(&self, params: Params, meta: SocketMetadata) -> RpcResult {
        params.parse::<(String, String)>().map(|(worker_id, secret)|{
            if let Some(valid_secret) = self.secret {
                let hash = keccak(secret);
                if hash != valid_secret {
                    return to_value(&false);
                }
            }
            debug!(target: "stratum", "New worker #{} registered", worker_id);
            self.workers.write().insert(meta.addr().clone(), worker_id);
            to_value(true)
        }).map(|v| v.expect("Only true/false is returned and it's always serializable; qed"))
    }

    /// rpc method `mining.submit`
    fn submit(&self, params: Params, _meta: SocketMetadata) -> RpcResult {
        Ok(Value::Array(match params {
            Params::Array(vals) => {
                // first two elements are service messages (worker_id & job_id)
                match self.dispatcher.submit(
                    vals.iter()
                        .filter_map(|val| match *val {
                            Value::String(ref s) => Some(s.to_owned()),
                            _ => None,
                        })
                        .collect::<Vec<String>>(),
                ) {
                    Ok(()) => vec![to_value(true).expect("serializable")],
                    Err(InvalidSolution(msg)) => {
                        // When we have invalid solution, we propagate the
                        // reason to the client
                        warn!("Error because of invalid solution: {:?}", msg);
                        vec![
                            to_value(false).expect("serializable"),
                            to_value(msg).expect("serializable"),
                        ]
                    }
                    Err(submit_err) => {
                        warn!("Error while submitting share: {:?}", submit_err);
                        vec![to_value(false).expect("serializable")]
                    }
                }
            }
            _ => {
                trace!(target: "stratum", "Invalid submit work format {:?}", params);
                vec![to_value(false).expect("serializable")]
            }
        }))
    }

    fn push_work_all(
        &self, payload: String, tcp_dispatcher: &Dispatcher,
    ) -> Result<(), Error> {
        let hup_peers = {
            let workers = self.workers.read();
            let next_request_id = {
                let mut counter = self.notify_counter.write();
                if *counter == ::std::u32::MAX {
                    *counter = NOTIFY_COUNTER_INITIAL;
                } else {
                    *counter += 1
                }
                *counter
            };

            let mut hup_peers = HashSet::with_capacity(0); // most of the cases won't be needed, hence avoid allocation
            let workers_msg = format!("{{ \"id\": {}, \"method\": \"mining.notify\", \"params\": {} }}", next_request_id, payload);
            trace!(target: "stratum", "Pushing work for {} workers (payload: '{}')", workers.len(), &workers_msg);
            for (ref addr, worker_id) in workers.iter() {
                trace!(target: "stratum", "Pushing work to {} at addr {}", &worker_id, &addr);
                match tcp_dispatcher.push_message(addr, workers_msg.clone()) {
                    Err(PushMessageError::NoSuchPeer) => {
                        debug!(target: "stratum", "Worker no longer connected: {} addr {}", &worker_id, &addr);
                        hup_peers.insert(**addr);
                    }
                    Err(e) => {
                        warn!(target: "stratum", "Unexpected transport error: {:?}", e);
                    }
                    Ok(_) => {}
                }
            }
            hup_peers
        };

        if !hup_peers.is_empty() {
            let mut workers = self.workers.write();
            for hup_peer in hup_peers {
                workers.remove(&hup_peer);
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct SocketMetadata {
    addr: SocketAddr,
    // with the new version of jsonrpc-core, SocketMetadata
    // won't have to implement default, so this field will not
    // have to be an Option
    #[allow(dead_code)]
    tcp_dispatcher: Option<Dispatcher>,
}

impl Default for SocketMetadata {
    fn default() -> Self {
        SocketMetadata {
            addr: "0.0.0.0:0".parse().unwrap(),
            tcp_dispatcher: None,
        }
    }
}

impl SocketMetadata {
    pub fn addr(&self) -> &SocketAddr { &self.addr }
}

impl Metadata for SocketMetadata {}

pub struct PeerMetaExtractor {
    tcp_dispatcher: Dispatcher,
}

impl PeerMetaExtractor {
    fn new(tcp_dispatcher: Dispatcher) -> Self {
        PeerMetaExtractor { tcp_dispatcher }
    }
}

impl MetaExtractor<SocketMetadata> for PeerMetaExtractor {
    fn extract(&self, context: &RequestContext) -> SocketMetadata {
        SocketMetadata {
            addr: context.peer_addr,
            tcp_dispatcher: Some(self.tcp_dispatcher.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Shutdown, SocketAddr},
        sync::Arc,
    };
    use tokio02::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        runtime::Runtime,
        time::delay_for,
    };

    pub struct VoidManager;

    impl JobDispatcher for VoidManager {
        fn submit(&self, _payload: Vec<String>) -> Result<(), Error> { Ok(()) }
    }

    fn dummy_request(addr: &SocketAddr, data: &str) -> Vec<u8> {
        let mut runtime = Runtime::new()
            .expect("Tokio Runtime should be created with no errors");

        runtime.block_on(async {
            let mut stream = TcpStream::connect(addr)
                .await
                .expect("Should connect to server");

            let mut data_vec = data.as_bytes().to_vec();
            data_vec.extend(b"\n");

            stream
                .write_all(&data_vec)
                .await
                .expect("Should write data to stream");

            stream
                .shutdown(Shutdown::Write)
                .expect("Should shutdown write half");

            let mut read_buf = Vec::with_capacity(2048);
            stream
                .read_to_end(&mut read_buf)
                .await
                .expect("Should read data from stream");

            read_buf
        })
    }

    #[test]
    fn can_be_started() {
        let stratum = Stratum::start(
            &"127.0.0.1:19980".parse().unwrap(),
            Arc::new(VoidManager),
            None,
        );
        assert!(stratum.is_ok());
    }

    struct DummyManager {
        initial_payload: String,
    }

    impl DummyManager {
        fn build() -> DummyManager {
            DummyManager {
                initial_payload: r#"[ "dummy payload" ]"#.to_owned(),
            }
        }

        fn of_initial(mut self, new_initial: &str) -> DummyManager {
            self.initial_payload = new_initial.to_owned();
            self
        }
    }

    impl JobDispatcher for DummyManager {
        fn submit(&self, _payload: Vec<String>) -> Result<(), Error> { Ok(()) }
    }

    fn terminated_str(origin: &'static str) -> String {
        let mut s = String::new();
        s.push_str(origin);
        s.push_str("\n");
        s
    }

    #[test]
    fn can_subscribe() {
        let addr = "127.0.0.1:19970".parse().unwrap();
        let stratum = Stratum::start(
            &addr,
            Arc::new(
                DummyManager::build()
                    .of_initial(r#"["dummy autorize payload"]"#),
            ),
            None,
        )
        .expect("There should be no error starting stratum");

        let request = r#"{"jsonrpc": "2.0", "method": "mining.subscribe", "params": ["miner1", ""], "id": 1}"#;
        let response =
            String::from_utf8(dummy_request(&addr, request)).unwrap();

        assert_eq!(
            terminated_str(r#"{"jsonrpc":"2.0","result":true,"id":1}"#),
            response
        );
        assert_eq!(1, stratum.implementation.workers.read().len());
    }

    #[test]
    fn can_push_work() {
        let _ = ::env_logger::try_init();

        let addr = "127.0.0.1:19995".parse().unwrap();
        let stratum = Stratum::start(
            &addr,
            Arc::new(
                DummyManager::build()
                    .of_initial(r#"["dummy autorize payload"]"#),
            ),
            None,
        )
        .expect("There should be no error starting stratum");

        let mut auth_request =
            r#"{"jsonrpc": "2.0", "method": "mining.subscribe", "params": ["miner1", ""], "id": 1}"#
            .as_bytes()
            .to_vec();
        auth_request.extend(b"\n");

        let auth_response = "{\"jsonrpc\":\"2.0\",\"result\":true,\"id\":1}\n";

        let mut runtime = Runtime::new()
            .expect("Tokio Runtime should be created with no errors");

        let response = runtime.block_on(async {
            let mut stream = TcpStream::connect(&addr)
                .await
                .expect("Should connect to server");

            // Write auth request
            stream
                .write_all(&auth_request)
                .await
                .expect("Should write auth request");

            // Read auth response
            let mut read_buf0 = vec![0u8; auth_response.len()];
            stream
                .read_exact(&mut read_buf0)
                .await
                .expect("Should read auth response");

            assert_eq!(String::from_utf8(read_buf0).unwrap(), auth_response);
            trace!(target: "stratum", "Received authorization confirmation");

            // Wait a bit
            delay_for(std::time::Duration::from_millis(100)).await;

            // Push work
            trace!(target: "stratum", "Pusing work to peers");
            stratum
                .push_work_all(r#"{ "00040008", "100500" }"#.to_owned())
                .expect("Pushing work should produce no errors");

            // Wait a bit
            delay_for(std::time::Duration::from_millis(100)).await;

            trace!(target: "stratum", "Ready to read work from server");
            delay_for(std::time::Duration::from_millis(100)).await;

            stream
                .shutdown(Shutdown::Write)
                .expect("Should shutdown write half");

            // Read work response
            let mut read_buf1 = Vec::with_capacity(2048);
            stream
                .read_to_end(&mut read_buf1)
                .await
                .expect("Should read work response");

            trace!(target: "stratum", "Received work from server");
            read_buf1
        });

        let response =
            String::from_utf8(response).expect("Response should be utf-8");

        assert_eq!(
            "{ \"id\": 17, \"method\": \"mining.notify\", \"params\": { \"00040008\", \"100500\" } }\n",
            response
        );
    }
}
