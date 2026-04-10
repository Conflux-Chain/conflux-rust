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

use cfx_types::H256;
use hash::keccak;
use jsonrpsee::{
    core::RpcResult,
    server::RpcModule,
    types::{ErrorObjectOwned, Id, Params, Request, Response, ResponsePayload},
};
use parking_lot::RwLock;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock as AsyncRwLock},
};

const NOTIFY_COUNTER_INITIAL: u32 = 16;

/// Container which owns rpc server and stratum implementation
pub struct Stratum {
    /// stratum protocol implementation
    implementation: Arc<StratumImpl>,
    /// Shutdown sender
    shutdown_tx: mpsc::Sender<()>,
}

impl Stratum {
    pub async fn start(
        addr: &SocketAddr, dispatcher: Arc<dyn JobDispatcher>,
        secret: Option<H256>,
    ) -> Result<Arc<Stratum>, Error> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        let implementation = Arc::new(StratumImpl {
            dispatcher,
            secret,
            notify_counter: RwLock::new(NOTIFY_COUNTER_INITIAL),
            workers: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::default()),
        });

        let implementation_for_methods = implementation.clone();
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Io(e.to_string()))?;
        debug!("Stratum server started on {}", local_addr);

        // Spawn server task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                debug!("Accepted connection from {}", peer_addr);
                                let impl_for_methods = implementation_for_methods.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(stream, peer_addr, impl_for_methods).await {
                                        debug!("Connection error for {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("Failed to accept connection: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Shutting down stratum server");
                        break;
                    }
                }
            }
        });

        let stratum = Arc::new(Stratum {
            implementation,
            shutdown_tx,
        });

        Ok(stratum)
    }

    pub async fn stop(&self) -> Result<(), Error> {
        self.shutdown_tx.send(()).await.map_err(|e| {
            Error::Io(format!("Failed to send shutdown signal: {}", e))
        })
    }
}

impl PushWorkHandler for Stratum {
    fn push_work_all(&self, payload: String) -> Result<(), Error> {
        debug!("Pushing job {} to miners", payload);
        self.implementation.push_work_all(payload)
    }
}

async fn handle_connection(
    stream: TcpStream, peer_addr: SocketAddr,
    implementation_for_methods: Arc<StratumImpl>,
) -> io::Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(AsyncRwLock::new(BufWriter::new(writer)));

    let implementation = implementation_for_methods.clone();

    // Create RPC module with peer_addr as context
    let module =
        StratumImpl::build_rpc_methods(implementation_for_methods, peer_addr);
    let methods = Arc::new(module);

    // Register connection for push notifications
    let (tx, mut rx) = mpsc::channel::<String>(100);
    implementation.connections.write().insert(peer_addr, tx);

    // Spawn task to handle push notifications
    let writer_clone = writer.clone();
    let push_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut writer = writer_clone.write().await;
            if let Err(e) = writer.write_all(msg.as_bytes()).await {
                debug!("Failed to write notification: {}", e);
                break;
            }
            if let Err(e) = writer.write_all(b"\n").await {
                debug!("Failed to write newline: {}", e);
                break;
            }
            if let Err(e) = writer.flush().await {
                debug!("Failed to flush: {}", e);
                break;
            }
        }
    });

    let mut line = String::new();

    loop {
        line.clear();

        let n = reader.read_line(&mut line).await?;

        if n == 0 {
            debug!("Connection closed by peer {}", peer_addr);
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        debug!("Received request from {}: {}", peer_addr, trimmed);

        // Parse the JSON-RPC request
        let request: Result<Request, _> = serde_json::from_str(trimmed);

        let response = match request {
            Ok(req) => {
                let id = req.id.clone();
                let method = req.method.clone();

                // Call the method
                match methods.raw_json_request(&trimmed, 1).await {
                    Ok((response_raw, _rx)) => {
                        let response_str = response_raw.get();
                        debug!("Response for {}: {}", method, response_str);
                        response_str.to_string()
                    }
                    Err(e) => {
                        warn!("Method call failed for {}: {}", method, e);
                        let error_response: Response<Value> = Response::new(
                            ResponsePayload::error(ErrorObjectOwned::owned(
                                -32603,
                                "Internal error",
                                Some(e.to_string()),
                            )),
                            id,
                        );
                        serde_json::to_string(&error_response).unwrap()
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse request: {}", e);
                let error_response: Response<Value> = Response::new(
                    ResponsePayload::error(ErrorObjectOwned::owned(
                        -32700,
                        "Parse error",
                        Some(e.to_string()),
                    )),
                    Id::Null,
                );
                serde_json::to_string(&error_response).unwrap()
            }
        };

        // Write response
        let mut writer = writer.write().await;
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    // Clean up on disconnect
    push_task.abort();
    implementation.connections.write().remove(&peer_addr);
    // Note: We don't remove from workers map here to allow reconnection with
    // same worker_id Workers are only removed when push_work_all detects a
    // failed connection

    Ok(())
}

struct StratumImpl {
    /// Payload manager
    dispatcher: Arc<dyn JobDispatcher>,
    /// Secret if any
    secret: Option<H256>,
    /// Dispatch notify counter
    notify_counter: RwLock<u32>,
    // socket addr to worker_id mapping for active workers
    workers: Arc<RwLock<HashMap<SocketAddr, String>>>,
    /// Active connections for pushing notifications
    connections: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<String>>>>,
}

impl StratumImpl {
    /// rpc method `mining.subscribe`
    async fn subscribe(
        &self, params: Params<'_>, peer_addr: SocketAddr,
    ) -> RpcResult<bool> {
        let params_vec: Vec<String> = params.parse()?;

        if params_vec.len() < 2 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "Invalid params: expected [worker_id, secret]",
                None::<()>,
            ));
        }

        let worker_id = &params_vec[0];
        let secret = &params_vec[1];

        if let Some(valid_secret) = self.secret {
            let hash = keccak(secret);
            if hash != valid_secret {
                return Ok(false);
            }
        }

        let mut workers = self.workers.write();
        workers.insert(peer_addr, worker_id.clone());

        Ok(true)
    }

    /// rpc method `mining.submit`
    async fn submit(&self, params: Params<'_>) -> RpcResult<Vec<Value>> {
        let params_vec: Vec<String> = params.parse()?;

        match self.dispatcher.submit(params_vec) {
            Ok(()) => Ok(vec![Value::Bool(true)]),
            Err(crate::traits::Error::InvalidSolution(msg)) => {
                warn!("Error because of invalid solution: {:?}", msg);
                Ok(vec![Value::Bool(false), Value::String(msg)])
            }
            Err(submit_err) => {
                warn!("Error while submitting share: {:?}", submit_err);
                Ok(vec![Value::Bool(false)])
            }
        }
    }

    fn push_work_all(&self, payload: String) -> Result<(), Error> {
        let connections = self.connections.read();
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

        let mut hup_peers = HashSet::with_capacity(0);
        let workers_msg = format!(
            r#"{{"id":{},"method":"mining.notify","params":{}}}"#,
            next_request_id, payload
        );

        trace!(target: "stratum", "Pushing work for {} workers (payload: '{}')", workers.len(), &workers_msg);

        for (addr, worker_id) in workers.iter() {
            trace!(target: "stratum", "Pushing work to addr {} worker_id {}", &addr, &worker_id);

            if let Some(tx) = connections.get(addr) {
                if let Err(e) = tx.try_send(workers_msg.clone()) {
                    debug!(target: "stratum", "Worker no longer connected: addr {}, error: {:?}", &addr, e);
                    hup_peers.insert(*addr);
                }
            } else {
                debug!(target: "stratum", "Worker has no active connection: addr {}", &addr);
                hup_peers.insert(*addr);
            }
        }

        drop(connections);
        drop(workers);

        if !hup_peers.is_empty() {
            let mut connections = self.connections.write();
            let mut workers = self.workers.write();
            for hup_peer in hup_peers {
                connections.remove(&hup_peer);
                workers.remove(&hup_peer);
            }
        }

        Ok(())
    }

    fn build_rpc_methods(
        implementation_for_methods: Arc<StratumImpl>, peer_addr: SocketAddr,
    ) -> RpcModule<SocketAddr> {
        let mut module = RpcModule::new(peer_addr);

        // Register mining.subscribe method
        {
            let implementation = implementation_for_methods.clone();
            module
                .register_async_method(
                    "mining.subscribe",
                    move |params: Params, _ctx: Arc<SocketAddr>, _ext| {
                        let implementation = implementation.clone();
                        let peer_addr = *(_ctx.as_ref());
                        async move {
                            implementation.subscribe(params, peer_addr).await
                        }
                    },
                )
                .expect("successfully register mining.subscribe method");
        }

        // Register mining.submit method
        {
            let implementation = implementation_for_methods.clone();
            module
                .register_async_method(
                    "mining.submit",
                    move |params: Params, _ctx: Arc<SocketAddr>, _ext| {
                        let implementation = implementation.clone();
                        async move { implementation.submit(params).await }
                    },
                )
                .expect("successfully register mining.submit method");
        }

        module
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::sleep,
    };

    pub struct VoidManager;

    impl JobDispatcher for VoidManager {
        fn submit(&self, _payload: Vec<String>) -> Result<(), Error> { Ok(()) }
    }

    async fn dummy_request(addr: &SocketAddr, data: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("Should connect to server");

        let mut data_vec = data.as_bytes().to_vec();
        data_vec.extend(b"\n");

        stream
            .write_all(&data_vec)
            .await
            .expect("Should write data to stream");

        stream.shutdown().await.expect("Should shutdown write half");

        let mut read_buf = Vec::with_capacity(2048);
        stream
            .read_to_end(&mut read_buf)
            .await
            .expect("Should read data from stream");

        read_buf
    }

    #[tokio::test]
    async fn can_be_started() {
        let stratum = Stratum::start(
            &"127.0.0.1:19980".parse().unwrap(),
            Arc::new(VoidManager),
            None,
        )
        .await;
        assert!(stratum.is_ok());
        if let Ok(s) = stratum {
            let _ = s.stop().await;
        }
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

    #[tokio::test]
    async fn can_subscribe() {
        let addr = "127.0.0.1:19970".parse().unwrap();
        let stratum = Stratum::start(
            &addr,
            Arc::new(
                DummyManager::build()
                    .of_initial(r#"["dummy autorize payload"]"#),
            ),
            None,
        )
        .await
        .expect("There should be no error starting stratum");

        let request = r#"{"jsonrpc": "2.0", "method": "mining.subscribe", "params": ["miner1", ""], "id": 1}"#;
        let response =
            String::from_utf8(dummy_request(&addr, request).await).unwrap();

        // Parse and compare JSON instead of string comparison
        let response_json: Value =
            serde_json::from_str(response.trim()).unwrap();
        let expected_json: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","result":true,"id":1}"#)
                .unwrap();
        assert_eq!(expected_json, response_json);
        assert_eq!(1, stratum.implementation.workers.read().len());

        let _ = stratum.stop().await;
    }

    #[tokio::test]
    async fn can_push_work() {
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
        .await
        .expect("There should be no error starting stratum");

        let mut auth_request =
            r#"{"jsonrpc": "2.0", "method": "mining.subscribe", "params": ["miner1", ""], "id": 1}"#
            .as_bytes()
            .to_vec();
        auth_request.extend(b"\n");

        let auth_response = "{\"jsonrpc\":\"2.0\",\"result\":true,\"id\":1}\n";

        let response = {
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

            // Parse and compare JSON instead of string comparison
            let response_json: Value = serde_json::from_str(
                String::from_utf8(read_buf0).unwrap().trim(),
            )
            .unwrap();
            let expected_json: Value =
                serde_json::from_str(auth_response).unwrap();
            assert_eq!(expected_json, response_json);
            trace!(target: "stratum", "Received authorization confirmation");

            // Wait a bit
            sleep(Duration::from_millis(100)).await;

            // Push work
            trace!(target: "stratum", "Pushing work to peers");
            stratum
                .push_work_all(r#"{ "00040008", "100500" }"#.to_owned())
                .expect("Pushing work should produce no errors");

            // Wait a bit
            sleep(Duration::from_millis(100)).await;

            trace!(target: "stratum", "Ready to read work from server");
            sleep(Duration::from_millis(100)).await;

            stream.shutdown().await.expect("Should shutdown write half");

            // Read work response
            let mut read_buf1 = Vec::with_capacity(2048);
            stream
                .read_to_end(&mut read_buf1)
                .await
                .expect("Should read work response");

            trace!(target: "stratum", "Received work from server");
            read_buf1
        };

        let response =
            String::from_utf8(response).expect("Response should be utf-8");

        assert_eq!(
            r#"{"id":17,"method":"mining.notify","params":{ "00040008", "100500" }}"#.to_owned() + "\n",
            response
        );

        let _ = stratum.stop().await;
    }

    #[tokio::test]
    async fn test_can_subscribe_with_secret() {
        let addr = "127.0.0.1:19971".parse().unwrap();
        let secret_str = "test_secret";
        let secret_hash = keccak(secret_str);

        let stratum =
            Stratum::start(&addr, Arc::new(VoidManager), Some(secret_hash))
                .await
                .expect("Should start stratum with secret");

        let request = format!(
            r#"{{"jsonrpc": "2.0", "method": "mining.subscribe", "params": ["miner1", "{}"], "id": 1}}"#,
            secret_str
        );

        let response =
            String::from_utf8(dummy_request(&addr, &request).await).unwrap();

        // Parse and compare JSON instead of string comparison
        let response_json: Value =
            serde_json::from_str(response.trim()).unwrap();
        let expected_json: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","result":true,"id":1}"#)
                .unwrap();
        assert_eq!(expected_json, response_json);
        assert_eq!(1, stratum.implementation.workers.read().len());

        let _ = stratum.stop().await;
    }

    #[tokio::test]
    async fn test_can_subscribe_with_invalid_secret() {
        let addr = "127.0.0.1:19972".parse().unwrap();
        let secret_str = "test_secret";
        let secret_hash = keccak(secret_str);
        let stratum =
            Stratum::start(&addr, Arc::new(VoidManager), Some(secret_hash))
                .await
                .expect("Should start stratum with secret");

        let request = r#"{"jsonrpc": "2.0", "method": "mining.subscribe", "params": ["miner1", "wrong_secret"], "id": 2}"#;
        let response =
            String::from_utf8(dummy_request(&addr, request).await).unwrap();

        // Parse and compare JSON instead of string comparison
        let response_json: Value =
            serde_json::from_str(response.trim()).unwrap();
        let expected_json: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","result":false,"id":2}"#)
                .unwrap();
        assert_eq!(expected_json, response_json);
        assert_eq!(0, stratum.implementation.workers.read().len());

        let _ = stratum.stop().await;
    }

    #[tokio::test]
    async fn test_can_submit() {
        let addr = "127.0.0.1:19973".parse().unwrap();

        struct TestDispatcher {
            submissions: Arc<RwLock<Vec<Vec<String>>>>,
        }

        impl JobDispatcher for TestDispatcher {
            fn submit(&self, payload: Vec<String>) -> Result<(), Error> {
                self.submissions.write().push(payload);
                Ok(())
            }
        }

        let test_dispatcher = TestDispatcher {
            submissions: Arc::new(RwLock::new(Vec::new())),
        };
        let submissions = test_dispatcher.submissions.clone();

        let stratum = Stratum::start(&addr, Arc::new(test_dispatcher), None)
            .await
            .expect("Should start stratum");

        // subscribe
        let subscribe_request = r#"{"jsonrpc": "2.0", "method": "mining.subscribe", "params": ["miner1", ""], "id": 1}"#;
        let subscribe_response =
            String::from_utf8(dummy_request(&addr, subscribe_request).await)
                .unwrap();

        // Parse and compare JSON instead of string comparison
        let response_json: Value =
            serde_json::from_str(subscribe_response.trim()).unwrap();
        let expected_json: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","result":true,"id":1}"#)
                .unwrap();
        assert_eq!(expected_json, response_json);

        // submit
        let submit_request = r#"{"jsonrpc": "2.0", "method": "mining.submit", "params": ["test_miner", "job_id", "0x1", "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"], "id": 2}"#;

        let submit_response =
            String::from_utf8(dummy_request(&addr, submit_request).await)
                .unwrap();

        // Parse and compare JSON instead of string comparison
        let response_json: Value =
            serde_json::from_str(submit_response.trim()).unwrap();
        let expected_json: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","result":[true],"id":2}"#)
                .unwrap();
        assert_eq!(expected_json, response_json);

        assert_eq!(1, submissions.read().len());
        assert_eq!(
            vec![
            "test_miner",
            "job_id",
            "0x1",
            "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ],
            submissions.read()[0]
        );

        assert_eq!(1, stratum.implementation.workers.read().len());

        let _ = stratum.stop().await;
    }
}
