// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    alliance_tree_graph::hsb_sync_protocol::sync_protocol::RpcResponse,
    parameters::sync::REQUEST_START_WAITING_TIME,
    sync::{Error, ErrorKind, ProtocolConfiguration},
};
use futures::{channel::oneshot, future::Future};
use network::{NetworkContext, PeerId};
use parking_lot::Mutex;
pub use request_handler::{
    AsAny, Request, RequestHandler, RequestMessage, SynchronizationPeerRequest,
};
use std::{
    cmp::Ordering,
    collections::binary_heap::BinaryHeap,
    sync::Arc,
    time::{Duration, Instant},
};

pub mod request_handler;

#[derive(Debug)]
struct WaitingRequest(Box<dyn Request>, Duration); // (request, delay)

pub struct RequestManager {
    /// Each element is (timeout_time, request, chosen_peer)
    waiting_requests: Mutex<BinaryHeap<TimedWaitingRequest>>,

    /// This is used to handle request_id matching
    request_handler: Arc<RequestHandler>,
}

impl RequestManager {
    pub fn new(protocol_config: &ProtocolConfiguration) -> Self {
        Self {
            waiting_requests: Default::default(),
            request_handler: Arc::new(RequestHandler::new(protocol_config)),
        }
    }

    /// Send a unary rpc request to remote peer `recipient`.
    pub async fn unary_rpc<'a>(
        &'a self, io: &'a dyn NetworkContext, recipient: Option<PeerId>,
        mut request: Box<dyn Request>,
    ) -> impl Future<Output = Result<Box<dyn RpcResponse>, Error>> + 'a
    {
        async move {
            // ask network to fulfill rpc request
            let (res_tx, res_rx) = oneshot::channel();
            request.set_response_notification(res_tx);

            self.request_with_delay(io, request, recipient, None);

            // wait for response
            let response = res_rx.await??;
            Ok(response)
        }
    }

    /// Send request to remote peer with delay mechanism. If failed,
    /// add the request to waiting queue to resend later.
    pub fn request_with_delay(
        &self, io: &dyn NetworkContext, mut request: Box<dyn Request>,
        peer: Option<PeerId>, delay: Option<Duration>,
    )
    {
        // increase delay for resent request.
        let (cur_delay, next_delay) = match delay {
            Some(d) => (d, d + *REQUEST_START_WAITING_TIME),
            None => (*REQUEST_START_WAITING_TIME, *REQUEST_START_WAITING_TIME),
        };

        if peer.is_none() {
            request.notify_error(ErrorKind::RpcCancelledByDisconnection.into());
            return;
        }

        // delay if no peer available or delay required
        if delay.is_some() {
            // todo remove the request if waiting time is too long?
            // E.g. attacker may broadcast many many invalid block hashes,
            // and no peer could return the corresponding block header.
            debug!("request_with_delay: add request to waiting_requests, peer={:?}, request={:?}, delay={:?}", peer, request, cur_delay);
            self.waiting_requests.lock().push(TimedWaitingRequest::new(
                Instant::now() + cur_delay,
                WaitingRequest(request, next_delay),
                peer.unwrap(),
            ));

            return;
        }

        if let Err(mut req) = self.request_handler.send_request(
            io,
            peer,
            request,
            Some(next_delay),
        ) {
            debug!("request_with_delay: send_request fails, peer={:?}, request={:?}", peer, req);
            req.notify_error(ErrorKind::RpcCancelledByDisconnection.into());
        }
    }

    // Match request with given response.
    // No need to let caller handle request resending.
    pub fn match_request(
        &self, io: &dyn NetworkContext, peer_id: PeerId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        self.request_handler.match_request(io, peer_id, request_id)
    }

    pub fn process_timeout_requests(&self, io: &dyn NetworkContext) {
        trace!("process_timeout_requests: start");
        let timeout_requests = self.request_handler.get_timeout_requests(io);
        for mut req in timeout_requests {
            debug!("Timeout requests: {:?}", req);
            req.request.notify_error(ErrorKind::RpcTimeout.into());
        }
    }

    /// Send waiting requests that their backoff delay have passes
    pub fn resend_waiting_requests(&self, io: &dyn NetworkContext) {
        debug!("resend_waiting_requests: start");
        let mut waiting_requests = self.waiting_requests.lock();
        let now = Instant::now();

        while let Some(req) = waiting_requests.pop() {
            if req.time_to_send >= now {
                waiting_requests.push(req);
                break;
            }

            let chosen_peer = req.peer;
            debug!("Send waiting req {:?} to peer={}", req, chosen_peer);

            let WaitingRequest(request, delay) = req.request;
            let next_delay = delay + *REQUEST_START_WAITING_TIME;

            if let Err(mut req) = self.request_handler.send_request(
                io,
                Some(chosen_peer),
                request,
                Some(next_delay),
            ) {
                req.notify_error(ErrorKind::RpcCancelledByDisconnection.into());
            }
        }
    }

    pub fn on_peer_connected(&self, peer: PeerId) {
        self.request_handler.add_peer(peer);
    }

    pub fn on_peer_disconnected(&self, _io: &dyn NetworkContext, peer: PeerId) {
        if let Some(unfinished_requests) =
            self.request_handler.remove_peer(peer)
        {
            for mut msg in unfinished_requests {
                msg.request.notify_error(
                    ErrorKind::RpcCancelledByDisconnection.into(),
                );
            }
        } else {
            debug!("Peer already removed form request manager when disconnected peer={}", peer);
        }
    }
}

#[derive(Debug)]
struct TimedWaitingRequest {
    time_to_send: Instant,
    request: WaitingRequest,
    peer: PeerId,
}

impl TimedWaitingRequest {
    fn new(
        time_to_send: Instant, request: WaitingRequest, peer: PeerId,
    ) -> Self {
        Self {
            time_to_send,
            request,
            peer,
        }
    }
}

impl Ord for TimedWaitingRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        other.time_to_send.cmp(&self.time_to_send)
    }
}
impl PartialOrd for TimedWaitingRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.time_to_send.partial_cmp(&self.time_to_send)
    }
}
impl Eq for TimedWaitingRequest {}
impl PartialEq for TimedWaitingRequest {
    fn eq(&self, other: &Self) -> bool {
        self.time_to_send == other.time_to_send
    }
}
