// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    alliance_tree_graph::hsb_sync_protocol::{
        request_manager::RequestManager, sync_protocol::RpcResponse,
    },
    message::{Message, SetRequestId},
    sync::{Error, ErrorKind, ProtocolConfiguration},
};
use futures::channel::oneshot;
use network::{NetworkContext, PeerId, UpdateNodeOperation};
use parking_lot::Mutex;
use std::{
    any::Any,
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    fmt::Debug,
    mem,
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub struct RequestHandler {
    protocol_config: ProtocolConfiguration,
    peers: Mutex<HashMap<PeerId, RequestContainer>>,
    requests_queue: Mutex<BinaryHeap<Arc<TimedSyncRequests>>>,
}

impl RequestHandler {
    pub fn new(protocol_config: &ProtocolConfiguration) -> Self {
        Self {
            protocol_config: protocol_config.clone(),
            peers: Mutex::new(HashMap::new()),
            requests_queue: Default::default(),
        }
    }

    pub fn add_peer(&self, peer_id: PeerId) {
        self.peers.lock().insert(
            peer_id,
            RequestContainer {
                peer_id,
                inflight_requests: HashMap::new(),
                next_request_id: 0,
                max_inflight_request_count: self
                    .protocol_config
                    .max_inflight_request_count,
                ..Default::default()
            },
        );
    }

    // Match request for given response.
    // Could return the following error:
    // 1. Error return from peer.match_request():
    //      No need to let caller handle request resending;
    // 2. UnknownPeer:
    //      No need to let caller handle request resending;
    pub fn match_request(
        &self, io: &dyn NetworkContext, peer_id: PeerId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        let mut peers = self.peers.lock();
        let mut requests_queue = self.requests_queue.lock();
        if let Some(peer) = peers.get_mut(&peer_id) {
            peer.match_request(
                io,
                request_id,
                &mut *requests_queue,
                &self.protocol_config,
            )
        } else {
            bail!(ErrorKind::UnknownPeer);
        }
    }

    /// Send request to the specified peer. If peer is `None` or send request
    /// failed, return the request back to caller to handle in advance.
    pub fn send_request(
        &self, io: &dyn NetworkContext, peer: Option<PeerId>,
        mut request: Box<dyn Request>, delay: Option<Duration>,
    ) -> Result<(), Box<dyn Request>>
    {
        let peer = match peer {
            Some(peer) => peer,
            None => return Err(request),
        };

        let mut peers = self.peers.lock();
        let mut requests_queue = self.requests_queue.lock();

        let peer_info = match peers.get_mut(&peer) {
            Some(peer) => peer,
            None => return Err(request),
        };

        let request_id = match peer_info.get_next_request_id() {
            Some(id) => id,
            None => {
                peer_info.append_pending_request(RequestMessage::new(
                    request, delay,
                ));
                return Ok(());
            }
        };

        request.set_request_id(request_id);
        if request.send(io, peer).is_err() {
            return Err(request);
        }

        let msg = RequestMessage::new(request, delay);

        let timed_req = Arc::new(TimedSyncRequests::from_request(
            peer,
            request_id,
            &msg,
            &self.protocol_config,
        ));
        peer_info.append_inflight_request(request_id, msg, timed_req.clone());
        requests_queue.push(timed_req);

        Ok(())
    }

    fn get_timeout_sync_requests(&self) -> Vec<Arc<TimedSyncRequests>> {
        let mut requests = self.requests_queue.lock();
        let mut timeout_requests = Vec::new();
        let now = Instant::now();
        loop {
            if requests.is_empty() {
                break;
            }
            let sync_req = requests.pop().expect("queue not empty");
            if sync_req.removed.load(AtomicOrdering::Relaxed) == true {
                continue;
            }
            if sync_req.timeout_time >= now {
                requests.push(sync_req);
                break;
            } else {
                debug!("Timeout request {:?}", sync_req);
                timeout_requests.push(sync_req);
            }
        }
        timeout_requests
    }

    pub fn get_timeout_requests(
        &self, io: &dyn NetworkContext,
    ) -> Vec<RequestMessage> {
        // Check if in-flight requests timeout
        let mut timeout_requests = Vec::new();
        let mut peers_to_disconnect = HashSet::new();
        for sync_req in self.get_timeout_sync_requests() {
            if let Ok(req) =
                self.match_request(io, sync_req.peer_id, sync_req.request_id)
            {
                let peer_id = sync_req.peer_id;
                if let Some(request_container) =
                    self.peers.lock().get_mut(&peer_id)
                {
                    if request_container
                        .on_timeout_should_disconnect(&self.protocol_config)
                    {
                        peers_to_disconnect.insert(peer_id);
                    }
                }
                timeout_requests.push(req);
            } else {
                debug!("Timeout a removed request {:?}", sync_req);
            }
        }
        let op = if self.protocol_config.demote_peer_for_timeout {
            Some(UpdateNodeOperation::Demotion)
        } else {
            Some(UpdateNodeOperation::Failure)
        };
        for peer_id in peers_to_disconnect {
            // Note `self.peers` will be used in `disconnect_peer`, so we must
            // call it without locking `self.peers`.
            io.disconnect_peer(
                peer_id,
                op,
                "too many timeout requests", /* reason */
            );
        }

        timeout_requests
    }

    /// Return unfinished_requests
    pub fn remove_peer(&self, peer_id: PeerId) -> Option<Vec<RequestMessage>> {
        self.peers
            .lock()
            .remove(&peer_id)
            .map(|mut p| p.get_unfinished_requests())
    }
}

#[derive(Default)]
struct RequestContainer {
    peer_id: PeerId,
    pub inflight_requests: HashMap<u64, SynchronizationPeerRequest>,
    pub next_request_id: u64,
    pub max_inflight_request_count: u64,
    pub pending_requests: VecDeque<RequestMessage>,
    pub timeout_statistics: VecDeque<u64>,
}

impl RequestContainer {
    pub fn on_timeout_should_disconnect(
        &mut self, config: &ProtocolConfiguration,
    ) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if self.timeout_statistics.is_empty() {
            self.timeout_statistics.push_back(now);
            return false;
        }

        self.timeout_statistics.push_back(now);
        loop {
            let old_time = *self.timeout_statistics.front().unwrap();
            if now - old_time <= config.timeout_observing_period_s {
                break;
            }
            self.timeout_statistics.pop_front();
        }

        if self.timeout_statistics.len()
            <= config.max_allowed_timeout_in_observing_period as usize
        {
            return false;
        } else {
            return true;
        }
    }

    /// If new request will be allowed to send, advance the request id now,
    /// otherwise, actual new request id will be given to this request
    /// when it is moved from pending to inflight queue.
    pub fn get_next_request_id(&mut self) -> Option<u64> {
        if self.inflight_requests.len()
            < self.max_inflight_request_count as usize
        {
            let id = self.next_request_id;
            self.next_request_id += 1;
            Some(id)
        } else {
            None
        }
    }

    pub fn append_inflight_request(
        &mut self, request_id: u64, message: RequestMessage,
        timed_req: Arc<TimedSyncRequests>,
    )
    {
        self.inflight_requests.insert(
            request_id,
            SynchronizationPeerRequest { message, timed_req },
        );
    }

    pub fn append_pending_request(&mut self, msg: RequestMessage) {
        self.pending_requests.push_back(msg);
    }

    pub fn has_pending_requests(&self) -> bool {
        !self.pending_requests.is_empty()
    }

    pub fn pop_pending_request(&mut self) -> Option<RequestMessage> {
        self.pending_requests.pop_front()
    }

    pub fn remove_inflight_request(
        &mut self, request_id: u64,
    ) -> Option<SynchronizationPeerRequest> {
        if let Some(save_req) = self.inflight_requests.remove(&request_id) {
            Some(save_req)
        } else {
            debug!(
                "Remove out of bound request peer={} request_id={} next={}",
                self.peer_id, request_id, self.next_request_id
            );
            None
        }
    }

    // Match request with given response.
    // Could return the following error:
    // 1. RequestNotFound:
    //      In this case, no request is matched, so NO need to
    //      handle the resending of the request for caller;
    // 2. Error from send_message():
    //      This also does NOT introduce needs to handle request
    //      resending for caller;
    pub fn match_request(
        &mut self, io: &dyn NetworkContext, request_id: u64,
        requests_queue: &mut BinaryHeap<Arc<TimedSyncRequests>>,
        protocol_config: &ProtocolConfiguration,
    ) -> Result<RequestMessage, Error>
    {
        let removed_req = self.remove_inflight_request(request_id);
        if let Some(removed_req) = removed_req {
            removed_req
                .timed_req
                .removed
                .store(true, AtomicOrdering::Relaxed);
            while self.has_pending_requests() {
                if let Some(new_request_id) = self.get_next_request_id() {
                    let mut pending_msg = self.pop_pending_request().unwrap();
                    pending_msg.set_request_id(new_request_id);
                    let send_res = pending_msg.request.send(io, self.peer_id);

                    if send_res.is_err() {
                        warn!("Error while send_message, err={:?}", send_res);
                        self.append_pending_request(pending_msg);
                        return Err(send_res.err().unwrap().into());
                    }

                    let timed_req = Arc::new(TimedSyncRequests::from_request(
                        self.peer_id,
                        new_request_id,
                        &pending_msg,
                        protocol_config,
                    ));
                    self.append_inflight_request(
                        new_request_id,
                        pending_msg,
                        timed_req.clone(),
                    );
                    requests_queue.push(timed_req);
                } else {
                    break;
                }
            }
            Ok(removed_req.message)
        } else {
            bail!(ErrorKind::RequestNotFound)
        }
    }

    pub fn get_unfinished_requests(&mut self) -> Vec<RequestMessage> {
        let mut unfinished_requests = Vec::new();
        let mut new_map = HashMap::new();
        mem::swap(&mut self.inflight_requests, &mut new_map);
        for (_, req) in new_map {
            req.timed_req.removed.store(true, AtomicOrdering::Relaxed);
            unfinished_requests.push(req.message);
        }

        while let Some(req) = self.pending_requests.pop_front() {
            unfinished_requests.push(req);
        }
        unfinished_requests
    }
}

#[derive(Debug)]
pub struct SynchronizationPeerRequest {
    pub message: RequestMessage,
    pub timed_req: Arc<TimedSyncRequests>,
}

/// Support to downcast trait to concrete request type.
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Trait of request message
pub trait Request: Send + Debug + AsAny + Message + SetRequestId {
    /// Request timeout for resend purpose.
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration;

    /// Notify the handler when error happens for the request.
    fn notify_error(&mut self, error: Error);

    /// This is for RPC request. Set the notification handle for the request.
    fn set_response_notification(
        &mut self, res_tx: oneshot::Sender<Result<Box<dyn RpcResponse>, Error>>,
    );
}

#[derive(Debug)]
pub struct RequestMessage {
    pub request: Box<dyn Request>,
    pub delay: Option<Duration>,
}

impl RequestMessage {
    pub fn new(request: Box<dyn Request>, delay: Option<Duration>) -> Self {
        RequestMessage { request, delay }
    }

    pub fn set_request_id(&mut self, request_id: u64) {
        self.request.set_request_id(request_id);
    }

    pub fn downcast_mut<T: Request + Any>(
        &mut self, _io: &dyn NetworkContext, _request_manager: &RequestManager,
    ) -> Result<&mut T, Error> {
        match self.request.as_any_mut().downcast_mut::<T>() {
            Some(req) => Ok(req),
            None => {
                warn!("failed to downcast general request to concrete request type");
                Err(ErrorKind::UnexpectedResponse.into())
            }
        }
    }
}

#[derive(Debug)]
pub struct TimedSyncRequests {
    pub peer_id: PeerId,
    pub timeout_time: Instant,
    pub request_id: u64,
    pub removed: AtomicBool,
}

impl TimedSyncRequests {
    pub fn new(
        peer_id: PeerId, timeout: Duration, request_id: u64,
    ) -> TimedSyncRequests {
        TimedSyncRequests {
            peer_id,
            timeout_time: Instant::now() + timeout,
            request_id,
            removed: AtomicBool::new(false),
        }
    }

    pub fn from_request(
        peer_id: PeerId, request_id: u64, msg: &RequestMessage,
        conf: &ProtocolConfiguration,
    ) -> TimedSyncRequests
    {
        let timeout = msg.request.timeout(conf);
        TimedSyncRequests::new(peer_id, timeout, request_id)
    }
}

impl Ord for TimedSyncRequests {
    fn cmp(&self, other: &Self) -> Ordering {
        other.timeout_time.cmp(&self.timeout_time)
    }
}

impl PartialOrd for TimedSyncRequests {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.timeout_time.partial_cmp(&self.timeout_time)
    }
}

impl Eq for TimedSyncRequests {}

impl PartialEq for TimedSyncRequests {
    fn eq(&self, other: &Self) -> bool {
        self.timeout_time == other.timeout_time
    }
}
