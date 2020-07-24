// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, SetRequestId},
    parameters::sync::FAILED_REQUEST_RESEND_WAIT,
    sync::{
        message::{DynamicCapability, KeyContainer},
        request_manager::RequestManager,
        synchronization_protocol_handler::ProtocolConfiguration,
        synchronization_state::EpochGapLimit,
        Error, ErrorKind,
    },
};
use malloc_size_of::MallocSizeOf;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use network::{
    node_table::NodeId, ErrorKind as NetworkErrorKind, NetworkContext,
    UpdateNodeOperation,
};
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

#[derive(DeriveMallocSizeOf)]
pub struct RequestHandler {
    protocol_config: ProtocolConfiguration,
    peers: Mutex<HashMap<NodeId, RequestContainer>>,
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

    pub fn add_peer(&self, peer_id: NodeId) {
        self.peers.lock().insert(
            peer_id,
            RequestContainer {
                peer_id,
                inflight_requests: HashMap::new(),
                // Initialize request_id randomly to prevent responses from a
                // peer to interfere with requests of the same
                // peer after reconnection.
                next_request_id: rand::random(),
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
        &self, peer_id: &NodeId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        let mut peers = self.peers.lock();
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.match_request(request_id)
        } else {
            bail!(ErrorKind::UnknownPeer);
        }
    }

    pub fn send_pending_requests(
        &self, io: &dyn NetworkContext, peer: &NodeId,
    ) {
        if let Some(peer_info) = self.peers.lock().get_mut(peer) {
            peer_info.send_pending_requests(
                io,
                &mut *self.requests_queue.lock(),
                &self.protocol_config,
            );
        }
    }

    /// Send request to the specified peer. If peer is `None` or send request
    /// failed, return the request back to caller to handle in advance.
    pub fn send_request(
        &self, io: &dyn NetworkContext, peer: Option<NodeId>,
        request: Box<dyn Request>, delay: Option<Duration>,
    ) -> Result<(), Box<dyn Request>>
    {
        let peer = match peer {
            Some(peer) => peer,
            None => return Err(request),
        };

        let peers = &mut *self.peers.lock();
        let peer_info = match peers.get_mut(&peer) {
            Some(peer) => peer,
            None => return Err(request),
        };

        let msg = RequestMessage::new(request, delay);

        let request_id = match peer_info.get_next_request_id() {
            Some(id) => id,
            None => {
                peer_info.append_pending_request(msg);
                return Ok(());
            }
        };

        peer_info.immediate_send_request_to_peer(
            io,
            request_id,
            msg,
            &mut *self.requests_queue.lock(),
            &self.protocol_config,
        );

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

    pub fn process_timeout_requests(
        &self, io: &dyn NetworkContext,
    ) -> Vec<RequestMessage> {
        // Check if in-flight requests timeout
        let mut timeout_requests = Vec::new();
        let mut peers_to_disconnect = HashSet::new();
        let mut peers_to_send_pending_requests = HashSet::new();
        for sync_req in self.get_timeout_sync_requests() {
            if let Ok(mut req) =
                self.match_request(&sync_req.peer_id, sync_req.request_id)
            {
                let peer_id = sync_req.peer_id.clone();
                if let Some(request_container) =
                    self.peers.lock().get_mut(&peer_id)
                {
                    if request_container
                        .on_timeout_should_disconnect(&self.protocol_config)
                    {
                        peers_to_disconnect.insert(peer_id);
                    } else {
                        peers_to_send_pending_requests.insert(peer_id);
                    }
                }
                req.request.notify_timeout();
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
                &peer_id,
                op,
                "too many timeout requests", /* reason */
            );
        }
        for peer_id in peers_to_send_pending_requests {
            self.send_pending_requests(io, &peer_id);
        }

        timeout_requests
    }

    /// Return unfinished_requests
    pub fn remove_peer(&self, peer_id: &NodeId) -> Option<Vec<RequestMessage>> {
        self.peers
            .lock()
            .remove(peer_id)
            .map(|mut p| p.get_unfinished_requests())
    }
}

#[derive(Default, DeriveMallocSizeOf)]
struct RequestContainer {
    peer_id: NodeId,
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

    fn immediate_send_request_to_peer(
        &mut self, io: &dyn NetworkContext, request_id: u64,
        mut request_message: RequestMessage,
        requests_queue: &mut BinaryHeap<Arc<TimedSyncRequests>>,
        protocol_config: &ProtocolConfiguration,
    )
    {
        request_message.request.set_request_id(request_id);
        let res = request_message.request.send(io, &self.peer_id);
        let is_send_error = if let Err(e) = res {
            match e.kind() {
                NetworkErrorKind::OversizedPacket => {
                    panic!("Request packet should not be oversized!")
                }
                _ => {}
            }
            true
        } else {
            false
        };

        let timed_req = Arc::new(TimedSyncRequests::from_request(
            self.peer_id,
            request_id,
            &request_message,
            protocol_config,
            is_send_error,
        ));
        self.append_inflight_request(
            request_id,
            request_message,
            timed_req.clone(),
        );
        requests_queue.push(timed_req);
    }

    // Error from send_message():
    //      This also does NOT introduce needs to handle request
    //      resending for caller;
    pub fn send_pending_requests(
        &mut self, io: &dyn NetworkContext,
        requests_queue: &mut BinaryHeap<Arc<TimedSyncRequests>>,
        protocol_config: &ProtocolConfiguration,
    )
    {
        trace!("send_pending_requests: len={}", self.pending_requests.len());
        while self.has_pending_requests() {
            if let Some(new_request_id) = self.get_next_request_id() {
                let pending_msg = self.pop_pending_request().unwrap();

                self.immediate_send_request_to_peer(
                    io,
                    new_request_id,
                    pending_msg,
                    requests_queue,
                    protocol_config,
                );
            } else {
                break;
            }
        }
    }

    // Match request with given response.
    // Could return the following error:
    // 1. RequestNotFound:
    //      In this case, no request is matched, so NO need to
    //      handle the resending of the request for caller;
    pub fn match_request(
        &mut self, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        let removed_req = self.remove_inflight_request(request_id);
        if let Some(removed_req) = removed_req {
            removed_req
                .timed_req
                .removed
                .store(true, AtomicOrdering::Relaxed);
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

#[derive(Debug, DeriveMallocSizeOf)]
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
pub trait Request:
    Send + Debug + AsAny + Message + SetRequestId + MallocSizeOf
{
    /// Request timeout for resend purpose.
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration;

    /// Cleanup the inflight request items when peer disconnected or invalid
    /// message received.
    fn on_removed(&self, inflight_keys: &KeyContainer);
    /// Before send a request, check if its items already in flight.
    /// If in flight, do not request duplicated items.
    /// Otherwise, insert the item key into `inflight_keys`.
    fn with_inflight(&mut self, inflight_keys: &KeyContainer);
    /// If all requested items are already in flight, then do not send request
    /// to remote peer.
    fn is_empty(&self) -> bool;
    /// Notify the handler when the request gets cancelled by empty.
    fn notify_empty(&mut self) {}
    /// When a request failed (send fail, invalid response or timeout), it will
    /// be resend automatically.
    ///
    /// For some kind of requests, it will resend other kind of request other
    /// than the original one. E.g. when get compact block failed, it will
    /// request the whole block instead.
    ///
    /// If resend is not required, return `None`, e.g. request transactions
    /// failed.
    fn resend(&self) -> Option<Box<dyn Request>>;

    /// Required peer capability to send this request
    fn required_capability(&self) -> Option<DynamicCapability> { None }

    /// Notify the handler when the request gets timeout.
    fn notify_timeout(&mut self) {}

    /// Epoch-gap-limit required by this request.
    fn epoch_gap_limit(&self) -> Option<EpochGapLimit> { None }
}

#[derive(Debug, DeriveMallocSizeOf)]
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

    /// Download cast request to specified request type.
    /// If downcast failed, resend the request again and return
    /// `UnexpectedResponse` error.
    pub fn downcast_ref<T: Request + Any>(
        &self, io: &dyn NetworkContext, request_manager: &RequestManager,
    ) -> Result<&T, Error> {
        match self.request.as_any().downcast_ref::<T>() {
            Some(req) => Ok(req),
            None => {
                warn!("failed to downcast general request to concrete request type, message = {:?}", self);
                if let Some(resent_request) = self.request.resend() {
                    request_manager.resend_request_to_another_peer(
                        io,
                        &RequestMessage::new(resent_request, self.delay),
                    );
                }
                Err(ErrorKind::UnexpectedResponse.into())
            }
        }
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

#[derive(Debug, DeriveMallocSizeOf)]
pub struct TimedSyncRequests {
    pub peer_id: NodeId,
    pub timeout_time: Instant,
    pub request_id: u64,
    pub removed: AtomicBool,
}

impl TimedSyncRequests {
    pub fn new(
        peer_id: NodeId, timeout: Duration, request_id: u64,
    ) -> TimedSyncRequests {
        TimedSyncRequests {
            peer_id,
            timeout_time: Instant::now() + timeout,
            request_id,
            removed: AtomicBool::new(false),
        }
    }

    pub fn from_request(
        peer_id: NodeId, request_id: u64, msg: &RequestMessage,
        conf: &ProtocolConfiguration, is_send_error: bool,
    ) -> TimedSyncRequests
    {
        let timeout = if is_send_error {
            FAILED_REQUEST_RESEND_WAIT.clone()
        } else {
            msg.request.timeout(conf)
        };
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
