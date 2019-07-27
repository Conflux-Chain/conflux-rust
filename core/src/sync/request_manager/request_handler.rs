use crate::sync::{
    message::{KeyContainer, Message},
    msg_sender::send_message,
    request_manager::RequestManager,
    synchronization_protocol_handler::ProtocolConfiguration,
    Error, ErrorKind,
};
use network::{NetworkContext, PeerId};
use parking_lot::Mutex;
use priority_send_queue::SendQueuePriority;
use std::{
    any::Any,
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, VecDeque},
    fmt::Debug,
    mem,
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    },
    time::{Duration, Instant},
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
        let mut requests_vec = Vec::with_capacity(
            self.protocol_config.max_inflight_request_count as usize,
        );
        for _i in 0..self.protocol_config.max_inflight_request_count {
            requests_vec.push(None);
        }
        self.peers.lock().insert(
            peer_id,
            RequestContainer {
                peer_id,
                inflight_requests: requests_vec,
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
        &self, io: &NetworkContext, peer_id: PeerId, request_id: u64,
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

    pub fn send_request(
        &self, io: &NetworkContext, peer: PeerId, mut msg: RequestMessage,
        priority: SendQueuePriority,
    ) -> Result<(), Error>
    {
        let mut peers = self.peers.lock();
        let mut requests_queue = self.requests_queue.lock();
        if let Some(peer_info) = peers.get_mut(&peer) {
            if let Some(request_id) = peer_info.get_next_request_id() {
                msg.set_request_id(request_id);
                send_message(io, peer, msg.get_msg(), priority)?;
                let timed_req = Arc::new(TimedSyncRequests::from_request(
                    peer,
                    request_id,
                    &msg,
                    &self.protocol_config,
                ));
                peer_info.append_inflight_request(
                    request_id,
                    msg,
                    timed_req.clone(),
                );
                requests_queue.push(timed_req);
            } else {
                trace!("Append requests for later:{:?}", msg);
                peer_info.append_pending_request(msg);
            }
            Ok(())
        } else {
            Err(ErrorKind::UnknownPeer.into())
        }
    }

    /// Send request to the specified peer. If peer is `None` or send request
    /// failed, return the request back to caller to handle in advance.
    pub fn send_general_request(
        &self, io: &NetworkContext, peer: Option<PeerId>,
        mut request: Box<Request>, delay: Option<Duration>,
    ) -> Result<(), Box<Request>>
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
        let message = request.as_message();
        if send_message(io, peer, message, message.priority()).is_err() {
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
                // TODO And should handle timeout peers.
                timeout_requests.push(sync_req);
            }
        }
        timeout_requests
    }

    pub fn get_timeout_requests(
        &self, io: &NetworkContext,
    ) -> Vec<RequestMessage> {
        // Check if in-flight requests timeout
        let mut timeout_requests = Vec::new();
        for sync_req in self.get_timeout_sync_requests() {
            if let Ok(req) =
                self.match_request(io, sync_req.peer_id, sync_req.request_id)
            {
                timeout_requests.push(req);
            } else {
                debug!("Timeout a removed request {:?}", sync_req);
            }
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
    pub inflight_requests: Vec<Option<SynchronizationPeerRequest>>,
    /// lowest = next if there is no inflight requests
    pub lowest_request_id: u64,
    pub next_request_id: u64,
    pub max_inflight_request_count: u64,
    pub pending_requests: VecDeque<RequestMessage>,
}

impl RequestContainer {
    /// If new request will be allowed to send, advance the request id now,
    /// otherwise, actual new request id will be given to this request
    /// when it is moved from pending to inflight queue.
    pub fn get_next_request_id(&mut self) -> Option<u64> {
        if self.next_request_id
            < self.lowest_request_id + self.max_inflight_request_count
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
        self.inflight_requests
            [(request_id % self.max_inflight_request_count) as usize] =
            Some(SynchronizationPeerRequest { message, timed_req });
    }

    pub fn append_pending_request(&mut self, msg: RequestMessage) {
        self.pending_requests.push_back(msg);
    }

    #[allow(unused)]
    pub fn is_inflight_request(&self, request_id: u64) -> bool {
        request_id < self.next_request_id
            && request_id >= self.lowest_request_id
            && self.inflight_requests
                [(request_id % self.max_inflight_request_count) as usize]
                .is_some()
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
        if request_id < self.next_request_id
            && request_id >= self.lowest_request_id
        {
            let save_req = mem::replace(
                &mut self.inflight_requests
                    [(request_id % self.max_inflight_request_count) as usize],
                None,
            );
            // Advance lowest_request_id to the next in-flight request
            if request_id == self.lowest_request_id {
                while self.inflight_requests[(self.lowest_request_id
                    % self.max_inflight_request_count)
                    as usize]
                    .is_none()
                    && self.lowest_request_id < self.next_request_id
                {
                    self.lowest_request_id += 1;
                }
            }
            save_req
        } else {
            debug!("Remove out of bound request peer={} request_id={} low={} next={}", self.peer_id, request_id, self.lowest_request_id, self.next_request_id);
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
        &mut self, io: &NetworkContext, request_id: u64,
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
                    // FIXME: May need to set priority more precisely.
                    // Simply treat request as high priority for now.
                    let send_res = send_message(
                        io,
                        self.peer_id,
                        pending_msg.get_msg(),
                        SendQueuePriority::High,
                    );

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
        while let Some(maybe_req) = self.inflight_requests.pop() {
            if let Some(req) = maybe_req {
                req.timed_req.removed.store(true, AtomicOrdering::Relaxed);
                unfinished_requests.push(req.message);
            }
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

/// Trait of request message
pub trait Request: Send + Debug {
    fn set_request_id(&mut self, request_id: u64);
    fn as_message(&self) -> &Message;
    /// Support to downcast trait to concrete request type.
    fn as_any(&self) -> &Any;
    /// Request timeout for resend purpose.
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration;

    /// Cleanup the inflight request items when peer disconnected or invalid
    /// message received.
    fn on_removed(&self, inflight_keys: &mut KeyContainer);
    /// Before send a request, check if its items already in flight.
    /// If in flight, do not request duplicated items.
    /// Otherwise, insert the item key into `inflight_keys`.
    fn with_inflight(&mut self, inflight_keys: &mut KeyContainer);
    /// If all requested items are already in flight, then do not send request
    /// to remote peer.
    fn is_empty(&self) -> bool;
    /// When a request failed (send fail, invalid response or timeout), it will
    /// be resend automatically.
    ///
    /// For some kind of requests, it will resend other kind of request other
    /// than the original one. E.g. when get compact block failed, it will
    /// request the whole block instead.
    ///
    /// If resend is not required, return `None`, e.g. request transactions
    /// failed.
    fn resend(&self) -> Option<Box<Request>>;
}

#[derive(Debug)]
pub struct RequestMessage {
    pub request: Box<Request>,
    pub delay: Option<Duration>,
}

impl RequestMessage {
    pub fn new(request: Box<Request>, delay: Option<Duration>) -> Self {
        RequestMessage { request, delay }
    }

    pub fn set_request_id(&mut self, request_id: u64) {
        self.request.set_request_id(request_id);
    }

    pub fn get_msg(&self) -> &Message { self.request.as_message() }

    /// Download cast request to specified request type.
    /// If downcast failed, resend the request again and return
    /// `UnexpectedResponse` error.
    pub fn downcast_ref<T: Request + Any>(
        &self, io: &NetworkContext, request_manager: &RequestManager,
        remove_on_mismatch: bool,
    ) -> Result<&T, Error>
    {
        match self.request.as_any().downcast_ref::<T>() {
            Some(req) => Ok(req),
            None => {
                warn!("failed to downcast general request to concrete request type, message = {:?}", self);
                if remove_on_mismatch {
                    request_manager.remove_mismatch_request(io, self);
                }
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
