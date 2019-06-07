use crate::sync::{
    msg_sender::send_message,
    synchronization_protocol_handler::ProtocolConfiguration, Error, ErrorKind,
};
use message::{
    GetBlockHashesByEpoch, GetBlockHeaders, GetBlockTxn, GetBlocks,
    GetCompactBlocks, GetTransactions, Message,
};
use network::{NetworkContext, PeerId};
use parking_lot::Mutex;
use priority_send_queue::SendQueuePriority;
use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, VecDeque},
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
        &self, io: &NetworkContext, peer: PeerId, mut msg: Box<RequestMessage>,
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
    pub fn remove_peer(
        &self, peer_id: PeerId,
    ) -> Option<Vec<Box<RequestMessage>>> {
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
    pub pending_requests: VecDeque<Box<RequestMessage>>,
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
        &mut self, request_id: u64, message: Box<RequestMessage>,
        timed_req: Arc<TimedSyncRequests>,
    )
    {
        self.inflight_requests
            [(request_id % self.max_inflight_request_count) as usize] =
            Some(SynchronizationPeerRequest { message, timed_req });
    }

    pub fn append_pending_request(&mut self, msg: Box<RequestMessage>) {
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

    pub fn pop_pending_request(&mut self) -> Option<Box<RequestMessage>> {
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
            warn!("Remove out of bound request peer={} request_id={} low={} next={}", self.peer_id, request_id, self.lowest_request_id, self.next_request_id);
            None
        }
    }

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
            Ok(*removed_req.message)
        } else {
            bail!(ErrorKind::UnexpectedResponse)
        }
    }

    pub fn get_unfinished_requests(&mut self) -> Vec<Box<RequestMessage>> {
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
    pub message: Box<RequestMessage>,
    pub timed_req: Arc<TimedSyncRequests>,
}

#[derive(Debug)]
pub enum RequestMessage {
    Headers(GetBlockHeaders),
    Blocks(GetBlocks),
    Compact(GetCompactBlocks),
    BlockTxn(GetBlockTxn),
    Transactions(GetTransactions),
    Epochs(GetBlockHashesByEpoch),
}

impl RequestMessage {
    pub fn set_request_id(&mut self, request_id: u64) {
        match self {
            RequestMessage::Headers(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Blocks(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Compact(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::BlockTxn(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Transactions(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Epochs(ref mut msg) => {
                msg.set_request_id(request_id)
            }
        }
    }

    pub fn get_msg(&self) -> &Message {
        match self {
            RequestMessage::Headers(ref msg) => msg,
            RequestMessage::Blocks(ref msg) => msg,
            RequestMessage::Compact(ref msg) => msg,
            RequestMessage::BlockTxn(ref msg) => msg,
            RequestMessage::Transactions(ref msg) => msg,
            RequestMessage::Epochs(ref msg) => msg,
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
        let timeout = match *msg {
            RequestMessage::Headers(_) => conf.headers_request_timeout,
            RequestMessage::Epochs(_) => conf.headers_request_timeout,
            RequestMessage::Blocks(_)
            | RequestMessage::Compact(_)
            | RequestMessage::BlockTxn(_) => conf.blocks_request_timeout,
            RequestMessage::Transactions(_) => conf.transaction_request_timeout,
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
