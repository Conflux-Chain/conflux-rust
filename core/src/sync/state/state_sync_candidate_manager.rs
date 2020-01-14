use crate::{message::PeerId, sync::state::storage::SnapshotSyncCandidate};
use std::{
    collections::{BTreeMap, HashSet},
    time::{Duration, Instant},
};

/// 1. Send CandidateRequest to all peers and set them to `pending_peers`.
///     1.1: All peers respond before timeout, we choose one candidate and start
///         state sync.
///     1.2: Some peers timeout.
///         1.2.1: Have available candidates, we choose one and enter step 2.
///             `pending_peers` is cleared before entering step 2.
///         1.2.2: No available candidates, reset the status and restart step 1.
/// 2. Send ManifestRequest to some random peer in `active_peers`.
///     2.1: Valid manifest received, move on to step 3.
///     2.2: Timeout/invalid/empty response. Remove from `active_peers`.
///         2.2.1: Have more available `active_peers`, restart step 2.
///         2.2.2: `active_peers` is empty, reset and restart step 1.
/// 3. Send ChunkRequest to multiple peers in `active_peers`.
///     3.1: Valid chunks received.
///         3.1.1: All chunks received, set state_sync.status to Completed.
///         3.1.2: More chunks to request. Request from `active_peers`.
///     3.2: Timeout/invalid/empty response. Remove from `active_peers`.
///         3.2.1: Have more available `active_peers`, push this chunk key
///             back into the `pending_chunks` for later requesting.
///         3.2.2: `active_peers` is empty, reset and restart step 1.
///
/// All step start/restart are triggered by the periodic check of phase change.
pub struct StateSyncCandidateManager {
    /// The starting time of the ongoing candidate requesting
    start_time: Instant,

    /// The map from state candidates to the set of peers that can support this
    /// state
    candidates: BTreeMap<SnapshotSyncCandidate, HashSet<PeerId>>,
    /// The peers who have been requested for candidate response but has not
    /// replied
    pending_peers: HashSet<PeerId>,

    /// The chosen candidate that we are actually requesting state manifest and
    /// chunks
    pub active_candidate: Option<SnapshotSyncCandidate>,
    /// The peers that can serve `active_candidate`.
    active_peers: HashSet<PeerId>,
}

impl StateSyncCandidateManager {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            candidates: BTreeMap::new(),
            pending_peers: Default::default(),
            active_candidate: None,
            active_peers: Default::default(),
        }
    }

    pub fn reset(
        &mut self, candidates: Vec<SnapshotSyncCandidate>, peers: Vec<PeerId>,
    ) {
        let mut candidates_map = BTreeMap::new();
        for candidate in candidates {
            candidates_map.insert(candidate, HashSet::new());
        }
        self.start_time = Instant::now();
        self.candidates = candidates_map;
        self.pending_peers = peers.into_iter().collect();
        self.active_candidate = None;
        self.active_peers = HashSet::new();
    }

    /// Update the status about candidate choosing.
    /// Return the peer and epoch to retrieve the state manifest
    pub fn on_peer_response(
        &mut self, peer: &PeerId,
        supported_candidates: &Vec<SnapshotSyncCandidate>,
        requested_candidates: &Vec<SnapshotSyncCandidate>,
    ) -> Option<SnapshotSyncCandidate>
    {
        if !self.pending_peers.remove(peer) {
            debug!("Receive response from unexpected peer {:?}, possibly from old requests", peer);
            return None;
        }
        let mut requested_candidates_set: HashSet<&SnapshotSyncCandidate> =
            requested_candidates.iter().collect();
        for candidate in supported_candidates {
            match self.candidates.get_mut(candidate) {
                Some(peer_set) => {
                    peer_set.insert(*peer);
                }
                None => {
                    debug!(
                        "Receive unexpected candidate {:?} from peer {:?}",
                        candidate, peer
                    );
                }
            }
            requested_candidates_set.remove(&candidate);
        }
        for unsupported_candidate in requested_candidates_set {
            match self.candidates.get_mut(unsupported_candidate) {
                Some(peer_set) => {
                    peer_set.remove(peer);
                }
                None => {
                    debug!(
                        "requested candidate removed {:?} from peer {:?}",
                        unsupported_candidate, peer
                    );
                }
            }
        }

        // TODO We can choose an active candidate before receiving all the
        // response
        if self.pending_peers.is_empty() {
            self.set_active_candidate();
            // Here we return None only if all requested peers cannot serve the
            // candidates TODO ask about new state candidates or new
            // peers when active_candidate is None
            return self.active_candidate.clone();
        }
        None
    }

    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        self.active_peers.remove(peer);
        for peers in self.candidates.values_mut() {
            peers.remove(peer);
        }
    }

    #[allow(unused)]
    // TODO Should change candidates if we only have slow active peers
    pub fn should_change_candidate(&self) -> bool {
        self.active_candidate.is_none() || self.active_peers.is_empty()
    }

    pub fn active_peers(&self) -> &HashSet<PeerId> { &self.active_peers }

    /// `peer` cannot support the active candidate now
    pub fn note_state_sync_failure(&mut self, peer: &PeerId) {
        self.pending_peers.remove(peer);
        if self.pending_peers.is_empty() {
            // Rely on periodic phase checks to start state sync
            self.set_active_candidate();
        }
        self.active_peers.remove(peer);
        if let Some(active_candidate) = &self.active_candidate {
            if let Some(peers) = self.candidates.get_mut(active_candidate) {
                peers.remove(peer);
            }
        }
    }

    // TODO Find candidate according to priority
    fn set_active_candidate(&mut self) {
        for (candidate, peer_set) in &self.candidates {
            if !peer_set.is_empty() {
                debug!(
                    "StateSync: set active_candidate={:?}, active_peers={:?}",
                    candidate, peer_set
                );
                self.active_candidate = Some(candidate.clone());
                self.active_peers = peer_set.clone();
            }
        }
    }

    pub fn check_timeout(&mut self, candidate_timeout: &Duration) {
        if !self.pending_peers.is_empty()
            && self.start_time.elapsed() > *candidate_timeout
        {
            self.pending_peers.clear();
            self.set_active_candidate();
        }
    }

    /// Return `true ` if we are not requesting either candidates or states
    pub fn is_inactive(&self) -> bool {
        self.pending_peers.is_empty() && self.active_peers.is_empty()
    }
}

impl Default for StateSyncCandidateManager {
    fn default() -> Self { Self::new() }
}
