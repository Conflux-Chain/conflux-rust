use crate::sync::state::storage::SnapshotSyncCandidate;
use network::node_table::NodeId;
use primitives::EpochId;
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

    pub current_era_genesis: EpochId,
    candidates: Vec<SnapshotSyncCandidate>,

    /// The map from state candidates to the set of peers that can support this
    /// state
    candidate_to_active_peers: BTreeMap<SnapshotSyncCandidate, HashSet<NodeId>>,
    /// The peers who have been requested for candidate response but has not
    /// replied
    pending_peers: HashSet<NodeId>,

    /// The chosen candidate that we are actually requesting state manifest and
    /// chunks.
    active_candidate: Option<usize>,
}

impl StateSyncCandidateManager {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            current_era_genesis: Default::default(),
            candidates: Default::default(),
            candidate_to_active_peers: BTreeMap::new(),
            pending_peers: Default::default(),
            active_candidate: None,
        }
    }

    pub fn reset(
        &mut self, current_era_genesis: EpochId,
        candidates: Vec<SnapshotSyncCandidate>, peers: Vec<NodeId>,
    )
    {
        let mut candidates_map = BTreeMap::new();
        for candidate in &candidates {
            candidates_map.insert(candidate.clone(), HashSet::new());
        }
        self.start_time = Instant::now();
        self.current_era_genesis = current_era_genesis;
        self.candidates = candidates;
        self.candidate_to_active_peers = candidates_map;
        self.pending_peers = peers.into_iter().collect();
        self.active_candidate = None;
    }

    /// Update the status about candidate choosing.
    /// Return the peer and epoch to retrieve the state manifest
    pub fn on_peer_response(
        &mut self, peer: &NodeId,
        supported_candidates: &Vec<SnapshotSyncCandidate>,
        requested_candidates: &Vec<SnapshotSyncCandidate>,
    )
    {
        if !self.pending_peers.remove(peer) {
            debug!("Receive response from unexpected peer {:?}, possibly from old requests", peer);
            return;
        }
        let mut requested_candidates_set: HashSet<&SnapshotSyncCandidate> =
            requested_candidates.iter().collect();
        for candidate in supported_candidates {
            match self.candidate_to_active_peers.get_mut(candidate) {
                Some(peer_set) => {
                    peer_set.insert(*peer);
                }
                None => {
                    if requested_candidates_set.contains(candidate) {
                        debug!("requested candidate {:?} is stale", candidate);
                    } else {
                        debug!(
                            "Receive unexpected candidate {:?} from peer {:?}",
                            candidate, peer
                        );
                    }
                }
            }
            requested_candidates_set.remove(&candidate);
        }
        for unsupported_candidate in requested_candidates_set {
            match self
                .candidate_to_active_peers
                .get_mut(unsupported_candidate)
            {
                Some(peer_set) => {
                    peer_set.remove(peer);
                }
                None => {
                    debug!(
                        "requested candidate {:?} is stale",
                        unsupported_candidate,
                    );
                }
            }
        }
    }

    pub fn on_peer_disconnected(&mut self, peer: &NodeId) {
        for peers in self.candidate_to_active_peers.values_mut() {
            peers.remove(peer);
        }
    }

    pub fn pending_peers(&self) -> &HashSet<NodeId> { &self.pending_peers }

    pub fn get_active_candidate_and_peers(
        &self,
    ) -> Option<(SnapshotSyncCandidate, HashSet<NodeId>)> {
        self.active_candidate.map(|i| {
            let candidate = self.candidates[i].clone();
            let active_peers = self
                .candidate_to_active_peers
                .get(&candidate)
                .expect("Active candidate has a non-empty peer set")
                .clone();
            (candidate, active_peers)
        })
    }

    pub fn set_active_candidate(&mut self) {
        let mut candidate_index = self.active_candidate.map_or(0, |i| i + 1);
        let max_candidate_index = self.candidates.len();
        while candidate_index < max_candidate_index {
            self.active_candidate = Some(candidate_index);
            let candidate = &self.candidates[candidate_index];
            let peer_set =
                self.candidate_to_active_peers.get(candidate).unwrap();
            if peer_set.is_empty() {
                debug!(
                    "StateSync: candidate {}={:?}, active_peers={:?}",
                    candidate_index, candidate, peer_set
                );
            } else {
                debug!(
                    "StateSync: set active_candidate {}={:?}, active_peers={:?}",
                    candidate_index, candidate, peer_set
                );
                return;
            }
            candidate_index += 1;
        }
        // All sync candidates failed.
        if candidate_index == max_candidate_index {
            self.active_candidate = None;
        }
    }

    pub fn check_timeout(&mut self, candidate_timeout: &Duration) {
        if !self.pending_peers.is_empty()
            && self.start_time.elapsed() > *candidate_timeout
        {
            self.pending_peers.clear();
        }
    }

    /// Return `true ` if we are not requesting either candidates or states
    pub fn is_inactive(&self) -> bool {
        self.pending_peers.is_empty() && self.active_candidate.is_none()
    }
}

impl Default for StateSyncCandidateManager {
    fn default() -> Self { Self::new() }
}
