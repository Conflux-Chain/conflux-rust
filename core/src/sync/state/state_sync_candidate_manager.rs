use crate::{message::PeerId, sync::state::storage::SnapshotSyncCandidate};
use std::collections::{BTreeMap, HashSet};

pub struct StateSyncCandidateManager {
    /// The map from state candidates to the set of peers that can support this
    /// state
    candidates: BTreeMap<SnapshotSyncCandidate, HashSet<PeerId>>,
    /// The peers who have been requested for candidate response but has not
    /// replied
    pending_peers: HashSet<PeerId>,

    /// The chosen candidate that we are actually requesting state manifest and
    /// chunks
    active_candidate: Option<SnapshotSyncCandidate>,
    /// The peers that can serve `active_candidate`.
    active_peers: HashSet<PeerId>,
}

impl StateSyncCandidateManager {
    fn new() -> Self {
        Self {
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

        // TODO Find candidate according to priority
        // TODO We can choose an active candidate before receiving all the
        // response
        if self.pending_peers.is_empty() {
            for (candidate, peer_set) in &self.candidates {
                if !peer_set.is_empty() {
                    self.active_candidate = Some(candidate.clone());
                    self.active_peers = peer_set.clone();
                    return Some(self.active_candidate.clone().unwrap());
                }
            }
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

    pub fn active_peers(&self) -> HashSet<PeerId> { self.active_peers.clone() }

    /// `peer` cannot support the active candidate now
    pub fn note_state_sync_failure(&mut self, peer: &PeerId) {
        self.active_peers.remove(peer);
        if let Some(active_candidate) = &self.active_candidate {
            if let Some(peers) = self.candidates.get_mut(active_candidate) {
                peers.remove(peer);
            }
        }
    }
}

impl Default for StateSyncCandidateManager {
    fn default() -> Self { Self::new() }
}
