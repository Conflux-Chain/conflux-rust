use crate::{message::PeerId, sync::state::storage::SnapshotSyncCandidate};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashSet};

pub struct StateSyncCandidateManager {
    inner: RwLock<Inner>,
}

impl StateSyncCandidateManager {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner::new()),
        }
    }

    pub fn candidates(&self) -> Vec<SnapshotSyncCandidate> {
        self.inner
            .read()
            .candidates
            .keys()
            .into_iter()
            .map(Clone::clone)
            .collect()
    }

    pub fn active_peers(&self) -> HashSet<PeerId> {
        self.inner.read().active_peers.clone()
    }

    pub fn start(
        &self, candidates: Vec<SnapshotSyncCandidate>, peers: Vec<PeerId>,
    ) {
        self.inner.write().reset(candidates, peers);
    }

    pub fn on_peer_response(
        &self, peer: &PeerId, supported_candidates: &Vec<SnapshotSyncCandidate>,
    ) -> Option<SnapshotSyncCandidate> {
        self.inner
            .write()
            .on_peer_response(peer, supported_candidates)
    }

    pub fn should_change_candidate(&self) -> bool {
        self.inner.read().should_change_candidate()
    }

    pub fn on_peer_disconnected(&self, peer: &PeerId) {
        let mut inner = self.inner.write();
        inner.active_peers.remove(peer);
        for peers in inner.candidates.values_mut() {
            peers.remove(peer);
        }
    }
}

struct Inner {
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

impl Inner {
    fn new() -> Self {
        Self {
            candidates: BTreeMap::new(),
            pending_peers: Default::default(),
            active_candidate: None,
            active_peers: Default::default(),
        }
    }

    fn reset(
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
    fn on_peer_response(
        &mut self, peer: &PeerId,
        supported_candidates: &Vec<SnapshotSyncCandidate>,
    ) -> Option<SnapshotSyncCandidate>
    {
        if !self.pending_peers.remove(peer) {
            debug!("Receive response from unexpected peer {:?}, possibly from old requests", peer);
            return None;
        }
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

    // TODO Should change candidates if we only have slow active peers
    fn should_change_candidate(&self) -> bool {
        self.active_candidate.is_none() || self.active_peers.is_empty()
    }
}
