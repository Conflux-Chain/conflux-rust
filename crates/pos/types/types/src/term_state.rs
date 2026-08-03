// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque},
    convert::TryFrom,
    fmt::{Debug, Formatter},
};

use anyhow::{anyhow, bail, ensure, Result};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

use cfx_types::H256;
use diem_crypto::{
    bls::deserialize_bls_public_key_unchecked, vrf_number_with_nonce,
    HashValue, Signature, VRFProof,
};
use diem_logger::prelude::*;
pub use incentives::*;
use lock_status::{ForfeitRule, NodeLockStatus};
use move_core_types::vm_status::DiscardedVMStatus;
use pos_state_config::{PosStateConfigTrait, POS_STATE_CONFIG};
use pow_types::StakingEvent;

use crate::{
    account_address::{from_consensus_public_key, AccountAddress},
    account_config,
    block_info::{PivotBlockDecision, Round, View},
    contract_event::ContractEvent,
    epoch_state::EpochState,
    event::EventKey,
    transaction::{DisputePayload, ElectionPayload},
    validator_config::{
        ConsensusPublicKey, ConsensusVRFPublicKey, MultiConsensusPublicKey,
        MultiConsensusSignature,
    },
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
};

pub mod lock_status;
pub mod pos_state_config;

pub const TERM_LIST_LEN: usize = 6;
pub const ROUND_PER_TERM: Round = 60;
pub const IN_QUEUE_LOCKED_VIEWS: u64 = 10080;
pub const OUT_QUEUE_LOCKED_VIEWS: u64 = 10080;
// The view to start election in the whole PoS consensus protocol.

pub const TERM_MAX_SIZE: usize = 10000;
pub const TERM_ELECTED_SIZE: usize = 50;

mod incentives {
    use super::{TERM_ELECTED_SIZE, TERM_LIST_LEN, TERM_MAX_SIZE};
    use crate::term_state::pos_state_config::{
        PosStateConfigTrait, POS_STATE_CONFIG,
    };

    const BONUS_VOTE_MAX_SIZE: u64 = 100;

    pub const MAX_TERM_POINTS: u64 = 6_000_000;

    const ELECTION_PERCENTAGE: u64 = 20;
    const COMMITTEE_PERCENTAGE: u64 = 75;
    const LEADER_PERCENTAGE: u64 = 3;
    const BONUS_VOTE_PERCENTAGE: u64 = 2;

    pub const ELECTION_POINTS: u64 =
        MAX_TERM_POINTS * ELECTION_PERCENTAGE / 100 / (TERM_MAX_SIZE as u64);
    pub const COMMITTEE_POINTS: u64 = MAX_TERM_POINTS * COMMITTEE_PERCENTAGE
        / 100
        / (TERM_ELECTED_SIZE as u64)
        / (TERM_LIST_LEN as u64);

    pub fn leader_points(view: u64) -> u64 {
        MAX_TERM_POINTS * LEADER_PERCENTAGE
            / 100
            / POS_STATE_CONFIG.round_per_term(view)
    }

    pub fn bonus_vote_points(view: u64) -> u64 {
        MAX_TERM_POINTS * BONUS_VOTE_PERCENTAGE
            / 100
            / POS_STATE_CONFIG.round_per_term(view)
            / BONUS_VOTE_MAX_SIZE
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum NodeStatus {
    Accepted,
    Retired,
    Unlocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct NodeData {
    /// This struct is only used locally, so loaded public keys must be valid.
    #[serde(deserialize_with = "deserialize_bls_public_key_unchecked")]
    public_key: ConsensusPublicKey,
    vrf_public_key: Option<ConsensusVRFPublicKey>,
    lock_status: NodeLockStatus,
}

impl NodeData {
    pub fn lock_status(&self) -> &NodeLockStatus { &self.lock_status }
}

/// A node becomes its voting power number of ElectionNodes for election.
#[derive(
    Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Ord, PartialOrd,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ElectionNodeID {
    node_id: NodeID,
    nonce: u64,
}

impl ElectionNodeID {
    pub fn new(node_id: NodeID, nonce: u64) -> Self {
        ElectionNodeID { node_id, nonce }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ElectingHeap(
    BinaryHeap<(HashValue, ElectionNodeID)>,
    HashSet<AccountAddress>,
);

#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ElectedMap(BTreeMap<AccountAddress, u64>);

pub type CandyMap = ElectedMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum NodeList {
    Electing(ElectingHeap),
    Elected(ElectedMap),
}

impl Default for NodeList {
    fn default() -> Self { NodeList::Electing(Default::default()) }
}

impl NodeList {
    fn len(&self) -> usize {
        match self {
            NodeList::Electing(heap) => heap.0.len(),
            NodeList::Elected(map) => map.0.len(),
        }
    }

    fn add_node(&mut self, vrf_output: HashValue, node_id: ElectionNodeID) {
        if let NodeList::Electing(heap) = self {
            heap.add_node(vrf_output, node_id);
        } else {
            panic!("The term is finalized");
        }
    }

    #[must_use]
    fn finalize_elect(&mut self) -> CandyMap {
        if let NodeList::Electing(heap) = self {
            let electing_heap = std::mem::take(heap);
            let (elected_heap, candy_map) = electing_heap.finalize();
            *self = NodeList::Elected(elected_heap);
            return candy_map;
        } else {
            panic!("The term is finalized");
        }
    }

    fn has_elected(&self, addr: &AccountAddress) -> bool {
        if let NodeList::Electing(heap) = self {
            heap.1.contains(addr)
        } else {
            panic!("The term is finalized");
        }
    }

    fn serving_votes(&self, address: &AccountAddress) -> u64 {
        if let NodeList::Elected(map) = self {
            map.0.get(address).cloned().unwrap_or(0)
        } else {
            panic!("The term is not finalized");
        }
    }

    fn committee(&self) -> &ElectedMap {
        if let NodeList::Elected(map) = self {
            map
        } else {
            panic!("The term is not finalized");
        }
    }
}

impl ElectedMap {
    pub fn inner(&self) -> &BTreeMap<AccountAddress, u64> { &self.0 }
}

impl ElectingHeap {
    pub fn read_top_electing(&self) -> BTreeMap<AccountAddress, u64> {
        let mut top_electing: BTreeMap<AccountAddress, u64> = BTreeMap::new();
        let mut clone = self.clone();
        let mut count = 0usize;
        while let Some((_, node_id)) = clone.0.pop() {
            *top_electing.entry(node_id.node_id.addr).or_insert(0) += 1;
            count += 1;
            if count >= POS_STATE_CONFIG.term_elected_size() {
                break;
            }
        }
        top_electing
    }

    fn finalize(mut self) -> (ElectedMap, CandyMap) {
        let mut elected_map = ElectedMap::default();
        let mut count = 0usize;
        while let Some((_, node_id)) = self.0.pop() {
            *elected_map.0.entry(node_id.node_id.addr).or_insert(0) += 1;
            count += 1;
            if count >= POS_STATE_CONFIG.term_elected_size() {
                break;
            }
        }
        let mut candy_map = elected_map.clone();
        for (_, node_id) in self.0.into_vec().drain(..) {
            *candy_map.0.entry(node_id.node_id.addr).or_insert(0) += 1;
        }
        (elected_map, candy_map)
    }

    pub fn add_node(&mut self, hash: HashValue, node_id: ElectionNodeID) {
        let is_not_full_set = self.0.len() < POS_STATE_CONFIG.term_max_size();
        self.1.insert(node_id.node_id.addr.clone());
        if self
            .0
            .peek()
            .map_or(true, |(max_value, _)| is_not_full_set || hash < *max_value)
        {
            self.0.push((hash, node_id.clone()));
            if self.0.len() > POS_STATE_CONFIG.term_max_size() {
                self.0.pop();
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TermData {
    start_view: Round,
    seed: Vec<u8>,
    /// (VRF.val, NodeID)
    node_list: NodeList,
}

impl TermData {
    pub fn start_view(&self) -> u64 { self.start_view }

    pub fn get_term(&self) -> u64 {
        POS_STATE_CONFIG.get_term_view(self.start_view).0
    }

    pub fn node_list(&self) -> &NodeList { &self.node_list }
}

impl PartialEq for ElectingHeap {
    fn eq(&self, other: &Self) -> bool {
        if self.1 != other.1 {
            return false;
        }
        let mut iter_self = self.0.iter();
        let mut iter_other = other.0.iter();
        while let Some(node) = iter_self.next() {
            match iter_other.next() {
                None => return false,
                Some(other_node) => {
                    if node != other_node {
                        return false;
                    }
                }
            }
        }
        iter_other.next().is_none()
    }
}

impl Eq for ElectingHeap {}

impl TermData {
    fn next_term(&self, node_list: NodeList, seed: Vec<u8>) -> Self {
        TermData {
            start_view: self.start_view
                + POS_STATE_CONFIG.round_per_term(self.start_view),
            seed,
            node_list,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TermList {
    /// The current active term.
    /// After the first `TERM_LIST_LEN` terms, it should be the term of
    /// `term_list[TERM_LIST_LEN-1]`
    current_term: u64,
    /// The maintained term list. It should always have a length `TERM_LIST_LEN
    /// + 2`. The first `TERM_LIST_LEN` terms are used to validate new
    /// election transactions, and the last 2 terms are open for election.
    term_list: Vec<TermData>,
    candy_rewards: CandyMap,
    electing_index: usize,
}

impl TermList {
    fn start_term(&self) -> u64 {
        self.current_term.saturating_sub(TERM_LIST_LEN as u64 - 1)
    }

    fn committee_for_term(&self, term: u64) -> &[TermData] {
        let first_term = term.saturating_sub(TERM_LIST_LEN as u64 - 1) as usize;
        let last_term = first_term + TERM_LIST_LEN - 1;
        if first_term < self.start_term() as usize
            || last_term >= self.electing_term_number() as usize
        {
            panic!(
                "Can not get committee for term {}, current term {}",
                term, self.current_term
            );
        }
        let start_offset = first_term - self.start_term() as usize;
        let end_offset = last_term - self.start_term() as usize;
        &self.term_list[start_offset..=end_offset]
    }

    fn get_term_by_number(&self, term_number: u64) -> Option<&TermData> {
        let start_term = self.start_term();
        if term_number < start_term {
            return None;
        }
        self.term_list.get((term_number - start_term) as usize)
    }

    fn electing_term_number(&self) -> u64 {
        self.start_term() + self.electing_index as u64
    }

    fn electing_term_mut(&mut self) -> &mut TermData {
        &mut self.term_list[self.electing_index]
    }

    fn electing_term(&self) -> &TermData {
        &self.term_list[self.electing_index]
    }

    pub fn term_list(&self) -> &Vec<TermData> { &self.term_list }
}

impl TermList {
    /// Add a new node to term list after a valid Election transaction has been
    /// executed.
    pub fn new_node_elected(
        &mut self, event: &ElectionEvent, voting_power: u64,
    ) -> anyhow::Result<()> {
        if event.start_term != self.electing_term_number() {
            bail!("term is not open for election, opening term {}, election term {}", self.electing_term_number(),event.start_term);
        }
        let term = self.electing_term_mut();

        if term.node_list.has_elected(&event.node_id.addr) {
            diem_warn!(
                "The author {} has participated election for term {}",
                event.node_id.addr,
                event.start_term
            );
            return Ok(());
        }

        for nonce in 0..voting_power {
            // Hash after appending the nonce to get multiple identifier for
            // election.
            let priority = vrf_number_with_nonce(&event.vrf_output, nonce);
            term.node_list.add_node(
                priority,
                ElectionNodeID::new(event.node_id.clone(), nonce),
            );
        }
        Ok(())
    }

    pub fn new_term(&mut self, new_term: u64, new_seed: Vec<u8>) {
        diem_debug!(
            "new_term={}, start_view:{:?}",
            new_term,
            self.term_list
                .iter()
                .map(|t| (t.start_view, t.node_list.len()))
                .collect::<Vec<_>>()
        );
        self.current_term = new_term;
        if new_term < TERM_LIST_LEN as u64 {
            // The initial terms are not open for election.
            return;
        }
        // This double-check should always pass.
        debug_assert!(
            Some(self.term_list[TERM_LIST_LEN].start_view)
                == POS_STATE_CONFIG.get_starting_view_for_term(new_term)
        );
        self.term_list.remove(0);
        let new_term = self
            .term_list
            .last()
            .unwrap()
            .next_term(Default::default(), new_seed);
        self.term_list.push(new_term);
        self.electing_index -= 1;
        assert_eq!(self.electing_index, 6);
    }

    pub fn finalize_election(&mut self) {
        diem_debug!(
            "Finalize election of term {}",
            self.electing_term_number()
        );
        let finalize_term = self.electing_term_mut();
        let candy_map = finalize_term.node_list.finalize_elect();
        self.candy_rewards = candy_map;
        self.electing_index += 1;
        assert_eq!(self.electing_index, 7);
    }

    fn serving_votes(
        &self, target_term_offset: usize, author: &AccountAddress,
    ) -> u64 {
        assert!(
            target_term_offset >= TERM_LIST_LEN - 1
                && target_term_offset < TERM_LIST_LEN + 2
        );
        // TODO(lpl): Optimize by adding hash set to each term or adding another
        // field to node_map.
        let start_term_offset = target_term_offset - (TERM_LIST_LEN - 1);

        // The checking of `target_view` ensures that this is in range of
        // `term_list`.
        // For any valid `target_term_offset`, always checks to the end of
        // `term_list` because it's within the service time of
        // `target_term`.
        let mut serving_votes = Vec::with_capacity(TERM_LIST_LEN);
        for i in start_term_offset..target_term_offset {
            let term = &self.term_list[i];
            serving_votes.push(term.node_list.serving_votes(author));
        }
        return serving_votes.iter().sum();
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct DisputeRecord {
    /// Outlives `lock_until`: it is what stops the same evidence being filed
    /// again once the lock expires. Accepting `n` consumes every epoch below.
    last_offense_epoch: u64,
    /// Absolute, so a lost callback loses the bookkeeping but not the penalty.
    lock_until: View,
}

#[derive(Clone, Serialize, Eq, PartialEq, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct PosState {
    /// All the nodes that have staked in PoW.
    /// Nodes are only inserted and will never be removed.
    node_map: HashMap<AccountAddress, NodeData>,
    /// `current_view / TERM_LIST_LEN == term_list.current_term` is always
    /// true. This is not the same as `RoundState.current_view` because the
    /// view does not increase for blocks following a pending
    /// reconfiguration block.
    current_view: Round,
    /// Current epoch state
    epoch_state: EpochState,
    term_list: TermList,

    /// Track the nodes that have retired and are waiting to be unlocked.
    /// Nodes that are enqueued early will also become unlocked early.
    retiring_nodes: VecDeque<AccountAddress>,
    /// Current pivot decision.
    pivot_decision: PivotBlockDecision,

    node_map_hint: HashMap<View, HashSet<AccountAddress>>,
    unlock_event_hint: HashSet<AccountAddress>,

    /// If `skipped` is `true`, this PosState belongs to a block following a
    /// reconfiguration block, so this block is not executed and the
    /// PosState is the same as its parent. These skipped blocks have the
    /// same view as their parents and should not be saved as `CommittedBlock`.
    skipped: bool,

    /// Must stay last: BCS is a non-backtracking prefix parser, so a tail
    /// field is unambiguously absent from an older encoding, while one added
    /// earlier could be absorbed by a following length-prefixed field and
    /// decode as garbage.
    dispute_records: BTreeMap<AccountAddress, DisputeRecord>,
}

/// The layout before CIP-173 appended `dispute_records`. Must reuse the same
/// inner types: `NodeData`'s unchecked BLS deserializer accepts keys the
/// checked one rejects.
#[derive(Deserialize)]
struct PosStateV1 {
    node_map: HashMap<AccountAddress, NodeData>,
    current_view: Round,
    epoch_state: EpochState,
    term_list: TermList,
    retiring_nodes: VecDeque<AccountAddress>,
    pivot_decision: PivotBlockDecision,
    node_map_hint: HashMap<View, HashSet<AccountAddress>>,
    unlock_event_hint: HashSet<AccountAddress>,
    skipped: bool,
}

/// Encoding twin of [`PosStateV1`]; borrows to avoid cloning `node_map`.
#[derive(Serialize)]
struct PosStateV1Ref<'a> {
    node_map: &'a HashMap<AccountAddress, NodeData>,
    current_view: &'a Round,
    epoch_state: &'a EpochState,
    term_list: &'a TermList,
    retiring_nodes: &'a VecDeque<AccountAddress>,
    pivot_decision: &'a PivotBlockDecision,
    node_map_hint: &'a HashMap<View, HashSet<AccountAddress>>,
    unlock_event_hint: &'a HashSet<AccountAddress>,
    skipped: &'a bool,
}

impl From<PosStateV1> for PosState {
    fn from(v1: PosStateV1) -> Self {
        Self {
            node_map: v1.node_map,
            current_view: v1.current_view,
            epoch_state: v1.epoch_state,
            term_list: v1.term_list,
            retiring_nodes: v1.retiring_nodes,
            pivot_decision: v1.pivot_decision,
            node_map_hint: v1.node_map_hint,
            unlock_event_hint: v1.unlock_event_hint,
            skipped: v1.skipped,
            // The only reachable answer: a CIP-156 lock is indistinguishable
            // from an ordinary withdrawal, so locks already running cannot be
            // reconstructed and keep the pre-CIP-173 rules until they expire.
            dispute_records: BTreeMap::new(),
        }
    }
}

/// The on-disk encoding. Kept off the `Serialize`/`Deserialize` impls so a
/// future in-memory use of `PosState` cannot inherit the format fork.
impl PosState {
    pub fn encode_persisted(&self) -> Result<Vec<u8>> {
        // Past the gate the new layout goes out even when the map is empty, so
        // that a binary without CIP-173 fails to read the row instead of
        // booting and executing disputes under rules the chain has left.
        if self.dispute_records.is_empty()
            && !POS_STATE_CONFIG.cip173_active(self.current_view)
        {
            bcs::to_bytes(&PosStateV1Ref {
                node_map: &self.node_map,
                current_view: &self.current_view,
                epoch_state: &self.epoch_state,
                term_list: &self.term_list,
                retiring_nodes: &self.retiring_nodes,
                pivot_decision: &self.pivot_decision,
                node_map_hint: &self.node_map_hint,
                unlock_event_hint: &self.unlock_event_hint,
                skipped: &self.skipped,
            })
            .map_err(Into::into)
        } else {
            bcs::to_bytes(self).map_err(Into::into)
        }
    }

    pub fn decode_persisted(data: &[u8]) -> Result<Self> {
        // Complete BCS encodings are prefix-free, so the trial order is safe:
        // old bytes hit `Eof` under the current layout, and current bytes
        // leave a trailing map that `from_bytes` rejects as `RemainingInput`.
        let current_err = match bcs::from_bytes::<PosState>(data) {
            Ok(state) => return Ok(state),
            Err(e) => e,
        };
        let legacy: PosStateV1 =
            bcs::from_bytes(data).map_err(|legacy_err| {
                anyhow!(
                "PoS state decodes in neither layout: current={}, legacy={}",
                current_err,
                legacy_err
            )
            })?;
        // A state *at* the transition view came from a block whose parent was
        // still pre-CIP-173, so an older binary that stopped here was in the
        // right. One view further and it executed a block it should not have.
        ensure!(
            legacy.current_view <= POS_STATE_CONFIG.cip173_transition_view(),
            "PoS state at view {} is stored in the pre-CIP-173 layout, so it \
             was written past the transition view by a binary without \
             CIP-173; its dispute state is missing and cannot be recovered",
            legacy.current_view
        );
        Ok(legacy.into())
    }
}

impl Debug for PosState {
    fn fmt(
        &self, f: &mut Formatter<'_>,
    ) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("PosState")
            .field("view", &self.current_view)
            .field("node_map_size", &self.node_map.len())
            .field("term_list", &self.term_list)
            .field("epoch_state", &self.epoch_state)
            .finish()
    }
}

impl PosState {
    pub fn new(
        initial_seed: Vec<u8>, initial_nodes: Vec<(NodeID, u64)>,
        initial_committee: Vec<(AccountAddress, u64)>,
        genesis_pivot_decision: PivotBlockDecision,
    ) -> Self {
        let mut node_map = HashMap::new();
        let mut node_list = BTreeMap::default();
        for (node_id, total_voting_power) in initial_nodes {
            let mut lock_status = NodeLockStatus::default();
            // The genesis block should not have updates for lock status.
            lock_status.new_lock(
                0,
                total_voting_power,
                true,
                None,
                &mut Vec::new(),
            );
            node_map.insert(
                node_id.addr.clone(),
                NodeData {
                    public_key: node_id.public_key.clone(),
                    vrf_public_key: Some(node_id.vrf_public_key.clone()),
                    lock_status,
                },
            );
        }
        for (addr, voting_power) in initial_committee {
            // VRF output of initial terms will not be used, because these terms
            // are not open for election.
            node_list.insert(addr, voting_power);
        }
        let mut term_list = Vec::new();
        let initial_term = TermData {
            start_view: 0,
            seed: initial_seed.clone(),
            node_list: NodeList::Elected(ElectedMap(node_list.clone())),
        };
        term_list.push(initial_term);
        // TODO(lpl): The initial terms can have different node list.
        // Duplicate the initial term for the first TERM_LIST_LEN + 2 terms.
        for i in 0..(TERM_LIST_LEN + 1) {
            let last_term = term_list.last().unwrap();
            let mut next_term =
                last_term.next_term(Default::default(), initial_seed.clone());
            if i < TERM_LIST_LEN - 1 {
                let _ = next_term.node_list.finalize_elect();
            }
            term_list.push(next_term);
        }
        let mut pos_state = PosState {
            node_map,
            current_view: 0,
            epoch_state: EpochState::empty(),
            term_list: TermList {
                current_term: 0,
                term_list,
                electing_index: TERM_LIST_LEN,
                candy_rewards: ElectedMap(node_list),
            },
            retiring_nodes: Default::default(),
            pivot_decision: genesis_pivot_decision,
            node_map_hint: Default::default(),
            unlock_event_hint: Default::default(),
            skipped: false,
            dispute_records: Default::default(),
        };
        let (verifier, vrf_seed) = pos_state.get_committee_at(0).unwrap();
        pos_state.epoch_state = EpochState::new(0, verifier, vrf_seed);
        pos_state
    }

    pub fn new_empty() -> Self {
        Self {
            node_map: Default::default(),
            current_view: 0,
            epoch_state: EpochState::empty(),
            term_list: TermList {
                current_term: 0,
                term_list: Default::default(),
                electing_index: 0,
                candy_rewards: Default::default(),
            },
            retiring_nodes: Default::default(),
            node_map_hint: Default::default(),
            unlock_event_hint: Default::default(),
            pivot_decision: PivotBlockDecision {
                block_hash: Default::default(),
                height: 0,
            },
            skipped: false,
            dispute_records: Default::default(),
        }
    }

    pub fn set_skipped(&mut self, skipped: bool) { self.skipped = skipped; }

    pub fn set_pivot_decision(&mut self, pivot_decision: PivotBlockDecision) {
        self.pivot_decision = pivot_decision;
    }

    pub fn pivot_decision(&self) -> &PivotBlockDecision { &self.pivot_decision }

    // pub fn current_term_seed(&self) -> &Vec<u8> {
    //     self.target_term_seed(self.term_list.current_term)
    // }

    pub fn target_term_seed(&self, target_term: u64) -> &Vec<u8> {
        &self
            .term_list
            .get_term_by_number(target_term)
            .expect("term not in term list")
            .seed
    }

    pub fn epoch_state(&self) -> &EpochState { &self.epoch_state }

    pub fn term_list(&self) -> &TermList { &self.term_list }

    pub fn account_node_data(
        &self, account_address: AccountAddress,
    ) -> Option<&NodeData> {
        self.node_map.get(&account_address)
    }
}

/// Read-only functions use in `TransactionValidator`
impl PosState {
    /// Binds `sender` to a slot the submitter actually controls by
    /// requiring `node_map[sender].public_key == auth_pk`. Returns the
    /// `NodeData` so callers can reuse the borrow.
    fn check_sender_owns_auth_key(
        &self, sender: &AccountAddress, auth_pk: &ConsensusPublicKey,
        not_registered: DiscardedVMStatus,
    ) -> Result<&NodeData, DiscardedVMStatus> {
        let node = self.account_node_data(*sender).ok_or(not_registered)?;
        if &node.public_key != auth_pk {
            return Err(DiscardedVMStatus::AUTHENTICATOR_KEY_MISMATCH);
        }
        Ok(node)
    }

    pub fn validate_election_simple(
        &self, sender: &AccountAddress, auth_pk: &ConsensusPublicKey,
        election_tx: &ElectionPayload,
    ) -> Option<DiscardedVMStatus> {
        let node_id = NodeID::new(
            election_tx.public_key.clone(),
            election_tx.vrf_public_key.clone(),
        );
        diem_trace!(
            "validate_election_simple: {:?} {}",
            node_id.addr,
            election_tx.target_term
        );
        // Sender must match the addr derived from the payload's
        // declared keys, so a registered submitter can't stuff another
        // node's payload keys.
        if *sender != node_id.addr {
            return Some(DiscardedVMStatus::ELECTION_SIGNER_MISMATCH);
        }
        let node = match self.check_sender_owns_auth_key(
            sender,
            auth_pk,
            DiscardedVMStatus::ELECTION_NON_EXISTENT_NODE,
        ) {
            Ok(node) => node,
            Err(err) => return Some(err),
        };

        let target_view = match POS_STATE_CONFIG
            .get_starting_view_for_term(election_tx.target_term)
        {
            None => {
                return Some(DiscardedVMStatus::ELECTION_TARGET_TERM_NOT_OPEN)
            }
            Some(v) => v,
        };

        if node.lock_status.available_votes() == 0 {
            return Some(DiscardedVMStatus::ELECTION_WITHOUT_VOTES);
        }
        // Do not check `ELECTION_TERM_END_ROUND` because we are using the
        // committed state in this simple validation.
        if target_view
            <= self.current_view
                + POS_STATE_CONFIG.election_term_end_round(self.current_view)
        {
            return Some(DiscardedVMStatus::ELECTION_TARGET_TERM_NOT_OPEN);
        }
        None
    }

    pub fn validate_pivot_decision_simple(
        &self, sender: &AccountAddress, auth_pk: &ConsensusPublicKey,
        pivot_decision_tx: &PivotBlockDecision,
    ) -> Option<DiscardedVMStatus> {
        // node_map (not active-committee): PivotDecision is gossiped
        // per round and committee gating would drop newly-joined
        // members at every term boundary.
        if let Err(err) = self.check_sender_owns_auth_key(
            sender,
            auth_pk,
            DiscardedVMStatus::PIVOT_DECISION_SENDER_NOT_REGISTERED,
        ) {
            return Some(err);
        }
        if pivot_decision_tx.height <= self.pivot_decision.height {
            return Some(DiscardedVMStatus::PIVOT_DECISION_HEIGHT_TOO_OLD);
        }
        None
    }

    pub fn validate_dispute_simple(
        &self, sender: &AccountAddress, auth_pk: &ConsensusPublicKey,
    ) -> Option<DiscardedVMStatus> {
        // Registered-node gating; `verify_dispute` runs at execute time.
        self.check_sender_owns_auth_key(
            sender,
            auth_pk,
            DiscardedVMStatus::DISPUTE_SENDER_NOT_REGISTERED,
        )
        .err()
    }
}

/// Read-only functions used in `execute_block`
impl PosState {
    pub fn validate_election(
        &self, election_tx: &ElectionPayload,
    ) -> Result<()> {
        let node_id = NodeID::new(
            election_tx.public_key.clone(),
            election_tx.vrf_public_key.clone(),
        );
        diem_trace!(
            "validate_election: {:?} {}",
            node_id.addr,
            election_tx.target_term
        );
        let node = match self.node_map.get(&node_id.addr) {
            Some(node) => node,
            None => return Err(anyhow!("Election for non-existent node.")),
        };

        if node.lock_status.available_votes() == 0 {
            bail!("Election without any votes");
        }
        let target_view = match POS_STATE_CONFIG
            .get_starting_view_for_term(election_tx.target_term)
        {
            None => {
                bail!("target view overflows, election_tx={:?}", election_tx)
            }
            Some(v) => v,
        };
        if target_view
            > self.current_view
                + POS_STATE_CONFIG.election_term_start_round(self.current_view)
            || target_view
                <= self.current_view
                    + POS_STATE_CONFIG
                        .election_term_end_round(self.current_view)
        {
            bail!(
                "Target term is not open for election: target={} current={}",
                target_view,
                self.current_view
            );
        }

        let target_term_offset =
            (election_tx.target_term - self.term_list.start_term()) as usize;
        assert_eq!(target_term_offset, self.term_list.electing_index);

        let target_term = &self.term_list.electing_term();
        if election_tx
            .vrf_proof
            .verify(&target_term.seed, node.vrf_public_key.as_ref().unwrap())
            .is_err()
        {
            bail!("Invalid VRF proof for election")
        }

        if target_term.node_list.has_elected(&node_id.addr) {
            bail!("The sender has elected for this term")
        }

        if node.lock_status.available_votes()
            <= self
                .term_list
                .serving_votes(target_term_offset, &node_id.addr)
        {
            bail!("Election without enough votes");
        }

        Ok(())
    }

    pub fn validate_pivot_decision(
        &self, pivot_decision_tx: &PivotBlockDecision,
        signature: MultiConsensusSignature,
    ) -> Result<()> {
        if pivot_decision_tx.height <= self.pivot_decision.height {
            return Err(anyhow!(format!(
                "Pivot Decision height too small, found[{}], expect[{}]",
                pivot_decision_tx.height, self.pivot_decision.height
            )));
        }
        let senders: Vec<_> = self
            .epoch_state
            .verifier()
            .address_to_validator_info()
            .keys()
            .cloned()
            .collect();
        let public_keys: Vec<ConsensusPublicKey> = senders
            .iter()
            .map(|sender| {
                self.epoch_state.verifier().get_public_key(sender).unwrap()
            })
            .collect();
        let public_key = MultiConsensusPublicKey::new(public_keys);
        if let Err(e) = signature.verify(pivot_decision_tx, &public_key) {
            return Err(anyhow!(format!(
                "Pivot Decision verification failed [{:?}]",
                e
            )));
        }
        let signers = signature.get_signers(&senders)?;
        if let Err(e) = self
            .epoch_state()
            .verifier()
            .check_voting_power(signers.iter())
        {
            return Err(anyhow!(format!(
                "Pivot Decision voting power check failed [{:?}]",
                e
            )));
        }
        Ok(())
    }

    pub fn validate_dispute(
        &self, dispute_payload: &DisputePayload, offense_epoch: u64,
    ) -> Result<()> {
        let node =
            self.node_map.get(&dispute_payload.address).ok_or_else(|| {
                anyhow!("Unknown dispute node: {:?}", dispute_payload.address)
            })?;
        ensure!(
            node.lock_status.exempt_from_forfeit().is_none(),
            "Dispute a forfeited node: {:?}",
            dispute_payload.address
        );
        if POS_STATE_CONFIG.cip173_active(self.current_view) {
            self.check_dispute_admissible(
                &dispute_payload.address,
                offense_epoch,
            )?;
        }
        Ok(())
    }

    fn check_dispute_admissible(
        &self, address: &AccountAddress, offense_epoch: u64,
    ) -> Result<()> {
        let first_admissible = POS_STATE_CONFIG
            .dispute_first_admissible_epoch()
            .ok_or_else(|| {
                anyhow!("CIP-173 active with no scheduled transition view")
            })?;
        ensure!(
            offense_epoch >= first_admissible,
            "Dispute evidence predates CIP-173: offence epoch {}, first \
             admissible {}",
            offense_epoch,
            first_admissible
        );
        ensure!(
            offense_epoch <= self.epoch_state.epoch,
            "Dispute evidence claims an unreached epoch: offence epoch {}, \
             current epoch {}",
            offense_epoch,
            self.epoch_state.epoch
        );
        if let Some(record) = self.dispute_records.get(address) {
            ensure!(
                offense_epoch > record.last_offense_epoch,
                "Dispute evidence already punished: offence epoch {}, \
                 watermark {}",
                offense_epoch,
                record.last_offense_epoch
            );
        }
        Ok(())
    }

    /// Return `(validator_set, term_seed)`.
    pub fn get_committee_at(
        &self, term: u64,
    ) -> Result<(ValidatorVerifier, Vec<u8>)> {
        diem_debug!(
            "Get committee at term {} in view {}, term list start at {}",
            term,
            self.current_view,
            self.term_list.start_term()
        );
        let mut voting_power_map = BTreeMap::new();
        for term_data in self.term_list.committee_for_term(term) {
            for (addr, votes) in term_data.node_list.committee().0.iter() {
                *voting_power_map.entry(addr.clone()).or_insert(0 as u64) +=
                    votes;
            }
        }
        let mut address_to_validator_info = BTreeMap::new();
        for (addr, voting_power) in voting_power_map {
            let node_data = self.node_map.get(&addr).expect("node in node_map");
            // Retired nodes are not removed from term_list,
            // but we do not include them in the new committee.
            let voting_power = std::cmp::min(
                voting_power,
                node_data.lock_status.available_votes(),
            );
            if voting_power > 0 {
                address_to_validator_info.insert(
                    addr,
                    ValidatorConsensusInfo::new(
                        node_data.public_key.clone(),
                        node_data.vrf_public_key.clone(),
                        voting_power,
                    ),
                );
            }
        }

        Ok((
            ValidatorVerifier::new(address_to_validator_info),
            self.term_list.term_list[0].seed.clone(),
        ))
    }

    /// TODO(lpl): Return VDF seed for the term.
    /// Return `Some(target_term)` if `author` should send its election
    /// transaction.
    pub fn next_elect_term(&self, author: &AccountAddress) -> Option<u64> {
        if self.current_view
            < POS_STATE_CONFIG.first_start_election_view() as u64
        {
            return None;
        }

        if self.term_list.electing_term().node_list.has_elected(author) {
            return None;
        }

        if let Some(node) = self.node_map.get(author) {
            let available_votes = node.lock_status.available_votes();
            let serving_votes = self
                .term_list
                .serving_votes(self.term_list.electing_index, author);

            return if available_votes > serving_votes {
                Some(self.term_list.electing_term_number())
            } else {
                None
            };
        }

        None
    }

    pub fn final_serving_view(&self, author: &AccountAddress) -> Option<Round> {
        let mut final_elected_term = None;
        for term in self.term_list.term_list.iter().rev() {
            match &term.node_list {
                NodeList::Electing(heap) => {
                    if heap.1.contains(author) {
                        final_elected_term = Some(term.get_term());
                        break;
                    }
                }
                NodeList::Elected(map) => {
                    if map.0.contains_key(author) {
                        final_elected_term = Some(term.get_term());
                        break;
                    }
                }
            }
        }
        final_elected_term.map(|t| {
            POS_STATE_CONFIG
                .get_starting_view_for_term(t + TERM_LIST_LEN as u64)
                .expect("checked term")
                + 1
        })
    }

    pub fn get_unlock_events(&self) -> Vec<ContractEvent> {
        let mut unlocked_nodes = Vec::new();
        for addr in &self.unlock_event_hint {
            let node = self.node_map.get(&addr).expect("exists");
            let unlock_event = ContractEvent::new(
                UnlockEvent::event_key(),
                bcs::to_bytes(&UnlockEvent {
                    node_id: *addr,
                    unlocked: node.lock_status.unlocked_votes(),
                })
                .unwrap(),
            );
            unlocked_nodes.push(unlock_event);
        }

        return unlocked_nodes;
    }

    pub fn current_view(&self) -> u64 { self.current_view }

    pub fn skipped(&self) -> bool { self.skipped }

    pub fn next_evicted_term(&mut self) -> BTreeMap<H256, u64> {
        let candy_rewards = std::mem::take(&mut self.term_list.candy_rewards);
        candy_rewards
            .0
            .iter()
            .map(|(id, cnt)| (H256::from(id.to_u8()), *cnt))
            .collect()
    }
}

/// Write functions used apply changes (process events in PoS and PoW)
impl PosState {
    pub fn register_node(&mut self, node_id: NodeID) -> Result<()> {
        diem_trace!("register_node: {:?}", node_id);
        ensure!(
            !self.node_map.contains_key(&node_id.addr),
            "register an already registered address"
        );
        self.node_map.insert(
            node_id.addr,
            NodeData {
                public_key: node_id.public_key,
                vrf_public_key: Some(node_id.vrf_public_key),
                lock_status: NodeLockStatus::default(),
            },
        );
        Ok(())
    }

    pub fn update_voting_power(
        &mut self, addr: &AccountAddress, increased_voting_power: u64,
    ) -> Result<()> {
        diem_trace!(
            "update_voting_power: {:?} {}",
            addr,
            increased_voting_power
        );
        let view = self.current_view;
        let dispute_lock_until = self
            .dispute_records
            .get(addr)
            .map(|record| record.lock_until)
            .filter(|lock_until| view < *lock_until);
        let mut update_views = Vec::new();
        match self.node_map.get_mut(addr) {
            Some(node_status) => node_status.lock_status.new_lock(
                view,
                increased_voting_power,
                false,
                dispute_lock_until,
                &mut update_views,
            ),
            None => bail!("increase voting power of a non-existent node!"),
        };
        self.record_update_views(addr, update_views);
        Ok(())
    }

    pub fn new_node_elected(&mut self, event: &ElectionEvent) -> Result<()> {
        diem_debug!(
            "new_node_elected: {:?} {:?}",
            event.node_id,
            event.start_term
        );
        let author = &event.node_id.addr;
        let available_votes = self
            .node_map
            .get(author)
            .expect("checked in execution")
            .lock_status
            .available_votes();
        let target_term_offset =
            (event.start_term - self.term_list.start_term()) as usize;
        let serving_votes =
            self.term_list.serving_votes(target_term_offset, author);
        let voting_power = available_votes.saturating_sub(serving_votes);
        if voting_power > 0 {
            // A workaround for too much staked CFX in Testnet.
            let bounded_power = std::cmp::min(
                voting_power,
                POS_STATE_CONFIG.max_nonce_per_account(self.current_view()),
            );
            self.term_list.new_node_elected(event, bounded_power)?;
        } else {
            diem_warn!("No votes can be elected: {:?} {:?}. available: {}, serving: {}.", event.node_id,
            event.start_term,available_votes,serving_votes);
        }
        Ok(())
    }

    /// `get_new_committee` has been called before this to produce an
    /// EpochState. And `next_view` will not be called for blocks following
    /// a pending reconfiguration block.
    pub fn next_view(&mut self) -> Result<Option<EpochState>> {
        // Increase view after updating node status above to get a correct
        // `status_start_view`.
        self.current_view += 1;

        diem_debug!("current view {}", self.current_view);

        // Update the status for the all.
        self.unlock_event_hint.clear();

        if let Some(addresses) = self.node_map_hint.remove(&self.current_view) {
            for address in addresses {
                let node = self.node_map.get_mut(&address).expect("exists");
                let new_votes_unlocked =
                    node.lock_status.update(self.current_view);
                if new_votes_unlocked {
                    self.unlock_event_hint.insert(address);
                }
            }
        }

        let epoch_state = if self.current_view == 1 {
            let (verifier, term_seed) = self.get_committee_at(0)?;
            // genesis
            Some(EpochState::new(1, verifier, term_seed.clone()))
        } else {
            let (term, view_in_term) =
                POS_STATE_CONFIG.get_term_view(self.current_view);
            if view_in_term == 0 {
                let new_term = term;
                let (verifier, term_seed) = self.get_committee_at(new_term)?;
                // generate new epoch for new term.
                self.term_list.new_term(
                    new_term,
                    self.pivot_decision.block_hash.as_bytes().to_vec(),
                );
                // TODO(lpl): If we allow epoch changes within a term, this
                // should be updated.
                Some(EpochState::new(new_term + 1, verifier, term_seed.clone()))
            } else if self.current_view
                >= POS_STATE_CONFIG.first_end_election_view()
                && view_in_term
                    == POS_STATE_CONFIG.round_per_term(self.current_view) / 2
            {
                self.term_list.finalize_election();
                None
            } else {
                None
            }
        };
        if let Some(epoch_state) = &epoch_state {
            self.epoch_state = epoch_state.clone();
        }
        Ok(epoch_state)
    }

    pub fn retire_node(
        &mut self, addr: &AccountAddress, votes: u64,
    ) -> Result<()> {
        diem_trace!("retire_node: {:?} {}", addr, votes);
        let mut update_views = Vec::new();
        match self.node_map.get_mut(&addr) {
            Some(node) => {
                node.lock_status.new_unlock(
                    self.current_view,
                    votes,
                    &mut update_views,
                );
            }
            None => bail!("Retiring node does not exist"),
        };
        self.record_update_views(addr, update_views);
        Ok(())
    }

    pub fn force_retire_node(&mut self, addr: &AccountAddress) -> Result<()> {
        diem_trace!("force_retire_node: {:?}", addr);
        let mut update_views = Vec::new();
        match self.node_map.get_mut(&addr) {
            Some(node) => node
                .lock_status
                .force_retire(self.current_view, &mut update_views),
            None => bail!("Force retiring node does not exist"),
        };
        self.record_update_views(addr, update_views);
        Ok(())
    }

    /// `None` for the pre-CIP-173 event, which carries no offence epoch.
    pub fn forfeit_node(
        &mut self, addr: &AccountAddress, offense_epoch: Option<u64>,
    ) -> Result<()> {
        diem_trace!("forfeit_node: {:?} {:?}", addr, offense_epoch);
        let view = self.current_view;
        let previous = self.dispute_records.get(addr).copied();

        let (rule, record) = match POS_STATE_CONFIG.dispute_locked_views(view) {
            None => (ForfeitRule::FreezeWithdrawable, None),
            Some(locked_views) if !POS_STATE_CONFIG.cip173_active(view) => (
                ForfeitRule::RelockOnActive {
                    deadline: view.saturating_add(locked_views),
                },
                None,
            ),
            Some(locked_views) => {
                let offense_epoch = offense_epoch.ok_or_else(|| {
                    anyhow!("CIP-173 dispute event without an offence epoch")
                })?;
                if previous
                    .map_or(false, |r| offense_epoch <= r.last_offense_epoch)
                {
                    // Both copies of a duplicated dispute are validated
                    // against the same parent state, so both reach here.
                    // Rejecting the second would invalidate the whole block an
                    // honest proposer built.
                    return Ok(());
                }
                let deadline = view
                    .saturating_add(locked_views)
                    .max(previous.map_or(0, |r| r.lock_until));
                (
                    ForfeitRule::RelockAll { deadline },
                    Some(DisputeRecord {
                        last_offense_epoch: offense_epoch,
                        lock_until: deadline,
                    }),
                )
            }
        };

        let mut update_views = Vec::new();
        match self.node_map.get_mut(&addr) {
            Some(node) => node.lock_status.forfeit(rule, &mut update_views),
            None => bail!("Forfeiting node does not exist"),
        }
        if let Some(record) = record {
            self.dispute_records.insert(*addr, record);
        }
        self.record_update_views(addr, update_views);
        Ok(())
    }
}

impl PosState {
    pub fn record_update_views(
        &mut self, address: &AccountAddress, views: Vec<View>,
    ) {
        for view in views {
            diem_trace!(
                "{:?} will update lock status at view {}",
                address,
                view
            );
            self.node_map_hint.entry(view).or_default().insert(*address);
        }
    }
}

// impl Default for PosState {
//     fn default() -> Self {
//         Self {
//             node_map: Default::default(),
//             current_view: 0,
//             term_list: TermList {
//                 current_term: 0,
//                 term_list: Default::default(),
//             },
//         }
//     }
// }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ElectionEvent {
    node_id: NodeID,
    vrf_output: HashValue,
    start_term: u64,
}

impl ElectionEvent {
    pub fn new(
        public_key: ConsensusPublicKey, vrf_public_key: ConsensusVRFPublicKey,
        vrf_output: HashValue, start_term: u64,
    ) -> Self {
        Self {
            node_id: NodeID::new(public_key, vrf_public_key),
            vrf_output,
            start_term,
        }
    }
}

impl ElectionEvent {
    pub fn event_key() -> EventKey {
        EventKey::new_from_address(
            &account_config::election_select_address(),
            3,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetireEvent {
    pub node_id: AccountAddress,
    pub votes: u64,
}

impl RetireEvent {
    pub fn new(node_id: AccountAddress, votes: u64) -> Self {
        RetireEvent { node_id, votes }
    }

    pub fn event_key() -> EventKey {
        EventKey::new_from_address(&account_config::retire_address(), 4)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }

    pub fn matches_staking_event(
        &self, staking_event: &StakingEvent,
    ) -> Result<bool> {
        match staking_event {
            StakingEvent::Retire(addr_h256, votes) => {
                let addr = AccountAddress::from_bytes(addr_h256)?;
                Ok(self.node_id == addr && self.votes == *votes)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterEvent {
    pub node_id: NodeID,
}

impl RegisterEvent {
    pub fn new(
        public_key: ConsensusPublicKey, vrf_public_key: ConsensusVRFPublicKey,
    ) -> Self {
        Self {
            node_id: NodeID::new(public_key, vrf_public_key),
        }
    }

    pub fn event_key() -> EventKey {
        EventKey::new_from_address(&account_config::register_address(), 5)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }

    pub fn matches_staking_event(
        &self, staking_event: &StakingEvent,
    ) -> Result<bool> {
        match staking_event {
            StakingEvent::Register(
                addr_h256,
                bls_pub_key_bytes,
                vrf_pub_key_bytes,
            ) => {
                let addr = AccountAddress::from_bytes(addr_h256)?;
                let public_key =
                    ConsensusPublicKey::try_from(bls_pub_key_bytes.as_slice())?;
                let vrf_public_key = ConsensusVRFPublicKey::try_from(
                    vrf_pub_key_bytes.as_slice(),
                )?;
                let node_id =
                    NodeID::new(public_key.clone(), vrf_public_key.clone());
                ensure!(
                    node_id.addr == addr,
                    "register event has unmatching address and keys"
                );
                Ok(self.node_id == node_id)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateVotingPowerEvent {
    pub node_address: AccountAddress,
    pub voting_power: u64,
}

impl UpdateVotingPowerEvent {
    pub fn new(node_address: AccountAddress, voting_power: u64) -> Self {
        Self {
            node_address,
            voting_power,
        }
    }

    pub fn event_key() -> EventKey {
        EventKey::new_from_address(
            &account_config::update_voting_power_address(),
            6,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }

    pub fn matches_staking_event(
        &self, staking_event: &StakingEvent,
    ) -> Result<bool> {
        match staking_event {
            StakingEvent::IncreaseStake(addr_h256, updated_voting_power) => {
                let addr = AccountAddress::from_bytes(addr_h256)?;
                Ok(self.node_address == addr
                    && self.voting_power == *updated_voting_power)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct NodeID {
    pub public_key: ConsensusPublicKey,
    pub vrf_public_key: ConsensusVRFPublicKey,

    /// Computed based on other fields.
    pub addr: AccountAddress,
}

impl NodeID {
    pub fn new(
        public_key: ConsensusPublicKey, vrf_public_key: ConsensusVRFPublicKey,
    ) -> Self {
        let addr = from_consensus_public_key(&public_key, &vrf_public_key);
        Self {
            public_key,
            vrf_public_key,
            addr,
        }
    }
}

impl Ord for NodeID {
    fn cmp(&self, other: &Self) -> Ordering { self.addr.cmp(&other.addr) }
}

impl PartialOrd for NodeID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UnlockEvent {
    /// The node id to unlock.
    ///
    /// The management contract should unlock the corresponding account.
    pub node_id: AccountAddress,
    pub unlocked: u64,
}

impl UnlockEvent {
    pub fn event_key() -> EventKey {
        EventKey::new_from_address(&account_config::unlock_address(), 5)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeEvent {
    /// The node id to dispute.
    pub node_id: AccountAddress,
}

impl DisputeEvent {
    pub fn event_key() -> EventKey {
        EventKey::new_from_address(&account_config::dispute_address(), 6)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}

/// A separate event key rather than a field on `DisputeEvent`, so the
/// pre-activation encoding stays byte-identical for replay.
#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeEventV2 {
    pub node_id: AccountAddress,
    pub offense_epoch: u64,
}

impl DisputeEventV2 {
    pub fn event_key() -> EventKey {
        EventKey::new_from_address(&account_config::dispute_address(), 7)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}

/// Decode either dispute event, `None` for any other key. Both versions are
/// recognised in one place so a third consumer cannot support one and silently
/// drop the other.
pub fn decode_dispute_event(
    event: &ContractEvent,
) -> Option<anyhow::Result<(AccountAddress, Option<u64>)>> {
    if *event.key() == DisputeEvent::event_key() {
        Some(
            DisputeEvent::from_bytes(event.event_data())
                .map(|e| (e.node_id, None)),
        )
    } else if *event.key() == DisputeEventV2::event_key() {
        Some(
            DisputeEventV2::from_bytes(event.event_data())
                .map(|e| (e.node_id, Some(e.offense_epoch))),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block_info::PivotBlockDecision,
        term_state::pos_state_config::PosStateConfig,
        transaction::ElectionPayload, validator_config::ConsensusVRFProof,
    };
    use diem_crypto::{
        bls::BLSPrivateKey,
        ec_vrf::{EcVrfPrivateKey, EcVrfProof},
        PrivateKey, Uniform,
    };
    use rand::{rngs::StdRng, SeedableRng};

    struct Keys {
        bls_pk: ConsensusPublicKey,
        vrf_pk: ConsensusVRFPublicKey,
        addr: AccountAddress,
    }

    fn keys_from_seed(seed: u64) -> Keys {
        let mut rng = StdRng::seed_from_u64(seed);
        let bls_sk = BLSPrivateKey::generate(&mut rng);
        let bls_pk = bls_sk.public_key();
        let vrf_sk = EcVrfPrivateKey::generate(&mut rng);
        let vrf_pk = vrf_sk.public_key();
        let node_id = NodeID::new(bls_pk.clone(), vrf_pk.clone());
        Keys {
            bls_pk,
            vrf_pk,
            addr: node_id.addr,
        }
    }

    // simple-validation doesn't verify the VRF proof, so any bytes work.
    fn dummy_vrf_proof() -> ConsensusVRFProof {
        EcVrfProof::try_from(&[][..]).unwrap()
    }

    fn state_with_node(k: &Keys) -> PosState {
        let mut state = PosState::new_empty();
        state
            .register_node(NodeID::new(k.bls_pk.clone(), k.vrf_pk.clone()))
            .expect("register_node");
        state
    }

    #[test]
    fn pivot_decision_rejects_unregistered_sender() {
        let alice = keys_from_seed(1);
        let mallory = keys_from_seed(2);
        let state = state_with_node(&alice);

        let tx = PivotBlockDecision {
            block_hash: Default::default(),
            height: 1,
        };
        assert_eq!(
            state.validate_pivot_decision_simple(
                &mallory.addr,
                &mallory.bls_pk,
                &tx
            ),
            Some(DiscardedVMStatus::PIVOT_DECISION_SENDER_NOT_REGISTERED),
        );
    }

    #[test]
    fn pivot_decision_rejects_auth_key_mismatch() {
        let alice = keys_from_seed(1);
        let mallory = keys_from_seed(2);
        let state = state_with_node(&alice);

        let tx = PivotBlockDecision {
            block_hash: Default::default(),
            height: 1,
        };
        assert_eq!(
            state.validate_pivot_decision_simple(
                &alice.addr,
                &mallory.bls_pk,
                &tx
            ),
            Some(DiscardedVMStatus::AUTHENTICATOR_KEY_MISMATCH),
        );
    }

    #[test]
    fn pivot_decision_accepts_legitimate_self_signed() {
        let alice = keys_from_seed(1);
        let state = state_with_node(&alice);

        let tx = PivotBlockDecision {
            block_hash: Default::default(),
            height: 1,
        };
        assert_eq!(
            state.validate_pivot_decision_simple(
                &alice.addr,
                &alice.bls_pk,
                &tx
            ),
            None,
        );
    }

    #[test]
    fn dispute_rejects_unregistered_sender() {
        let alice = keys_from_seed(1);
        let mallory = keys_from_seed(2);
        let state = state_with_node(&alice);

        assert_eq!(
            state.validate_dispute_simple(&mallory.addr, &mallory.bls_pk),
            Some(DiscardedVMStatus::DISPUTE_SENDER_NOT_REGISTERED),
        );
    }

    #[test]
    fn dispute_rejects_auth_key_mismatch() {
        let alice = keys_from_seed(1);
        let mallory = keys_from_seed(2);
        let state = state_with_node(&alice);

        assert_eq!(
            state.validate_dispute_simple(&alice.addr, &mallory.bls_pk),
            Some(DiscardedVMStatus::AUTHENTICATOR_KEY_MISMATCH),
        );
    }

    #[test]
    fn dispute_accepts_legitimate_self_signed() {
        let alice = keys_from_seed(1);
        let state = state_with_node(&alice);

        assert_eq!(
            state.validate_dispute_simple(&alice.addr, &alice.bls_pk),
            None,
        );
    }

    /// Two whole terms in, so the transition view starts one.
    const TRANSITION: View = 2 * ROUND_PER_TERM;
    /// Epoch `n` is term `n - 1`, so this is the first epoch CIP-173 admits.
    const FIRST_EPOCH: u64 = 3;
    const DISPUTE_LOCK: u64 = 1000;

    fn install_config() {
        const M: u64 = u64::MAX;
        POS_STATE_CONFIG.get_or_init(|| {
            PosStateConfig::new(
                ROUND_PER_TERM,
                TERM_MAX_SIZE,
                TERM_ELECTED_SIZE,
                IN_QUEUE_LOCKED_VIEWS,
                OUT_QUEUE_LOCKED_VIEWS,
                M,
                0,
                0,
                // fix_cip99_* is mainnet-only and absent from master's helper;
                // M keeps it unscheduled so the test sees master's behaviour.
                M,
                0,
                0,
                M,
                M,
                M,
                0,
                0,
                ROUND_PER_TERM,
                0,
                DISPUTE_LOCK,
                TRANSITION,
            )
        });
    }

    fn staked_state(k: &Keys, view: View, epoch: u64, votes: u64) -> PosState {
        install_config();
        let mut state = state_with_node(k);
        state.current_view = view;
        state.epoch_state.epoch = epoch;
        state.update_voting_power(&k.addr, votes).expect("staked");
        state
    }

    fn dispute_of(k: &Keys) -> DisputePayload {
        DisputePayload {
            address: k.addr,
            bls_pub_key: k.bls_pk.clone(),
            vrf_pub_key: k.vrf_pk.clone(),
            conflicting_votes: crate::transaction::ConflictSignature::Vote((
                vec![],
                vec![],
            )),
        }
    }

    fn lock_status_of<'a>(
        state: &'a PosState, k: &Keys,
    ) -> &'a lock_status::NodeLockStatus {
        &state.node_map.get(&k.addr).expect("registered").lock_status
    }

    fn exits_of(state: &PosState, k: &Keys) -> Vec<View> {
        lock_status_of(state, k)
            .out_queue
            .iter()
            .map(|item| item.view)
            .collect()
    }

    #[test]
    fn dispute_locks_stake_and_records_the_offence() {
        let alice = keys_from_seed(1);
        let mut state = staked_state(&alice, TRANSITION, FIRST_EPOCH, 10);
        assert_eq!(lock_status_of(&state, &alice).available_votes(), 10);

        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("forfeit");

        assert_eq!(lock_status_of(&state, &alice).available_votes(), 0);
        assert_eq!(exits_of(&state, &alice), vec![TRANSITION + DISPUTE_LOCK]);
        let record = *state.dispute_records.get(&alice.addr).expect("recorded");
        assert_eq!(record.last_offense_epoch, FIRST_EPOCH);
        assert_eq!(record.lock_until, TRANSITION + DISPUTE_LOCK);
    }

    /// Wider than CIP-156 as published, which lets a disputed voter "stake
    /// more votes to become active votes again"; the penalty is on the
    /// validator, so it matches force retirement instead.
    #[test]
    fn a_deposit_during_the_lock_buys_no_voting_power() {
        let alice = keys_from_seed(1);
        let mut state = staked_state(&alice, TRANSITION, FIRST_EPOCH, 10);
        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("forfeit");
        let lock_until = state.dispute_records[&alice.addr].lock_until;

        state.current_view = TRANSITION + 1;
        state.update_voting_power(&alice.addr, 50).expect("deposit");

        assert_eq!(lock_status_of(&state, &alice).available_votes(), 0);
        assert!(exits_of(&state, &alice)
            .iter()
            .all(|exit| *exit >= lock_until));

        state.current_view = lock_until;
        state.update_voting_power(&alice.addr, 7).expect("deposit");
        assert_eq!(lock_status_of(&state, &alice).available_votes(), 7);
    }

    /// Locks already running at activation cannot be reconstructed, so those
    /// validators keep the old rule until they expire.
    #[test]
    fn a_lock_that_predates_the_gate_is_not_retrofitted() {
        let alice = keys_from_seed(1);
        let mut state = staked_state(&alice, TRANSITION - 1, FIRST_EPOCH, 10);
        state.forfeit_node(&alice.addr, None).expect("forfeit");
        assert_eq!(lock_status_of(&state, &alice).available_votes(), 0);

        state.current_view = TRANSITION;
        state.update_voting_power(&alice.addr, 50).expect("deposit");
        assert_eq!(lock_status_of(&state, &alice).available_votes(), 50);
    }

    #[test]
    fn replayed_evidence_neither_errors_nor_extends_the_lock() {
        let alice = keys_from_seed(1);
        let mut state = staked_state(&alice, TRANSITION, FIRST_EPOCH, 10);
        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("forfeit");
        let exits = exits_of(&state, &alice);

        state.current_view = TRANSITION + 10;
        assert!(state
            .validate_dispute(&dispute_of(&alice), FIRST_EPOCH)
            .is_err());

        // A duplicate inside an already-validated block must pass through as
        // a no-op, or it would invalidate the whole block.
        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("duplicate is a no-op");
        assert_eq!(exits_of(&state, &alice), exits);
    }

    #[test]
    fn a_later_offence_postpones_the_deadline() {
        let alice = keys_from_seed(1);
        let mut state = staked_state(&alice, TRANSITION, FIRST_EPOCH, 10);
        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("forfeit");

        state.current_view = TRANSITION + 10;
        state.epoch_state.epoch = FIRST_EPOCH + 1;
        state
            .validate_dispute(&dispute_of(&alice), FIRST_EPOCH + 1)
            .expect("a fresh offence is admissible");
        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH + 1))
            .expect("forfeit");

        let record = *state.dispute_records.get(&alice.addr).unwrap();
        assert_eq!(record.last_offense_epoch, FIRST_EPOCH + 1);
        assert_eq!(record.lock_until, TRANSITION + 10 + DISPUTE_LOCK);
        assert_eq!(
            exits_of(&state, &alice),
            vec![TRANSITION + 10 + DISPUTE_LOCK]
        );
    }

    #[test]
    fn a_dispute_never_shortens_a_withdrawal_already_in_flight() {
        let alice = keys_from_seed(1);
        let mut state = staked_state(&alice, TRANSITION, FIRST_EPOCH, 10);
        // Retire, so the stake leaves at a view well past the dispute lock.
        state.retire_node(&alice.addr, 10).expect("retire");
        let exits = exits_of(&state, &alice);
        assert!(exits.iter().all(|view| *view > TRANSITION + DISPUTE_LOCK));

        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("forfeit");

        assert_eq!(exits_of(&state, &alice), exits);
    }

    #[test]
    fn evidence_outside_the_admissible_epochs_is_refused() {
        let alice = keys_from_seed(1);
        let state = staked_state(&alice, TRANSITION, FIRST_EPOCH, 10);

        assert!(state
            .validate_dispute(&dispute_of(&alice), FIRST_EPOCH - 1)
            .is_err());
        assert!(state
            .validate_dispute(&dispute_of(&alice), FIRST_EPOCH + 1)
            .is_err());
        assert!(state
            .validate_dispute(&dispute_of(&alice), FIRST_EPOCH)
            .is_ok());
    }

    #[test]
    fn a_pre_activation_dispute_leaves_no_record() {
        let alice = keys_from_seed(1);
        let mut state = staked_state(&alice, TRANSITION - 1, FIRST_EPOCH, 10);

        state.forfeit_node(&alice.addr, None).expect("forfeit");

        assert!(state.dispute_records.get(&alice.addr).is_none());
        assert_eq!(lock_status_of(&state, &alice).available_votes(), 0);
    }

    #[test]
    fn persisted_layout_follows_the_transition_view() {
        let alice = keys_from_seed(1);

        let before = staked_state(&alice, TRANSITION - 1, FIRST_EPOCH, 10);
        let legacy = before.encode_persisted().expect("encode");
        assert!(
            bcs::from_bytes::<PosState>(&legacy).is_err(),
            "a legacy row must not decode as the current layout, or the \
             fallback would be reached by states that do not need it"
        );
        let decoded = PosState::decode_persisted(&legacy).expect("decode");
        assert!(decoded.dispute_records.is_empty());
        assert_eq!(decoded, before);

        let mut after = staked_state(&alice, TRANSITION, FIRST_EPOCH, 10);
        let empty_but_gated = after.encode_persisted().expect("encode");
        assert_eq!(
            PosState::decode_persisted(&empty_but_gated).expect("decode"),
            after
        );
        after
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("forfeit");
        let with_record = after.encode_persisted().expect("encode");
        assert_eq!(
            PosState::decode_persisted(&with_record).expect("decode"),
            after
        );
    }

    #[test]
    fn the_legacy_layout_is_the_current_one_without_its_last_field() {
        let alice = keys_from_seed(1);
        let state = staked_state(&alice, TRANSITION - 1, FIRST_EPOCH, 10);
        assert!(state.dispute_records.is_empty());

        // Pins the hand-written mirror to the real field order; a round-trip
        // through the mirror alone would agree with itself however wrong.
        assert_eq!(
            bcs::to_bytes(&state).expect("encode"),
            [state.encode_persisted().expect("encode").as_slice(), &[0u8]]
                .concat()
        );
    }

    /// A migration that dropped the watermark would surface here as evidence
    /// that can be replayed after the restart.
    #[test]
    fn a_dispute_survives_a_restart_on_each_side_of_the_gate() {
        let alice = keys_from_seed(1);
        let before = staked_state(&alice, TRANSITION - 1, FIRST_EPOCH, 10);

        let mut state =
            PosState::decode_persisted(&before.encode_persisted().unwrap())
                .expect("legacy row still readable");
        state.current_view = TRANSITION;
        state
            .forfeit_node(&alice.addr, Some(FIRST_EPOCH))
            .expect("forfeit");

        let restarted =
            PosState::decode_persisted(&state.encode_persisted().unwrap())
                .expect("current row readable");
        assert_eq!(restarted, state);
        assert_eq!(
            restarted.dispute_records[&alice.addr].last_offense_epoch,
            FIRST_EPOCH
        );
        assert!(restarted
            .validate_dispute(&dispute_of(&alice), FIRST_EPOCH)
            .is_err());
    }

    #[test]
    fn a_legacy_row_is_readable_up_to_the_transition_view_and_no_further() {
        let alice = keys_from_seed(1);
        let state = staked_state(&alice, 0, FIRST_EPOCH, 10);

        let legacy_at = |view: View| {
            bcs::to_bytes(&PosStateV1Ref {
                node_map: &state.node_map,
                current_view: &view,
                epoch_state: &state.epoch_state,
                term_list: &state.term_list,
                retiring_nodes: &state.retiring_nodes,
                pivot_decision: &state.pivot_decision,
                node_map_hint: &state.node_map_hint,
                unlock_event_hint: &state.unlock_event_hint,
                skipped: &state.skipped,
            })
            .unwrap()
        };

        assert!(PosState::decode_persisted(&legacy_at(TRANSITION - 1)).is_ok());
        assert!(PosState::decode_persisted(&legacy_at(TRANSITION)).is_ok());
        assert!(PosState::decode_persisted(&legacy_at(TRANSITION + 1)).is_err());
    }

    fn election_payload_for(k: &Keys) -> ElectionPayload {
        ElectionPayload {
            public_key: k.bls_pk.clone(),
            vrf_public_key: k.vrf_pk.clone(),
            target_term: 1,
            vrf_proof: dummy_vrf_proof(),
        }
    }

    #[test]
    fn election_rejects_signer_mismatch() {
        let alice = keys_from_seed(1);
        let mallory = keys_from_seed(2);
        let state = state_with_node(&alice);

        let payload = election_payload_for(&alice);
        assert_eq!(
            state.validate_election_simple(
                &mallory.addr,
                &mallory.bls_pk,
                &payload
            ),
            Some(DiscardedVMStatus::ELECTION_SIGNER_MISMATCH),
        );
    }

    #[test]
    fn election_rejects_auth_key_mismatch() {
        let alice = keys_from_seed(1);
        let mallory = keys_from_seed(2);
        let state = state_with_node(&alice);

        let payload = election_payload_for(&alice);
        assert_eq!(
            state.validate_election_simple(
                &alice.addr,
                &mallory.bls_pk,
                &payload
            ),
            Some(DiscardedVMStatus::AUTHENTICATOR_KEY_MISMATCH),
        );
    }

    #[test]
    fn check_sender_owns_auth_key_unregistered() {
        let alice = keys_from_seed(1);
        let mallory = keys_from_seed(2);
        let state = state_with_node(&alice);

        assert_eq!(
            state
                .check_sender_owns_auth_key(
                    &mallory.addr,
                    &mallory.bls_pk,
                    DiscardedVMStatus::ELECTION_NON_EXISTENT_NODE,
                )
                .err(),
            Some(DiscardedVMStatus::ELECTION_NON_EXISTENT_NODE),
        );
    }

    #[test]
    fn check_sender_owns_auth_key_accepts_matching() {
        let alice = keys_from_seed(1);
        let state = state_with_node(&alice);

        assert!(state
            .check_sender_owns_auth_key(
                &alice.addr,
                &alice.bls_pk,
                DiscardedVMStatus::ELECTION_NON_EXISTENT_NODE,
            )
            .is_ok());
    }
}
