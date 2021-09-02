// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap, HashMap, VecDeque},
    convert::TryFrom,
    fmt::{Debug, Formatter},
};

use anyhow::{anyhow, bail, ensure, Result};
use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

use cfx_types::H256;
use diem_crypto::{HashValue, VRFProof};
use diem_logger::prelude::*;
use move_core_types::{
    language_storage::TypeTag, vm_status::DiscardedVMStatus,
};
use pow_types::StakingEvent;

use crate::{
    account_address::{from_consensus_public_key, AccountAddress},
    account_config,
    block_info::{PivotBlockDecision, Round, View},
    contract_event::ContractEvent,
    epoch_state::EpochState,
    event::EventKey,
    transaction::{ElectionPayload, RetirePayload},
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
};

const TERM_LIST_LEN: usize = 6;
pub const ROUND_PER_TERM: Round = 60;
/// A term `n` is open for election in the view range
/// `(n * ROUND_PER_TERM - ELECTION_TERM_START_ROUND, n * ROUND_PER_TERM -
/// ELECTION_TERM_END_ROUND]`
const ELECTION_TERM_START_ROUND: Round = 90;
const ELECTION_TERM_END_ROUND: Round = 30;
// The view to start election in the whole PoS consensus protocol.
const FIRST_START_ELECTION_VIEW: u64 =
    TERM_LIST_LEN as u64 * ROUND_PER_TERM - ELECTION_TERM_START_ROUND;
const FIRST_END_ELECTION_VIEW: u64 =
    TERM_LIST_LEN as u64 * ROUND_PER_TERM - ELECTION_TERM_END_ROUND;

const TERM_MAX_SIZE: usize = 10000;
const TERM_ELECTED_SIZE: usize = 50;
pub const IN_QUEUE_LOCKED_VIEWS: u64 = 10080;
pub const OUT_QUEUE_LOCKED_VIEWS: u64 = 10080;

pub use incentives::*;
mod incentives {
    use super::{ROUND_PER_TERM, TERM_ELECTED_SIZE, TERM_MAX_SIZE};
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
        / (TERM_ELECTED_SIZE as u64);
    pub const LEADER_POINTS: u64 =
        MAX_TERM_POINTS * LEADER_PERCENTAGE / 100 / ROUND_PER_TERM;
    pub const BONUS_VOTE_POINTS: u64 = MAX_TERM_POINTS * BONUS_VOTE_PERCENTAGE
        / 100
        / ROUND_PER_TERM
        / BONUS_VOTE_MAX_SIZE;
}

use lock_status::NodeLockStatus;
use std::collections::HashSet;

pub mod lock_status {
    use super::*;
    #[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
    #[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
    pub struct StatusItem {
        pub view: View,
        pub votes: u64,
    }

    pub type StatusList = VecDeque<StatusItem>;

    #[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Default)]
    #[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
    pub struct NodeLockStatus {
        pub in_queue: StatusList,
        pub locked: u64,
        pub out_queue: StatusList,
        unlocked: u64,

        // Equals to the summation of in_queue + locked
        available_votes: u64,

        force_retired: bool,
        // If the staking is forfeited, the unlocked votes before forfeiting is
        // exempted.
        exempt_from_forfeit: Option<u64>,
    }

    pub struct NodeElectionStatus {
        pub serving_votes: StatusList,
        pub election_votes: StatusList,
    }

    pub struct UpdateHint {
        pub address: AccountAddress,
        pub view: View,
    }

    pub type ViewHints = Vec<View>;

    impl NodeLockStatus {
        #[must_use]
        pub(super) fn update(&mut self, view: View) -> (bool, Vec<View>) {
            let mut new_votes_unlocked = false;
            let mut update_views = vec![];

            while let Some(item) = self.in_queue.pop_front() {
                if item.view > view {
                    self.in_queue.push_front(item);
                    break;
                }
                self.locked += item.votes;
            }

            while let Some(item) = self.out_queue.pop_front() {
                if item.view > view {
                    self.out_queue.push_front(item);
                    break;
                }
                self.unlocked += item.votes;
                new_votes_unlocked = true;
            }

            if self.force_retired {
                update_views = self.new_unlock(view, self.locked).expect(
                    "Passed in votes is always no less than self.locked",
                );
            }

            if self.exempt_from_forfeit.is_some() {
                new_votes_unlocked = false
            }

            (new_votes_unlocked, update_views)
        }

        #[must_use]
        pub(super) fn new_lock(
            &mut self, view: View, votes: u64, initialize_mode: bool,
        ) -> Vec<View> {
            if votes == 0 {
                return vec![];
            }
            self.available_votes += votes;

            return if IN_QUEUE_LOCKED_VIEWS > 0 && !initialize_mode {
                let exit_queue_view = view + IN_QUEUE_LOCKED_VIEWS;
                self.in_queue.push_back(StatusItem {
                    view: exit_queue_view,
                    votes,
                });
                vec![exit_queue_view]
            } else {
                self.locked += votes;
                vec![]
            };
        }

        #[must_use]
        pub(super) fn new_unlock(
            &mut self, view: View, votes: u64,
        ) -> Result<Vec<View>> {
            if votes == 0 {
                return Ok(vec![]);
            }
            if self.locked < votes {
                bail!("not enough votes to unlock");
            }
            self.locked -= votes;
            self.available_votes -= votes;

            return Ok(if OUT_QUEUE_LOCKED_VIEWS > 0 {
                let exit_queue_view = view + OUT_QUEUE_LOCKED_VIEWS;
                self.out_queue.push_back(StatusItem {
                    view: exit_queue_view,
                    votes,
                });
                vec![exit_queue_view]
            } else {
                self.unlocked += votes;
                vec![]
            });
        }

        #[must_use]
        pub(super) fn force_retire(&mut self, view: View) -> Vec<View> {
            if self.force_retired {
                return vec![];
            }

            self.force_retired = true;
            self.new_unlock(view, self.locked)
                .expect("Passed in votes is always no less than self.locked")
        }

        #[allow(unused)]
        pub(super) fn forfeit(&mut self) {
            if self.exempt_from_forfeit.is_some() {
                return;
            }
            self.exempt_from_forfeit = Some(self.unlocked)
        }

        pub fn available_votes(&self) -> u64 {
            if self.force_retired || self.exempt_from_forfeit.is_some() {
                0
            } else {
                self.available_votes
            }
        }

        pub fn unlocked_votes(&self) -> u64 {
            self.exempt_from_forfeit.unwrap_or(self.unlocked)
        }
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
    public_key: ConsensusPublicKey,
    vrf_public_key: Option<ConsensusVRFPublicKey>,
    lock_status: NodeLockStatus,
}

impl NodeData{
    pub fn status(&self) -> NodeStatus{
        self.status
    }

    pub fn status_start_view(&self) -> Round{
        self.status_start_view
    }

    pub fn voting_power(&self) -> u64{
        self.voting_power
    }
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

impl ElectingHeap {
    fn finalize(mut self) -> (ElectedMap, CandyMap) {
        let mut elected_map = ElectedMap::default();
        let mut count = 0usize;
        while let Some((_, node_id)) = self.0.pop() {
            *elected_map.0.entry(node_id.node_id.addr).or_insert(0) += 1;
            count += 1;
            if count >= TERM_ELECTED_SIZE {
                break;
            }
        }
        let mut candy_map = elected_map.clone();
        for (_, node_id) in self.0.into_vec().drain(..) {
            *candy_map.0.entry(node_id.node_id.addr).or_insert(0) += 1;
        }
        (elected_map, candy_map)
    }

    fn add_node(&mut self, hash: HashValue, node_id: ElectionNodeID) {
        let is_not_full_set = self.0.len() < TERM_MAX_SIZE;
        if self
            .0
            .peek()
            .map_or(true, |(max_value, _)| is_not_full_set || hash < *max_value)
        {
            self.0.push((hash, node_id.clone()));
            self.1.insert(node_id.node_id.addr.clone());
            if self.0.len() > TERM_MAX_SIZE {
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
            start_view: self.start_view + ROUND_PER_TERM,
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

        for nonce in 0..voting_power {
            // Hash after appending the nonce to get multiple identifier for
            // election.
            let mut b = event.vrf_output.to_vec();
            b.append(&mut nonce.to_le_bytes().to_vec());
            let priority = HashValue::sha3_256_of(&b);
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
            self.term_list[TERM_LIST_LEN].start_view
                == new_term.saturating_mul(ROUND_PER_TERM)
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
        assert!(target_term_offset < TERM_LIST_LEN + 2);
        // TODO(lpl): Optimize by adding hash set to each term or adding another
        // field to node_map.
        let start_term_offset =
            target_term_offset as usize - (TERM_LIST_LEN - 1);

        // The checking of `target_view` ensures that this is in range of
        // `term_list`.
        // For any valid `target_term_offset`, always checks to the end of
        // `term_list` because it's within the service time of
        // `target_term`.
        let mut serving_votes = Vec::with_capacity(TERM_LIST_LEN);
        for i in start_term_offset..target_term_offset {
            let term = &self.term_list[i as usize];
            serving_votes.push(term.node_list.serving_votes(author));
        }
        return serving_votes.iter().sum();
    }
}

// FIXME(lpl): Check if we only need the latest version persisted.
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

    catch_up_mode: bool,
}

impl Debug for PosState {
    fn fmt(
        &self, f: &mut Formatter<'_>,
    ) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("PosState")
            .field("view", &self.current_view)
            .finish()
    }
}

impl PosState {
    pub fn new(
        initial_seed: Vec<u8>, initial_nodes: Vec<(NodeID, u64)>,
        genesis_pivot_decision: PivotBlockDecision, catch_up_mode: bool,
    ) -> Self
    {
        let mut node_map = HashMap::new();
        let mut node_list = BTreeMap::default();
        for (node_id, voting_power) in initial_nodes {
            let mut lock_status = NodeLockStatus::default();
            // The genesis block should not have updates for lock status.
            let _ = lock_status.new_lock(0, voting_power, true);
            node_map.insert(
                node_id.addr.clone(),
                NodeData {
                    public_key: node_id.public_key.clone(),
                    vrf_public_key: Some(node_id.vrf_public_key.clone()),
                    lock_status,
                },
            );
            // VRF output of initial terms will not be used, because these terms
            // are not open for election.
            node_list.insert(node_id.addr, voting_power);
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
            catch_up_mode,
        };
        let (verifier, vrf_seed) = pos_state.get_committee_at(0).unwrap();
        pos_state.epoch_state = EpochState {
            epoch: 0,
            verifier,
            vrf_seed,
        };
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
            catch_up_mode: false,
        }
    }

    pub fn set_catch_up_mode(&mut self, catch_up_mode: bool) {
        self.catch_up_mode = catch_up_mode;
    }

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

    pub fn account_node_data(&self, account_address: AccountAddress) -> Option<&NodeData> { self.node_map.get(&account_address) }
}

/// Read-only functions use in `TransactionValidator`
impl PosState {
    pub fn validate_election_simple(
        &self, election_tx: &ElectionPayload,
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
        let node = match self.node_map.get(&node_id.addr) {
            Some(node) => node,
            None => {
                return Some(DiscardedVMStatus::ELECTION_NON_EXISITENT_NODE);
            }
        };

        // if !matches!(node.status, NodeStatus::Accepted) {
        //     return Some(DiscardedVMStatus::ELECTION_NON_ACCEPTED_NODE);
        // }
        if election_tx
            .target_term
            .checked_mul(ROUND_PER_TERM)
            .is_none()
        {
            return Some(DiscardedVMStatus::ELECTION_TERGET_TERM_NOT_OPEN);
        }

        let target_view = election_tx.target_term * ROUND_PER_TERM;
        // if node.status_start_view + ELECTION_AFTER_ACCEPTED_ROUND >
        // target_view {
        //     return Some(DiscardedVMStatus::ELECTION_TOO_SOON);
        // }
        if node.lock_status.available_votes() == 0 {
            return Some(DiscardedVMStatus::ELECTION_WITHOUT_VOTES);
        }
        if target_view > self.current_view + ELECTION_TERM_START_ROUND
            || target_view < self.current_view + ELECTION_TERM_END_ROUND
        {
            return Some(DiscardedVMStatus::ELECTION_TERGET_TERM_NOT_OPEN);
        }
        None
    }

    pub fn validate_retire_simple(
        &self, retire_tx: &RetirePayload,
    ) -> Option<DiscardedVMStatus> {
        let node = match self.node_map.get(&retire_tx.node_id) {
            Some(node) => node,
            None => {
                return Some(DiscardedVMStatus::RETIRE_NON_EXISITENT_NODE);
            }
        };

        if node.lock_status.locked < retire_tx.votes {
            return Some(DiscardedVMStatus::RETIRE_WITHOUT_ENOUGH_VOTES);
        }

        None
    }

    pub fn validate_pivot_decision_simple(
        &self, pivot_decision_tx: &PivotBlockDecision,
    ) -> Option<DiscardedVMStatus> {
        if pivot_decision_tx.height <= self.pivot_decision.height {
            return Some(DiscardedVMStatus::PIVOT_DECISION_HEIGHT_TOO_OLD);
        }
        None
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
        let target_view = election_tx.target_term * ROUND_PER_TERM;
        if target_view > self.current_view + ELECTION_TERM_START_ROUND
            || target_view < self.current_view + ELECTION_TERM_END_ROUND
        {
            bail!(
                "Target term is not open for election: target={} current={}",
                target_view,
                self.current_view
            );
        }

        let target_term_offset = election_tx.target_term as usize
            - self.term_list.current_term as usize
            + (TERM_LIST_LEN - 1);
        if election_tx
            .vrf_proof
            .verify(
                &self.term_list.term_list[target_term_offset as usize].seed,
                node.vrf_public_key.as_ref().unwrap(),
            )
            .is_err()
        {
            bail!("Invalid VRF proof for election")
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

    pub fn validate_retire(
        &self, retire_payload: &RetirePayload,
    ) -> Result<()> {
        let node = match self.node_map.get(&retire_payload.node_id) {
            Some(node) => node,
            None => return Err(anyhow!("Retirement for non-existent node.")),
        };
        if node.lock_status.locked < retire_payload.votes {
            // PoW allows retiring more than once, so do not return error here.
            bail!("not enough votes for retire");
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
        if self.current_view < FIRST_START_ELECTION_VIEW as u64 {
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

    pub fn get_unlock_events(&self) -> Vec<ContractEvent> {
        let mut unlocked_nodes = Vec::new();
        for addr in &self.unlock_event_hint {
            let node = self.node_map.get(&addr).expect("exists");
            let unlock_event = ContractEvent::new(
                UnlockEvent::event_key(),
                0,                                      /* sequence_number */
                TypeTag::Vector(Box::new(TypeTag::U8)), /* TypeTag::ByteArray */
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

    pub fn catch_up_mode(&self) -> bool { self.catch_up_mode }

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
        let update_views = match self.node_map.get_mut(addr) {
            Some(node_status) => node_status.lock_status.new_lock(
                self.current_view,
                increased_voting_power,
                false,
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
        let voting_power = self
            .node_map
            .get(&event.node_id.addr)
            .expect("checked in execution")
            .lock_status
            .available_votes();
        self.term_list.new_node_elected(event, voting_power)
    }

    /// `get_new_committee` has been called before this to produce an
    /// EpochState. And `next_view` will not be called for blocks following
    /// a pending reconfiguration block.
    pub fn next_view(&mut self) -> Result<Option<EpochState>> {
        // Increase view after updating node status above to get a correct
        // `status_start_view`.
        self.current_view += 1;

        println!("current view {}", self.current_view);

        // Update the status for the all.
        self.unlock_event_hint.clear();
        if let Some(addresses) = self.node_map_hint.remove(&self.current_view) {
            for address in addresses {
                let node = self.node_map.get_mut(&address).expect("exists");
                let (new_votes_unlocked, update_views) =
                    node.lock_status.update(self.current_view);
                self.record_update_views(&address, update_views);
                if new_votes_unlocked {
                    self.unlock_event_hint.insert(address);
                }
            }
        }

        let epoch_state = if self.current_view == 1 {
            let (verifier, term_seed) = self.get_committee_at(0)?;
            // genesis
            Some(EpochState {
                // TODO(lpl): If we allow epoch changes within a term, this
                // should be updated.
                epoch: 1,
                verifier,
                vrf_seed: term_seed.clone(),
            })
        } else if self.current_view % ROUND_PER_TERM == 0 {
            let new_term = self.current_view / ROUND_PER_TERM;
            let (verifier, term_seed) = self.get_committee_at(new_term)?;
            // generate new epoch for new term.
            self.term_list.new_term(
                new_term,
                self.pivot_decision.block_hash.as_bytes().to_vec(),
            );
            Some(EpochState {
                // TODO(lpl): If we allow epoch changes within a term, this
                // should be updated.
                epoch: new_term + 1,
                verifier,
                vrf_seed: term_seed.clone(),
            })
        } else if self.current_view >= FIRST_END_ELECTION_VIEW
            && self.current_view % ROUND_PER_TERM == ROUND_PER_TERM / 2
        {
            self.term_list.finalize_election();
            None
        } else {
            None
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
        let views = match self.node_map.get_mut(&addr) {
            Some(node) => {
                node.lock_status.new_unlock(self.current_view, votes)?
            }
            None => {
                return Err(anyhow!("Retiring node does not exist"));
            }
        };
        self.record_update_views(addr, views);
        Ok(())
    }

    pub fn force_retire_node(&mut self, addr: &AccountAddress) -> Result<()> {
        diem_trace!("retire_node: {:?}", addr);
        let views = match self.node_map.get_mut(&addr) {
            Some(node) => node.lock_status.force_retire(self.current_view),
            None => {
                return Err(anyhow!("Retiring node does not exist"));
            }
        };
        self.record_update_views(addr, views);
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
    ) -> Self
    {
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
            StakingEvent::Retire(addr_h256, _votes) => {
                let addr = AccountAddress::from_bytes(addr_h256)?;
                Ok(self.node_id == addr)
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
    public_key: ConsensusPublicKey,
    vrf_public_key: ConsensusVRFPublicKey,

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
        self.addr.partial_cmp(&other.addr)
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
