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
    block_info::{PivotBlockDecision, Round},
    contract_event::ContractEvent,
    epoch_state::EpochState,
    event::EventKey,
    transaction::{ElectionPayload, RetirePayload},
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
};

const TERM_LIST_LEN: usize = 6;
// FIXME(lpl): Use correct value later.
pub const ELECTION_AFTER_ACCEPTED_ROUND: Round = 240;
pub const ROUND_PER_TERM: Round = 60;
/// A term `n` is open for election in the view range
/// `(n * ROUND_PER_TERM - ELECTION_TERM_START_ROUND, n * ROUND_PER_TERM -
/// ELECTION_TERM_END_ROUND]`
const ELECTION_TERM_START_ROUND: Round = 120;
const ELECTION_TERM_END_ROUND: Round = 30;

const TERM_MAX_SIZE: usize = 10000;
const TERM_ELECTED_SIZE: usize = 50;
const UNLOCK_WAIT_VIEW: u64 = 20160;

const BONUS_VOTE_MAX_SIZE: u64 = 100;

pub const MAX_TERM_POINTS: u64 = 6_000_000;

const ELECTION_PERCENTAGE: u64 = 20;
const COMMITTEE_PERCENTAGE: u64 = 75;
const LEADER_PERCENTAGE: u64 = 3;
const BONUS_VOTE_PERCENTAGE: u64 = 2;

pub const ELECTION_POINTS: u64 =
    MAX_TERM_POINTS * ELECTION_PERCENTAGE / 100 / (TERM_MAX_SIZE as u64);
pub const COMMITTEE_POINTS: u64 =
    MAX_TERM_POINTS * COMMITTEE_PERCENTAGE / 100 / (TERM_ELECTED_SIZE as u64);
pub const LEADER_POINTS: u64 =
    MAX_TERM_POINTS * LEADER_PERCENTAGE / 100 / ROUND_PER_TERM;
pub const BONUS_VOTE_POINTS: u64 = MAX_TERM_POINTS * BONUS_VOTE_PERCENTAGE
    / 100
    / ROUND_PER_TERM
    / BONUS_VOTE_MAX_SIZE;

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
    status: NodeStatus,
    status_start_view: Round,
    voting_power: u64,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TermData {
    start_view: Round,
    seed: Vec<u8>,
    /// (VRF.val, NodeID)
    node_list: BinaryHeap<(HashValue, ElectionNodeID)>,
}

impl PartialEq for TermData {
    fn eq(&self, other: &Self) -> bool {
        if self.start_view != other.start_view || self.seed != other.seed {
            return false;
        }
        let mut iter_self = self.node_list.iter();
        let mut iter_other = other.node_list.iter();
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

impl Eq for TermData {}

impl TermData {
    fn next_term(
        &self, node_list: BinaryHeap<(HashValue, ElectionNodeID)>,
        seed: Vec<u8>,
    ) -> Self
    {
        TermData {
            start_view: self.start_view + ROUND_PER_TERM,
            seed,
            node_list,
        }
    }
}

impl TermData {
    fn add_node(&mut self, vrf_output: HashValue, node_id: ElectionNodeID) {
        self.node_list.push((vrf_output, node_id))
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
}

impl TermList {
    /// Add a new node to term list after a valid Election transaction has been
    /// executed.
    pub fn new_node_elected(
        &mut self, event: &ElectionEvent, voting_power: u64,
    ) -> anyhow::Result<()> {
        let term_offset = event
            .start_term
            .checked_sub(self.current_term - (TERM_LIST_LEN as u64 - 1))
            .ok_or(anyhow!("election start_term is too early"))?
            as usize;
        if term_offset >= self.term_list.len() {
            bail!("election start_term is too late");
        }
        let term = &mut self.term_list[term_offset];

        for nonce in 0..voting_power {
            // Hash after appending the nonce to get multiple identifier for
            // election.
            let mut b = event.vrf_output.to_vec();
            b.append(&mut nonce.to_le_bytes().to_vec());
            let priority = HashValue::sha3_256_of(&b);
            term.add_node(
                priority,
                ElectionNodeID::new(event.node_id.clone(), nonce),
            );
            if term.node_list.len() > TERM_MAX_SIZE {
                // TODO: Decide if we want to keep the previously elected nodes
                // to avoid duplicated election.
                term.node_list.pop();
            }
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
    }

    fn can_be_elected(
        &self, target_term_offset: usize, author: &AccountAddress,
    ) -> bool {
        // TODO(lpl): Optimize by adding hash set to each term or adding another
        // field to node_map.
        let start_term_offset =
            target_term_offset as usize - (TERM_LIST_LEN - 1);
        // The checking of `target_view` ensures that this is in range of
        // `term_list`.
        // For any valid `target_term_offset`, always checks to the end of
        // `term_list` because it's within the service time of
        // `target_term`.
        for i in start_term_offset..=(TERM_LIST_LEN + 1) {
            let term = &self.term_list[i as usize];
            for (_, addr) in term.node_list.iter().take(TERM_ELECTED_SIZE) {
                if addr.node_id.addr == *author {
                    diem_debug!(
                        "can_be_elected: {:?} is in term {}:{}",
                        author,
                        i,
                        term.start_view
                    );
                    return false;
                }
            }
        }
        true
    }
}

// FIXME(lpl): Check if we only need the latest version persisted.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
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
        let mut node_list = BinaryHeap::new();
        for (node_id, voting_power) in initial_nodes {
            node_map.insert(
                node_id.addr.clone(),
                NodeData {
                    public_key: node_id.public_key.clone(),
                    vrf_public_key: Some(node_id.vrf_public_key.clone()),
                    status: NodeStatus::Accepted,
                    status_start_view: 0,
                    voting_power,
                },
            );
            // VRF output of initial terms will not be used, because these terms
            // are not open for election.
            for nonce in 0..voting_power {
                node_list.push((
                    Default::default(),
                    ElectionNodeID::new(node_id.clone(), nonce),
                ));
            }
        }
        let mut term_list = Vec::new();
        let initial_term = TermData {
            start_view: 0,
            seed: initial_seed.clone(),
            node_list,
        };
        term_list.push(initial_term);
        // TODO(lpl): The initial terms can have different node list.
        // Duplicate the initial term for the first TERM_LIST_LEN + 2 terms.
        for _ in 0..(TERM_LIST_LEN + 1) {
            let last_term = term_list.last().unwrap();
            let next_term =
                last_term.next_term(Default::default(), initial_seed.clone());
            term_list.push(next_term);
        }
        let mut pos_state = PosState {
            node_map,
            current_view: 0,
            epoch_state: EpochState::empty(),
            term_list: TermList {
                current_term: 0,
                term_list,
            },
            retiring_nodes: Default::default(),
            pivot_decision: genesis_pivot_decision,
            catch_up_mode,
        };
        let (verifier, vrf_seed) = pos_state.get_new_committee().unwrap();
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
            },
            retiring_nodes: Default::default(),
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

    pub fn current_term_seed(&self) -> &Vec<u8> {
        self.target_term_seed(self.term_list.current_term)
    }

    pub fn target_term_seed(&self, target_term: u64) -> &Vec<u8> {
        if target_term < (TERM_LIST_LEN as u64) {
            &self.term_list.term_list[target_term as usize].seed
        } else if target_term >= self.term_list.current_term {
            let target_term_offset = (target_term - self.term_list.current_term)
                as usize
                + (TERM_LIST_LEN - 1);
            &self.term_list.term_list[target_term_offset].seed
        } else {
            unreachable!("target_term_seed is only called for future terms.")
        }
    }

    pub fn epoch_state(&self) -> &EpochState { &self.epoch_state }
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

        if !matches!(node.status, NodeStatus::Accepted) {
            return Some(DiscardedVMStatus::ELECTION_NON_ACCEPTED_NODE);
        }
        if election_tx
            .target_term
            .checked_mul(ROUND_PER_TERM)
            .is_none()
        {
            return Some(DiscardedVMStatus::ELECTION_TERGET_TERM_NOT_OPEN);
        }

        let target_view = election_tx.target_term * ROUND_PER_TERM;
        if node.status_start_view + ELECTION_AFTER_ACCEPTED_ROUND > target_view
        {
            return Some(DiscardedVMStatus::ELECTION_TOO_SOON);
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
        let node_id = NodeID::new(
            retire_tx.public_key.clone(),
            retire_tx.vrf_public_key.clone(),
        );
        let node = match self.node_map.get(&node_id.addr) {
            Some(node) => node,
            None => {
                return Some(DiscardedVMStatus::RETIRE_NON_EXISITENT_NODE);
            }
        };
        if !matches!(node.status, NodeStatus::Accepted) {
            return Some(DiscardedVMStatus::RETIRE_NON_ACCEPTED_NODE);
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

        if !matches!(node.status, NodeStatus::Accepted) {
            bail!("Invalid node status for election");
        }
        if node.status_start_view + ELECTION_AFTER_ACCEPTED_ROUND
            > election_tx
                .target_term
                .checked_mul(ROUND_PER_TERM)
                .ok_or(anyhow!("start view overflow"))?
        {
            bail!("Election too soon after accepted");
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

        if !self
            .term_list
            .can_be_elected(target_term_offset, &node_id.addr)
        {
            bail!("Node in active term service cannot be elected");
        }

        Ok(())
    }

    pub fn validate_retire(
        &self, retire_payload: &RetirePayload,
    ) -> Result<()> {
        let node_id = NodeID::new(
            retire_payload.public_key.clone(),
            retire_payload.vrf_public_key.clone(),
        );
        let node = match self.node_map.get(&node_id.addr) {
            Some(node) => node,
            None => return Err(anyhow!("Retirement for non-existent node.")),
        };
        if !matches!(node.status, NodeStatus::Accepted) {
            bail!("Invalid node status for retiring");
        }

        Ok(())
    }

    /// Return `(validator_set, term_seed)`.
    pub fn get_new_committee(&self) -> Result<(ValidatorVerifier, Vec<u8>)> {
        let mut voting_power_map = BTreeMap::new();
        let term_size_limit =
            if self.term_list.current_term < TERM_LIST_LEN as u64 {
                usize::MAX
            } else {
                TERM_ELECTED_SIZE
            };
        for i in 0..TERM_LIST_LEN {
            let term = &self.term_list.term_list[i];
            for (_, node_id) in term.node_list.iter().take(term_size_limit) {
                let voting_power = voting_power_map
                    .entry(node_id.node_id.addr.clone())
                    .or_insert(0 as u64);
                *voting_power += 1;
            }
        }
        let mut address_to_validator_info = BTreeMap::new();
        for (addr, voting_power) in voting_power_map {
            let node_data = self.node_map.get(&addr).expect("node in node_map");
            // Retired nodes are not removed from term_list,
            // but we do not include them in the new committee.
            if matches!(node_data.status, NodeStatus::Accepted) {
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
        if self.term_list.current_term < (TERM_LIST_LEN - 1) as u64 {
            return None;
        }
        match self.node_map.get(author) {
            // This node has not staked in PoW.
            None => None,
            Some(node) => {
                match &node.status {
                    NodeStatus::Accepted => {
                        if ((self.term_list.current_term + 1) * ROUND_PER_TERM
                            >= node.status_start_view
                                + ELECTION_AFTER_ACCEPTED_ROUND)
                            && self
                                .term_list
                                .can_be_elected(TERM_LIST_LEN, author)
                        {
                            Some(self.term_list.current_term + 1)
                        } else if ((self.term_list.current_term + 2)
                            * ROUND_PER_TERM
                            >= node.status_start_view
                                + ELECTION_AFTER_ACCEPTED_ROUND)
                            && self
                                .term_list
                                .can_be_elected(TERM_LIST_LEN + 1, author)
                        {
                            Some(self.term_list.current_term + 2)
                        } else {
                            // This node is still active and thus cannot be
                            // elected.
                            None
                        }
                    }
                    // This node has retired and will never be elected again.
                    _ => None,
                }
            }
        }
    }

    pub fn get_unlock_events(&self) -> Vec<ContractEvent> {
        let mut unlocked_nodes = Vec::new();
        for retired_node in &self.retiring_nodes {
            let node = self.node_map.get(&retired_node).expect("exists");
            assert_eq!(node.status, NodeStatus::Retired);
            if node.status_start_view + UNLOCK_WAIT_VIEW <= self.current_view {
                let unlock_event = ContractEvent::new(
                    UnlockEvent::event_key(),
                    0, /* sequence_number */
                    TypeTag::Vector(Box::new(TypeTag::U8)), /* TypeTag::ByteArray */
                    bcs::to_bytes(&UnlockEvent {
                        node_id: *retired_node,
                    })
                    .unwrap(),
                );
                unlocked_nodes.push(unlock_event);
            } else {
                break;
            }
        }
        unlocked_nodes
    }

    pub fn current_view(&self) -> u64 { self.current_view }

    pub fn catch_up_mode(&self) -> bool { self.catch_up_mode }

    pub fn next_evicted_term(&self) -> Vec<H256> {
        if self.current_view < (TERM_LIST_LEN - 1) as u64 * ROUND_PER_TERM {
            return Vec::new();
        } else {
            self.term_list.term_list[0]
                .node_list
                .iter()
                .map(|(_, address)| {
                    H256::from_slice(address.node_id.addr.as_ref())
                })
                .collect()
        }
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
                status: NodeStatus::Accepted,
                status_start_view: self.current_view,
                voting_power: 0,
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
        match self.node_map.get_mut(addr) {
            Some(node_status) => {
                // TODO(lpl): Should we return error if the node has been
                // retired?
                if matches!(node_status.status, NodeStatus::Accepted) {
                    node_status.voting_power = increased_voting_power;
                    node_status.status_start_view = self.current_view;
                }
                Ok(())
            }
            None => bail!("increase voting power of a non-existent node!"),
        }
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
            .voting_power;
        self.term_list.new_node_elected(event, voting_power)
    }

    /// `get_new_committee` has been called before this to produce an
    /// EpochState. And `next_view` will not be called for blocks following
    /// a pending reconfiguration block.
    pub fn next_view(&mut self) -> Result<Option<EpochState>> {
        while let Some(retired_node) = self.retiring_nodes.pop_front() {
            let node = self.node_map.get_mut(&retired_node).expect("exists");
            assert_eq!(node.status, NodeStatus::Retired);
            if node.status_start_view + UNLOCK_WAIT_VIEW <= self.current_view {
                diem_debug!("pos_state unlock {:?}", retired_node);
                node.status = NodeStatus::Unlocked;
                node.status_start_view = self.current_view;
            } else {
                // This node and other nodes are not unlocked.
                self.retiring_nodes.push_front(retired_node);
                break;
            }
        }

        // Increase view after updating node status above to get a correct
        // `status_start_view`.
        self.current_view += 1;
        let epoch_state = if self.current_view == 1 {
            let (verifier, term_seed) = self.get_new_committee()?;
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
            let (verifier, term_seed) = self.get_new_committee()?;
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
        } else {
            None
        };
        if let Some(epoch_state) = &epoch_state {
            self.epoch_state = epoch_state.clone();
        }
        Ok(epoch_state)
    }

    pub fn retire_node(&mut self, addr: &AccountAddress) -> Result<()> {
        diem_trace!("retire_node: {:?}", addr);
        match self.node_map.get_mut(&addr) {
            Some(node) => match node.status {
                NodeStatus::Accepted => {
                    node.status = NodeStatus::Retired;
                    node.status_start_view = self.current_view;
                    self.retiring_nodes.push_back(*addr);
                    Ok(())
                }
                _ => Err(anyhow!(
                    "Node retirement is processed in invalid status"
                )),
            },
            None => Err(anyhow!("Retiring node does not exist")),
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
    pub node_id: NodeID,
}

impl RetireEvent {
    pub fn new(
        public_key: ConsensusPublicKey, vrf_public_key: ConsensusVRFPublicKey,
    ) -> Self {
        RetireEvent {
            node_id: NodeID::new(public_key, vrf_public_key),
        }
    }

    pub fn event_key() -> EventKey {
        EventKey::new_from_address(&account_config::retire_address(), 4)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
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
            StakingEvent::Register((
                addr_h256,
                bls_pub_key_bytes,
                vrf_pub_key_bytes,
            )) => {
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
            StakingEvent::IncreaseStake((addr_h256, updated_voting_power)) => {
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
