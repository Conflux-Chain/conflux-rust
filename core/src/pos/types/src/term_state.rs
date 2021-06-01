use crate::{
    account_address::AccountAddress,
    account_config,
    block_info::Round,
    epoch_state::EpochState,
    event::EventKey,
    transaction::{ElectionPayload, RetirePayload},
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
};
use anyhow::{anyhow, bail, Result};
use diem_crypto::{HashValue, VRFProof};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BinaryHeap, HashMap},
    fmt::{Debug, Formatter},
};

const TERM_LIST_LEN: usize = 6;
const ELECTION_AFTER_ACCEPTED_ROUND: Round = 240;
const ROUND_PER_TERM: Round = 60;
/// A term `n` is open for election in the view range
/// `(n * ROUND_PER_TERM - ELECTION_TERM_START_ROUND, n * ROUND_PER_TERM -
/// ELECTION_TERM_END_ROUND]`
const ELECTION_TERM_START_ROUND: Round = 120;
const ELECTION_TERM_END_ROUND: Round = 30;

const TERM_MAX_SIZE: usize = 16;

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum NodeStatus {
    Accepted,
    Retired,
    Unlocked,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeData {
    public_key: ConsensusPublicKey,
    vrf_public_key: Option<ConsensusVRFPublicKey>,
    status: NodeStatus,
    status_start_view: Round,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TermData {
    start_view: Round,
    seed: Vec<u8>,
    /// (VRF.val, NodeID)
    node_list: BinaryHeap<(HashValue, AccountAddress)>,
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
        &self, node_list: BinaryHeap<(HashValue, AccountAddress)>,
    ) -> Self {
        TermData {
            start_view: self.start_view + ROUND_PER_TERM,
            seed: HashValue::sha3_256_of(&self.seed).to_vec(),
            node_list,
        }
    }
}

impl TermData {
    pub fn add_node(&mut self, vrf_output: HashValue, node_id: AccountAddress) {
        self.node_list.push((vrf_output, node_id))
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
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
        &mut self, event: &ElectionEvent,
    ) -> anyhow::Result<()> {
        let term_offset = event
            .start_term
            .checked_sub(self.current_term)
            .ok_or(anyhow!("election start_term is too early"))?
            as usize;
        if term_offset >= self.term_list.len() {
            bail!("election start_term is too late");
        }
        let mut term = &mut self.term_list[term_offset];
        term.add_node(event.vrf_output, event.node_id);
        if term.node_list.len() > TERM_MAX_SIZE {
            // TODO: Decide if we want to keep the previously elected nodes to
            // avoid duplicated election.
            term.node_list.pop();
        }
        Ok(())
    }

    pub fn new_term(&mut self, new_term: u64) {
        // This double-check should always pass.
        if self.term_list[1].start_view
            == new_term.saturating_mul(ROUND_PER_TERM)
        {
            if new_term <= TERM_LIST_LEN as u64 {
                // The initial terms are not open for election.
                return;
            }
            self.term_list.remove(0);
            let last_term = self.term_list.last().unwrap();
            self.term_list.push(last_term.next_term(Default::default()));
            self.current_term = new_term;
        }
    }
}

// FIXME(lpl): Check if we only need the latest version persisted.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PosState {
    /// All the nodes that have staked in PoW.
    /// Nodes are only inserted and will never be removed.
    node_map: HashMap<AccountAddress, NodeData>,
    /// `current_view / TERM_LIST_LEN == term_list.current_term` is always
    /// true. This is not the same as `RoundState.current_view` because the
    /// view does not increase for blocks following a pending
    /// reconfiguration block.
    current_view: Round,
    term_list: TermList,
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
        initial_seed: Vec<u8>,
        initial_nodes: Vec<(
            AccountAddress,
            ConsensusPublicKey,
            Option<ConsensusVRFPublicKey>,
        )>,
    ) -> Self
    {
        let mut node_map = HashMap::new();
        let mut node_list = BinaryHeap::new();
        for (addr, public_key, vrf_public_key) in initial_nodes {
            node_map.insert(
                addr.clone(),
                NodeData {
                    public_key,
                    vrf_public_key,
                    status: NodeStatus::Accepted,
                    status_start_view: 0,
                },
            );
            // VRF output of initial terms will not be used, because these terms
            // are not open for election.
            node_list.push((Default::default(), addr));
        }
        let mut term_list = Vec::new();
        let initial_term = TermData {
            start_view: 0,
            seed: initial_seed,
            node_list,
        };
        term_list.push(initial_term);
        // TODO(lpl): The initial terms can have different node list.
        // Duplicate the initial term for the first TERM_LIST_LEN + 2 terms.
        for _ in 0..(TERM_LIST_LEN + 1) {
            let last_term = term_list.last().unwrap();
            let next_term = last_term.next_term(last_term.node_list.clone());
            term_list.push(next_term);
        }
        PosState {
            node_map,
            current_view: 0,
            term_list: TermList {
                current_term: 0,
                term_list,
            },
        }
    }
}

/// Read-only functions used in `execute_block`
impl PosState {
    pub fn validate_election(
        &self, election_tx: &ElectionPayload,
    ) -> Result<()> {
        let node = match self.node_map.get(&election_tx.node_id) {
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
        if target_view >= self.current_view + ELECTION_TERM_START_ROUND
            || target_view < self.current_view + ELECTION_TERM_END_ROUND
        {
            bail!("Target term is not open for election");
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

        // TODO(lpl): Optimize by adding hash set to each term or adding another
        // field to node_map.
        let start_term_offset = target_term_offset as usize - TERM_LIST_LEN;
        // The checking of `target_view` ensures that this is in range of
        // `term_list`.
        for i in start_term_offset..=target_term_offset {
            let term = &self.term_list.term_list[i as usize];
            for (_, addr) in &term.node_list {
                if *addr == election_tx.node_id {
                    bail!("Node in active term service cannot be elected");
                }
            }
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
        if !matches!(node.status, NodeStatus::Accepted) {
            bail!("Invalid node status for retiring");
        }

        // FIXME(lpl): Nodes in the current active term are not covered by this.
        for term in &self.term_list.term_list {
            for (_, addr) in &term.node_list {
                if *addr == retire_payload.node_id {
                    bail!("Node in active term service cannot retire");
                }
            }
        }
        Ok(())
    }

    pub fn get_new_committee(&self) -> Result<ValidatorVerifier> {
        let mut address_to_validator_info = BTreeMap::new();
        for i in 0..TERM_LIST_LEN {
            let term = &self.term_list.term_list[i];
            for (_, addr) in &term.node_list {
                let node = self.node_map.get(addr).ok_or(anyhow!(
                    "The node in active terms is missing in node_map"
                ))?;
                address_to_validator_info.insert(
                    addr.clone(),
                    ValidatorConsensusInfo::new(
                        node.public_key.clone(),
                        node.vrf_public_key.clone(),
                        1,
                    ),
                );
            }
        }
        // TODO(lpl): Decide the ratio of voting power.
        Ok(ValidatorVerifier::new(address_to_validator_info))
    }
}

/// Write functions used apply changes (process events in PoS and PoW)
impl PosState {
    pub fn new_node_elected(&mut self, event: &ElectionEvent) -> Result<()> {
        self.term_list.new_node_elected(event)
    }

    /// `get_new_committee` has been called before this to produce an
    /// EpochState. And `next_view` will not be called for blocks following
    /// a pending reconfiguration block.
    pub fn next_view(&mut self) -> Result<Option<EpochState>> {
        self.current_view += 1;

        let epoch_state = if self.current_view % ROUND_PER_TERM == 0 {
            let new_term = self.current_view / ROUND_PER_TERM;
            self.term_list.new_term(new_term);
            let verifier = self.get_new_committee()?;
            Some(EpochState {
                // TODO(lpl): If we allow epoch changes within a term, this
                // should be updated.
                epoch: new_term,
                verifier,
            })
        } else {
            None
        };
        Ok(epoch_state)
    }

    pub fn retire_node(&mut self, retire_event: &RetireEvent) -> Result<()> {
        match self.node_map.get_mut(&retire_event.node_id) {
            Some(node) => match node.status {
                NodeStatus::Accepted => {
                    node.status = NodeStatus::Retired;
                    node.status_start_view = self.current_view;
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

impl Default for PosState {
    fn default() -> Self {
        Self {
            node_map: Default::default(),
            current_view: 0,
            term_list: TermList {
                current_term: 0,
                term_list: Default::default(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ElectionEvent {
    node_id: AccountAddress,
    vrf_output: HashValue,
    start_term: u64,
}

impl ElectionEvent {
    pub fn new(
        node_id: AccountAddress, vrf_output: HashValue, start_term: u64,
    ) -> Self {
        Self {
            node_id,
            vrf_output,
            start_term,
        }
    }
}

impl ElectionEvent {
    pub fn election_event_key() -> EventKey {
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
    node_id: AccountAddress,
}

impl RetireEvent {
    pub fn new(node_id: AccountAddress) -> Self { RetireEvent { node_id } }

    pub fn retire_event_key() -> EventKey {
        EventKey::new_from_address(&account_config::retire_address(), 4)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}
