use anyhow::{anyhow, bail, Result};
use diem_crypto::{HashValue, VRFProof};
use diem_types::{
    account_address::AccountAddress,
    account_config,
    block_info::Round,
    epoch_state::EpochState,
    event::EventKey,
    transaction::ElectionPayload,
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BinaryHeap, HashMap},
    fmt::{Debug, Formatter},
};

const TERM_LIST_LEN: usize = 6;
const ELECTION_AFTER_ACCEPTED_ROUND: Round = 240;
const ROUND_PER_TERM: Round = 60;
/// A term `n` is open for election in the round range
/// `(n * ROUND_PER_TERM - ELECTION_TERM_START_ROUND, n * ROUND_PER_TERM -
/// ELECTION_TERM_END_ROUND]`
const ELECTION_TERM_START_ROUND: Round = 120;
const ELECTION_TERM_END_ROUND: Round = 30;

const TERM_MAX_SIZE: usize = 16;

#[derive(Copy, Clone)]
pub enum NodeStatus {
    Accepted,
    Retired,
    Unlocked,
}

#[derive(Clone)]
pub struct NodeData {
    public_key: ConsensusPublicKey,
    vrf_public_key: Option<ConsensusVRFPublicKey>,
    status: NodeStatus,
    status_start_round: Round,
    serving_term: Option<u64>,
}

#[derive(Clone)]
pub struct TermData {
    start_round: Round,
    seed: Vec<u8>,
    /// (VRF.val, NodeID)
    node_list: BinaryHeap<(HashValue, AccountAddress)>,
}

impl TermData {
    fn next_term(
        &self, node_list: BinaryHeap<(HashValue, AccountAddress)>,
    ) -> Self {
        TermData {
            start_round: self.start_round + ROUND_PER_TERM,
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

#[derive(Clone)]
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
        if self.term_list[1].start_round
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

// FIXME(lpl): Blocks following a pending reconfiguration block should not have
// transactions, and this may lead to an empty committee,
#[derive(Clone)]
pub struct PosState {
    /// All the nodes that have staked in PoW.
    /// Nodes are only inserted and will never be removed.
    node_map: HashMap<AccountAddress, NodeData>,
    /// `current_view / TERM_LIST_LEN == term_list.current_term` is always
    /// true. This is not the same as `RoundState.current_round` because the
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
            .field("round", &self.current_view)
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
                    status_start_round: 0,
                    // This will not be used for initial terms.
                    serving_term: None,
                },
            );
            // VRF output of initial terms will not be used, because these terms
            // are not open for election.
            node_list.push((Default::default(), addr));
        }
        let mut term_list = Vec::new();
        let initial_term = TermData {
            start_round: 0,
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
            bail!("Invalid node status");
        }
        if node.status_start_round + ELECTION_AFTER_ACCEPTED_ROUND
            > election_tx
                .target_term
                .checked_mul(ROUND_PER_TERM)
                .ok_or(anyhow!("start round overflow"))?
        {
            bail!("Election too soon after accepted");
        }
        let target_round = election_tx.target_term * ROUND_PER_TERM;
        if target_round >= self.current_view + ELECTION_TERM_START_ROUND
            || target_round < self.current_view + ELECTION_TERM_END_ROUND
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
        // The checking of `target_round` ensures that this is in range of
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
    pub fn election_event_key() -> EventKey {
        EventKey::new_from_address(
            &account_config::pivot_chain_select_address(),
            3,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}
