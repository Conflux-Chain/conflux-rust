use diem_crypto::HashValue;
use diem_types::{
    account_address::AccountAddress,
    block_info::Round,
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
};
use std::collections::{BinaryHeap, HashMap};

#[derive(Copy, Clone)]
pub enum NodeStatus {
    Accepted,
    Retired,
    Unlocked,
}

#[derive(Clone)]
pub struct NodeData {
    public_key: ConsensusPublicKey,
    vrf_public_key: ConsensusVRFPublicKey,
    status: NodeStatus,
    status_start_round: Round,
}

#[derive(Clone)]
pub struct TermData {
    start_round: Round,
    seed: Vec<u8>,
    /// (VRF.val, NodeID)
    node_list: BinaryHeap<(HashValue, AccountAddress)>,
}

#[derive(Clone)]
pub struct TermList {
    start_term: usize,
    term_list: Vec<TermData>,
}

#[derive(Clone)]
pub struct PosState {
    node_map: HashMap<AccountAddress, NodeData>,
    term_list: TermList,
}
