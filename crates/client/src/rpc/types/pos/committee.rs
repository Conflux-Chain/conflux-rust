use cfx_types::{H256, U64};
use diem_types::{
    epoch_state::EpochState,
    term_state::{NodeList, TermData},
};
use serde::Serialize;

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CommitteeState {
    pub current_committee: RpcCommittee,
    pub elections: Vec<RpcTermData>,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcCommittee {
    pub epoch_number: U64,
    pub quorum_voting_power: U64,
    pub total_voting_power: U64,
    pub nodes: Vec<NodeVotingPower>,
}

impl RpcCommittee {
    pub fn from_epoch_state(epoch_state: &EpochState) -> RpcCommittee {
        let mut committee = RpcCommittee::default();
        committee.epoch_number = U64::from(epoch_state.epoch);
        committee.quorum_voting_power =
            U64::from(epoch_state.verifier().quorum_voting_power());
        committee.total_voting_power =
            U64::from(epoch_state.verifier().total_voting_power());
        let validator_info = epoch_state.verifier().address_to_validator_info();

        for (account_address, validator_consensus_info) in validator_info {
            committee.nodes.push(NodeVotingPower::new(
                H256::from(account_address.to_u8()),
                validator_consensus_info.voting_power(),
            ))
        }
        committee
    }
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcTermData {
    pub start_block_number: U64,
    pub is_finalized: bool,
    pub top_electing_nodes: Vec<NodeVotingPower>,
}

impl From<&TermData> for RpcTermData {
    fn from(term_data: &TermData) -> Self {
        let mut value = RpcTermData::default();
        match term_data.node_list() {
            NodeList::Electing(electing_heap) => {
                value.is_finalized = false;
                value.start_block_number = U64::from(term_data.start_view());
                for (account, votes) in electing_heap.read_top_electing() {
                    value.top_electing_nodes.push(NodeVotingPower::new(
                        H256::from(account.to_u8()),
                        votes,
                    ))
                }
            }
            NodeList::Elected(elected) => {
                value.is_finalized = true;
                value.start_block_number = U64::from(term_data.start_view());
                for (account, votes) in elected.inner() {
                    value.top_electing_nodes.push(NodeVotingPower::new(
                        H256::from(account.to_u8()),
                        *votes,
                    ))
                }
            }
        }
        value
    }
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NodeVotingPower {
    pub address: H256,
    pub voting_power: U64,
}

impl NodeVotingPower {
    pub fn new(address: H256, voting_power: u64) -> Self {
        NodeVotingPower {
            address,
            voting_power: U64::from(voting_power),
        }
    }
}
