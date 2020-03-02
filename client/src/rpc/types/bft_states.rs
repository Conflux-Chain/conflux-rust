use cfxcore::state_exposer::BFTStates as PrimitiveBFTStates;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BFTCommitEvent {
    epoch: u64,
    commit: String,
    round: u64,
    parent: String,
    timestamp: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BFTStates {
    pub bft_events: Vec<BFTCommitEvent>,
}

impl BFTStates {
    pub fn new(bft_states: PrimitiveBFTStates) -> Self {
        let mut bft_events = Vec::new();
        for event in bft_states.bft_events {
            bft_events.push(BFTCommitEvent {
                epoch: event.epoch,
                commit: event.commit.into(),
                round: event.round,
                parent: event.parent.into(),
                timestamp: event.timestamp,
            })
        }
        Self { bft_events }
    }
}
