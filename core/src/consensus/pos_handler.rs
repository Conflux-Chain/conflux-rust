use std::sync::Arc;

use crate::pos::consensus::ConsensusDB;
use cfx_types::H256;
use diem_config::keys::ConfigKey;
use diem_crypto::HashValue;
use diem_types::{
    contract_event::ContractEvent,
    epoch_state::EpochState,
    reward_distribution_event::RewardDistributionEvent,
    term_state::{DisputeEvent, UnlockEvent},
    validator_config::{ConsensusPrivateKey, ConsensusVRFPrivateKey},
};
use primitives::pos::{NodeId, PosBlockId};
use storage_interface::DBReaderForPoW;

pub type PosVerifier = PosHandler<PosConnection>;

/// This includes the interfaces that the PoW consensus needs from the PoS
/// consensus.
///
/// We assume the PoS service will be always available after `initialize()`
/// returns, so all the other interfaces will panic if the PoS service is not
/// ready.
pub trait PosInterface {
    /// Wait for initialization.
    fn initialize(&self) -> Result<(), String>;

    /// Get a PoS block by its ID.
    ///
    /// Return `None` if the block does not exist or is not committed.
    fn get_committed_block(&self, h: &PosBlockId) -> Option<PosBlock>;

    /// Return the latest committed PoS block ID.
    /// This will become the PoS reference of the mined PoW block.
    fn latest_block(&self) -> PosBlockId;

    fn get_events(
        &self, from: &PosBlockId, to: &PosBlockId,
    ) -> Vec<ContractEvent>;

    fn get_epoch_ending_blocks(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Vec<PosBlockId>;

    fn get_reward_event(&self, epoch: u64) -> Option<RewardDistributionEvent>;

    fn get_epoch_state(&self, block_id: &PosBlockId) -> EpochState;
}

#[allow(unused)]
pub struct PosBlock {
    hash: PosBlockId,
    epoch: u64,
    round: u64,
    pivot_decision: H256,
    version: u64,
    view: u64,
    /* parent: PosBlockId,
     * author: NodeId,
     * voters: Vec<NodeId>, */
}

pub struct PosHandler<PoS: PosInterface> {
    pos: PoS,
    enable_height: u64,
    conf: PosConfiguration,
}

impl<PoS: PosInterface> PosHandler<PoS> {
    pub fn new(pos: PoS, conf: PosConfiguration, enable_height: u64) -> Self {
        pos.initialize().expect("PoS handler initialization error");
        Self {
            pos,
            enable_height,
            conf,
        }
    }

    pub fn config(&self) -> &PosConfiguration { &self.conf }

    pub fn is_enabled_at_height(&self, height: u64) -> bool {
        height >= self.enable_height
    }

    pub fn is_committed(&self, h: &PosBlockId) -> bool {
        self.pos.get_committed_block(h).is_some()
    }

    /// Check if `me` is equal to or extends `preds` (parent and referees).
    ///
    /// Since committed PoS blocks form a chain, and no pos block should be
    /// skipped, we only need to check if the round of `me` is equal to or plus
    /// one compared with the predecessors' rounds.
    ///
    /// Return `false` if `me` or `preds` contains non-existent PoS blocks.
    pub fn verify_against_predecessors(
        &self, me: &PosBlockId, preds: &Vec<PosBlockId>,
    ) -> bool {
        let me_round = match self.pos.get_committed_block(me) {
            None => {
                warn!("No pos block for me={:?}", me);
                return false;
            }
            Some(b) => (b.epoch, b.round),
        };
        for p in preds {
            let p_round = match self.pos.get_committed_block(p) {
                None => {
                    warn!("No pos block for pred={:?}", p);
                    return false;
                }
                Some(b) => (b.epoch, b.round),
            };
            if me_round < p_round {
                warn!("Incorrect round: me={:?}, pred={:?}", me_round, p_round);
                return false;
            }
        }
        true
    }

    pub fn get_pivot_decision(&self, h: &PosBlockId) -> Option<H256> {
        self.pos.get_committed_block(h).map(|b| b.pivot_decision)
    }

    pub fn get_latest_pos_reference(&self) -> PosBlockId {
        self.pos.latest_block()
    }

    pub fn get_pos_view(&self, h: &PosBlockId) -> Option<u64> {
        self.pos.get_committed_block(h).map(|b| b.view)
    }

    pub fn get_unlock_nodes(
        &self, h: &PosBlockId, parent_pos_ref: &PosBlockId,
    ) -> Vec<(NodeId, u64)> {
        let unlock_event_key = UnlockEvent::event_key();
        let mut unlock_nodes = Vec::new();
        for event in self.pos.get_events(parent_pos_ref, h) {
            if *event.key() == unlock_event_key {
                let unlock_event = UnlockEvent::from_bytes(event.event_data())
                    .expect("key checked");
                let node_id = H256::from_slice(unlock_event.node_id.as_ref());
                let votes = unlock_event.unlocked;
                unlock_nodes.push((node_id, votes));
            }
        }
        unlock_nodes
    }

    pub fn get_disputed_nodes(
        &self, h: &PosBlockId, parent_pos_ref: &PosBlockId,
    ) -> Vec<NodeId> {
        let dispute_event_key = DisputeEvent::event_key();
        let mut disputed_nodes = Vec::new();
        for event in self.pos.get_events(parent_pos_ref, h) {
            if *event.key() == dispute_event_key {
                let dispute_event =
                    DisputeEvent::from_bytes(event.event_data())
                        .expect("key checked");
                disputed_nodes
                    .push(H256::from_slice(dispute_event.node_id.as_ref()));
            }
        }
        disputed_nodes
    }

    pub fn get_reward_distribution_event(
        &self, h: &PosBlockId, parent_pos_ref: &PosBlockId,
    ) -> Option<Vec<RewardDistributionEvent>> {
        if h == parent_pos_ref {
            return None;
        }
        let me_block = self.pos.get_committed_block(h)?;
        let parent_block = self.pos.get_committed_block(parent_pos_ref)?;
        if me_block.epoch == parent_block.epoch {
            return None;
        }
        let mut events = Vec::new();
        for epoch in parent_block.epoch..me_block.epoch {
            events.push(self.pos.get_reward_event(epoch)?);
        }
        Some(events)
    }
}

pub struct PosConnection {
    pos_storage: Arc<dyn DBReaderForPoW>,
    consensus_db: Arc<ConsensusDB>,
}

impl PosConnection {
    pub fn new(
        pos_storage: Arc<dyn DBReaderForPoW>, consensus_db: Arc<ConsensusDB>,
    ) -> Self {
        Self {
            pos_storage,
            consensus_db,
        }
    }
}

impl PosInterface for PosConnection {
    fn initialize(&self) -> Result<(), String> { Ok(()) }

    fn get_committed_block(&self, h: &PosBlockId) -> Option<PosBlock> {
        debug!("get_committed_block: {:?}", h);
        let block_hash = h256_to_diem_hash(h);
        let committed_block = self
            .pos_storage
            .get_committed_block_by_hash(&block_hash)
            .ok()?;

        /*
        let parent;
        let author;
        if *h == PosBlockId::default() {
            // genesis has no block, and its parent/author will not be used.
            parent = PosBlockId::default();
            author = NodeId::default();
        } else {
            let block = self
                .pos_consensus_db
                .get_ledger_block(&block_hash)
                .map_err(|e| {
                    warn!("get_committed_block: err={:?}", e);
                    e
                })
                .ok()??;
            debug_assert_eq!(block.id(), block_hash);
            parent = diem_hash_to_h256(&block.parent_id());
            // NIL block has no author.
            author = H256::from_slice(block.author().unwrap_or(Default::default()).as_ref());
        }
         */
        debug!("pos_handler gets committed_block={:?}", committed_block);
        Some(PosBlock {
            hash: *h,
            epoch: committed_block.epoch,
            round: committed_block.round,
            pivot_decision: committed_block.pivot_decision.block_hash,
            view: committed_block.view,
            /* parent,
             * author,
             * voters: ledger_info
             *     .signatures()
             *     .keys()
             *     .map(|author| H256::from_slice(author.as_ref()))
             *     .collect(), */
            version: committed_block.version,
        })
    }

    fn latest_block(&self) -> PosBlockId {
        diem_hash_to_h256(
            &self
                .pos_storage
                .get_latest_ledger_info_option()
                .expect("Initialized")
                .ledger_info()
                .consensus_block_id(),
        )
    }

    fn get_events(
        &self, from: &PosBlockId, to: &PosBlockId,
    ) -> Vec<ContractEvent> {
        let start_version = self
            .pos_storage
            .get_committed_block_by_hash(&h256_to_diem_hash(from))
            .expect("err reading ledger info for from")
            .version;
        let end_version = self
            .pos_storage
            .get_committed_block_by_hash(&h256_to_diem_hash(to))
            .expect("err reading ledger info for to")
            .version;
        self.pos_storage
            .get_events_by_version(start_version, end_version)
            .expect("err reading events")
    }

    fn get_epoch_ending_blocks(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Vec<PosBlockId> {
        self.pos_storage
            .get_epoch_ending_blocks(start_epoch, end_epoch)
            .expect("err reading epoch ending blocks")
            .into_iter()
            .map(|h| diem_hash_to_h256(&h))
            .collect()
    }

    fn get_reward_event(&self, epoch: u64) -> Option<RewardDistributionEvent> {
        self.pos_storage.get_reward_event(epoch).ok()
    }

    fn get_epoch_state(&self, block_id: &PosBlockId) -> EpochState {
        self.pos_storage
            .get_pos_state(&h256_to_diem_hash(block_id))
            .expect("parent of an ending_epoch block")
            .epoch_state()
            .clone()
    }
}

pub struct PosConfiguration {
    pub bls_key: ConfigKey<ConsensusPrivateKey>,
    pub vrf_key: ConfigKey<ConsensusVRFPrivateKey>,
}

fn diem_hash_to_h256(h: &HashValue) -> PosBlockId { H256::from(h.as_ref()) }
fn h256_to_diem_hash(h: &PosBlockId) -> HashValue {
    HashValue::new(h.to_fixed_bytes())
}
